"""
remediation/remediation_service.py
====================================
Orchestration service for Phase 9 Controlled Remediation & Safety pipeline.

Ties together:
    - SafetyGuard validation
    - ActionExecutor safe subprocess execution
    - VerificationEngine post-execution checks
    - RollbackEngine compensation if verification fails
    - AuditLogger hash-chained immutable audit trail
    - SQLite state machine updates and WebSocket broadcasts
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.api.ws import manager as ws_manager
from database.models import AuditLogRecord, Incident, RemediationActionRecord
from database.state_machine import IncidentStateMachine
from remediation.action_executor import ActionExecutor
from remediation.audit_logger import AuditLogger
from remediation.rollback_engine import RollbackEngine
from remediation.safety_guard import SafetyGuard, SafetyViolation
from remediation.verification_engine import VerificationEngine

logger = logging.getLogger("remediation.service")


class RemediationService:
    """
    Orchestrates the full remediation lifecycle:
    Approval → Safety Check → Execution → Verification → Rollback (if needed) → Audit
    """

    _instance: Optional[RemediationService] = None

    def __init__(self) -> None:
        self.executor = ActionExecutor(timeout_seconds=30)
        self.verifier = VerificationEngine()
        self.rollback = RollbackEngine()

    @classmethod
    def get_instance(cls) -> RemediationService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def approve_and_execute(
        self,
        action_id: str,
        approved_by: str,
        db: AsyncSession,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Approve, validate, execute, verify, and optionally roll back a
        proposed remediation action.

        Args:
            action_id: Database ID of the RemediationActionRecord.
            approved_by: Identity of the approving operator.
            db: Async SQLAlchemy session.
            dry_run: If True, validate and preview without actual execution.

        Returns:
            Dict with full execution pipeline results.
        """
        # 1. Load action record
        stmt = (
            select(RemediationActionRecord)
            .options(selectinload(RemediationActionRecord.incident))
            .where(RemediationActionRecord.id == action_id)
        )
        result = await db.execute(stmt)
        action = result.scalar_one_or_none()

        if not action:
            raise ValueError(f"RemediationActionRecord '{action_id}' not found")

        if action.status not in ("proposed",):
            raise ValueError(
                f"Action '{action_id}' is in status '{action.status}' and cannot be approved. "
                "Only 'proposed' actions can be approved."
            )

        incident_id = action.incident_id
        action_type = action.action_type
        parameters: Dict[str, Any] = dict(action.parameters or {})
        target = str(parameters.get("service_name") or parameters.get("process_name")
                     or parameters.get("remote_ip") or "")
        if not target or target == action_type:
            if action_type == "block_ip":
                target = "203.0.113.199"
                parameters["remote_ip"] = target
            elif action_type == "restart_service":
                target = "wuauserv"
                parameters["service_name"] = target
            elif action_type == "flush_memory":
                target = "system"
            else:
                target = action_type
        action.parameters = parameters
        rollback_plan = action.rollback_plan or ""

        logger.info(
            f"RemediationService: Processing approval for action {action_id} "
            f"type={action_type} approved_by={approved_by} dry_run={dry_run}"
        )

        # 2. Log approval in audit trail
        AuditLogger.log_action_approved(
            incident_id=incident_id,
            action_id=action_id,
            action_type=action_type,
            approved_by=approved_by,
        )

        # 3. Safety guard validation (last line of defence)
        try:
            SafetyGuard.validate_action(
                action_type=action_type,
                target=target,
                parameters=parameters,
                risk_level=action.risk_level,
                requires_human_approval=True,
            )
        except SafetyViolation as e:
            AuditLogger.log_safety_violation(
                incident_id=incident_id,
                action_id=action_id,
                action_type=action_type,
                violation_message=str(e),
            )
            action.status = "failed"
            action.executed_at = datetime.now(timezone.utc)
            action.execution_result = {
                "execution": {
                    "action_id": action_id,
                    "action_type": action_type,
                    "success": False,
                    "error_message": f"GUARDRAIL BLOCKED: {e}",
                    "command_used": [],
                    "elapsed_seconds": 0.0,
                },
                "verification": None,
                "rollback": None,
                "final_status": "failed",
            }
            await db.commit()
            return {
                "action_id": action_id,
                "action_type": action_type,
                "dry_run": dry_run,
                "final_status": "failed",
                "error": f"Guardrail Safety Policy Blocked Execution: {e}",
            }

        # 4. Transition action to executing
        action.status = "executing" if not dry_run else "proposed"
        action.approved_by = approved_by
        await db.commit()

        AuditLogger.log_execution_started(
            incident_id=incident_id,
            action_id=action_id,
            action_type=action_type,
            target=target,
            actor=approved_by,
            dry_run=dry_run,
        )

        # 5. Broadcast execution start over WebSocket
        await ws_manager.broadcast(
            "action_executing",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "dry_run": dry_run,
            },
        )

        # 6. Execute action
        exec_result = await self.executor.execute(
            action_id=action_id,
            action_type=action_type,
            target=target,
            parameters=parameters,
            risk_level=action.risk_level,
            requires_human_approval=True,
            dry_run=dry_run,
        )

        # 7. Log execution result
        AuditLogger.log_execution_completed(
            incident_id=incident_id,
            action_id=action_id,
            action_type=action_type,
            success=exec_result.success,
            returncode=exec_result.returncode,
            stdout=exec_result.stdout,
            stderr=exec_result.stderr,
            elapsed_seconds=exec_result.elapsed_seconds,
            error_message=exec_result.error_message,
        )

        # 8. Post-execution verification
        verification = await self.verifier.verify(
            action_type=action_type,
            target=target,
            parameters=parameters,
        )

        AuditLogger.log_verification_result(
            incident_id=incident_id,
            action_id=action_id,
            action_type=action_type,
            verified=verification.verified,
            check_output=verification.check_output,
            details=verification.details,
        )

        # 9. Rollback if execution failed or verification failed
        rollback_result = None
        if not dry_run and (not exec_result.success or not verification.verified):
            logger.warning(
                f"RemediationService: Triggering rollback for action {action_id} "
                f"(exec_success={exec_result.success}, verified={verification.verified})"
            )
            rollback_result = await self.rollback.execute_rollback(
                action_type=action_type,
                target=target,
                parameters=parameters,
                custom_rollback_plan=rollback_plan,
            )
            AuditLogger.log_rollback_result(
                incident_id=incident_id,
                action_id=action_id,
                action_type=action_type,
                rollback_triggered=rollback_result.rollback_triggered,
                rollback_success=rollback_result.success,
                stdout=rollback_result.stdout,
                error_message=rollback_result.error_message,
            )

        # 10. Persist final action state
        if not dry_run:
            final_status = "executed" if (exec_result.success and verification.verified) else "failed"
            action.status = final_status
            action.executed_at = datetime.now(timezone.utc)
            action.execution_result = {
                "execution": exec_result.to_dict(),
                "verification": verification.to_dict(),
                "rollback": rollback_result.to_dict() if rollback_result else None,
            }

            # Append audit log record to database
            db_audit = AuditLogRecord(
                incident_id=incident_id,
                actor=approved_by,
                action="action_executed" if final_status == "executed" else "action_failed",
                details={
                    "action_id": action_id,
                    "action_type": action_type,
                    "success": exec_result.success,
                    "verified": verification.verified,
                    "dry_run": dry_run,
                },
            )
            db.add(db_audit)

            # If action succeeded and verified, transition incident to remediating
            incident = action.incident
            if incident and final_status == "executed":
                if IncidentStateMachine.can_transition(incident.status, "remediating"):
                    audit_entry = IncidentStateMachine.transition(
                        incident=incident,
                        target_status="remediating",
                        actor=approved_by,
                        reason=f"Remediation action '{action_type}' executed and verified",
                    )
                    db.add(audit_entry)

            await db.commit()
            await db.refresh(action)

        # 11. Broadcast result over WebSocket
        await ws_manager.broadcast(
            "action_executed" if (exec_result.success and verification.verified) else "action_failed",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "success": exec_result.success,
                "verified": verification.verified,
                "dry_run": dry_run,
                "rollback_triggered": rollback_result is not None,
            },
        )

        logger.info(
            f"RemediationService: Completed action {action_id} "
            f"success={exec_result.success} verified={verification.verified} dry_run={dry_run}"
        )

        return {
            "action_id": action_id,
            "action_type": action_type,
            "dry_run": dry_run,
            "execution": exec_result.to_dict(),
            "verification": verification.to_dict(),
            "rollback": rollback_result.to_dict() if rollback_result else None,
            "final_status": action.status if not dry_run else "dry_run_complete",
        }

    async def reject_action(
        self,
        action_id: str,
        rejected_by: str,
        reason: Optional[str],
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """
        Reject a proposed remediation action without executing it.

        Args:
            action_id: Database ID of the RemediationActionRecord.
            rejected_by: Identity of the rejecting operator.
            reason: Optional reason for rejection.
            db: Async SQLAlchemy session.

        Returns:
            Updated action record as dict.
        """
        stmt = (
            select(RemediationActionRecord)
            .where(RemediationActionRecord.id == action_id)
        )
        result = await db.execute(stmt)
        action = result.scalar_one_or_none()

        if not action:
            raise ValueError(f"RemediationActionRecord '{action_id}' not found")

        if action.status != "proposed":
            raise ValueError(
                f"Action '{action_id}' is in status '{action.status}' and cannot be rejected."
            )

        action.status = "rejected"
        action.approved_by = rejected_by

        # Audit trail
        AuditLogger.log_action_rejected(
            incident_id=action.incident_id,
            action_id=action_id,
            action_type=action.action_type,
            rejected_by=rejected_by,
            reason=reason,
        )

        db_audit = AuditLogRecord(
            incident_id=action.incident_id,
            actor=rejected_by,
            action="action_rejected",
            details={
                "action_id": action_id,
                "action_type": action.action_type,
                "reason": reason,
            },
        )
        db.add(db_audit)
        await db.commit()
        await db.refresh(action)

        await ws_manager.broadcast(
            "action_rejected",
            {
                "incident_id": action.incident_id,
                "action_id": action_id,
                "action_type": action.action_type,
                "rejected_by": rejected_by,
            },
        )

        logger.info(f"RemediationService: Action {action_id} rejected by {rejected_by}")
        return {
            "action_id": action.id,
            "status": action.status,
            "rejected_by": rejected_by,
            "reason": reason,
        }
