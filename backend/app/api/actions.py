"""
backend/app/api/actions.py
==========================
Phase 9 — Controlled Remediation & Safety REST API endpoints.

Implements the full human-in-the-loop action approval, rejection, dry-run,
audit log retrieval, and pending actions queue endpoints.

SAFETY CONTRACT:
    - NO remediation action is executed without prior human approval.
    - Every approval call passes through SafetyGuard before execution.
    - All events are written to the hash-chained audit log.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AuditLogRecord, RemediationActionRecord
from database.session import get_db
from remediation.audit_logger import AuditLogger
from remediation.remediation_service import RemediationService

logger = logging.getLogger("backend.api.actions")

router = APIRouter()


# ── Request / Response Pydantic models ─────────────────────────────────────────

class ApproveActionRequest(BaseModel):
    approved_by: str = Field(default="dashboard_operator", description="Operator identity approving the action")
    dry_run: bool = Field(default=False, description="If true, validate and preview without executing")


class RejectActionRequest(BaseModel):
    rejected_by: Optional[str] = Field(None, description="Operator identity rejecting the action")
    approved_by: Optional[str] = Field(None, description="Fallback operator identity field")
    reason: Optional[str] = Field(None, description="Reason for rejecting the action")

    def get_actor(self) -> str:
        return self.rejected_by or self.approved_by or "dashboard_operator"



class ActionResponse(BaseModel):
    action_id: str
    incident_id: str
    action_type: str
    status: str
    risk_level: str
    description: str
    parameters: Dict[str, Any]
    rollback_plan: Optional[str]
    proposed_by: str
    approved_by: Optional[str]
    execution_result: Optional[Dict[str, Any]]
    created_at: str
    executed_at: Optional[str]


def _serialize_action(action: RemediationActionRecord) -> Dict[str, Any]:
    return {
        "action_id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "status": action.status,
        "risk_level": action.risk_level,
        "description": action.description,
        "parameters": action.parameters or {},
        "rollback_plan": action.rollback_plan,
        "proposed_by": action.proposed_by,
        "approved_by": action.approved_by,
        "execution_result": action.execution_result,
        "created_at": action.created_at.isoformat(),
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
    }


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/pending")
async def list_pending_actions(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all remediation actions currently awaiting human approval.
    """
    stmt = (
        select(RemediationActionRecord)
        .where(RemediationActionRecord.status == "proposed")
        .order_by(RemediationActionRecord.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    actions = result.scalars().all()
    return {
        "total": len(actions),
        "pending": [_serialize_action(a) for a in actions],
    }


@router.get("/audit-log")
async def get_audit_log(
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """
    Return the last N entries from the remediation audit log (hash-chained JSONL).
    """
    entries = AuditLogger.read_entries(limit=limit)
    return {
        "total_entries": len(entries),
        "audit_log_path": str(AuditLogger.get_audit_log_path()),
        "entries": entries,
    }


@router.get("/{action_id}")
async def get_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Retrieve a single remediation action record by ID.
    """
    stmt = select(RemediationActionRecord).where(RemediationActionRecord.id == action_id)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found")
    return _serialize_action(action)


@router.post("/{action_id}/approve")
async def approve_action(
    action_id: str,
    body: ApproveActionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Approve and execute a proposed remediation action.

    The full pipeline runs:
    1. Safety Guard validation (allowlist + injection check)
    2. PowerShell subprocess execution (no shell=True)
    3. Automated verification check
    4. Rollback if execution or verification failed
    5. Hash-chained audit log entry written
    6. WebSocket broadcast of result

    Set `dry_run=true` to validate and preview the command without executing.
    """
    service = RemediationService.get_instance()
    try:
        result = await service.approve_and_execute(
            action_id=action_id,
            approved_by=body.approved_by,
            db=db,
            dry_run=body.dry_run,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Action approval pipeline failed for {action_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Execution pipeline error: {e}")
    return result


@router.post("/{action_id}/reject")
async def reject_action(
    action_id: str,
    body: RejectActionRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Reject a proposed remediation action. Records rejection in the audit log.
    """
    service = RemediationService.get_instance()
    try:
        result = await service.reject_action(
            action_id=action_id,
            rejected_by=body.get_actor(),
            reason=body.reason,
            db=db,
        )

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"Action rejection failed for {action_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Rejection error: {e}")
    return result
