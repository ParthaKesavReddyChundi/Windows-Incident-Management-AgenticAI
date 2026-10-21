"""
backend/app/services/incident_service.py
=========================================
Incident management service with automated alert correlation, deduplication,
state transitions, and database persistence.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.schemas.incident import (
    IncidentCreate,
    IncidentStatsSummary,
    RemediationActionCreate,
    Severity,
)
from database.models import (
    AnomalyRecord,
    AuditLogRecord,
    Incident,
    RemediationActionRecord,
)
from database.state_machine import IncidentStateMachine

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ACTIVE_STATUSES = ["detected", "investigating", "awaiting_approval", "remediating", "mitigated"]


def _format_incident_title(severity: str, top_features: Optional[List[Dict[str, Any]]]) -> str:
    """Generate a clean, descriptive title for an incident based on top deviant features."""
    if top_features and len(top_features) > 0:
        top_name = top_features[0].get("feature", "System Telemetry")
        # Clean up feature name
        clean_name = top_name.replace("_", " ").strip()
        return f"[{severity.upper()}] Anomaly Detected — High Deviation in {clean_name}"
    return f"[{severity.upper()}] Multivariate System Anomaly Detected"


class IncidentService:
    """Service providing incident lifecycle operations and anomaly correlation."""

    # ── Correlation & Alert Aggregation ──────────────────────────────────────

    @staticmethod
    async def correlate_or_create_incident(
        session: AsyncSession,
        score: float,
        threshold: float,
        severity: str,
        is_anomaly: bool,
        top_features: Optional[List[Dict[str, Any]]] = None,
        raw_features: Optional[Dict[str, Any]] = None,
        snapshot_id: Optional[str] = None,
        source: str = "live",
        correlation_window_seconds: int = 300,
    ) -> Tuple[Incident, AnomalyRecord, bool]:
        """
        Correlates an anomaly event into an existing active incident if one exists
        within the correlation window; otherwise, creates a new incident.

        Returns:
            (incident, anomaly_record, is_new_incident)
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=correlation_window_seconds)

        # Look for the most recent active incident from the same source
        query = (
            select(Incident)
            .where(
                Incident.source == source,
                Incident.status.in_(ACTIVE_STATUSES),
                Incident.updated_at >= window_start,
            )
            .order_by(desc(Incident.updated_at))
            .limit(1)
        )
        result = await session.execute(query)
        existing_incident = result.scalar_one_or_none()

        if existing_incident is not None:
            # Correlate into existing incident
            anomaly_record = AnomalyRecord(
                incident_id=existing_incident.id,
                timestamp=now,
                score=score,
                threshold=threshold,
                severity=severity,
                is_anomaly=is_anomaly,
                top_features=top_features or [],
                raw_features=raw_features or {},
            )
            session.add(anomaly_record)

            # Elevate severity if incoming is more critical
            existing_weight = SEVERITY_WEIGHTS.get(existing_incident.severity.lower(), 1)
            new_weight = SEVERITY_WEIGHTS.get(severity.lower(), 1)
            if new_weight > existing_weight:
                existing_incident.severity = severity.lower()

            # Update maximum anomaly score seen
            if score > existing_incident.anomaly_score:
                existing_incident.anomaly_score = score

            existing_incident.updated_at = now
            if snapshot_id:
                existing_incident.snapshot_id = snapshot_id

            logger.info(
                "Anomaly correlated into existing incident %s (score=%.4f, severity=%s)",
                existing_incident.id,
                score,
                severity,
            )
            return existing_incident, anomaly_record, False

        # Create new incident
        title = _format_incident_title(severity, top_features)
        new_incident = Incident(
            title=title,
            description=f"Automated incident triggered by autoencoder reconstruction error {score:.4f} exceeding threshold {threshold:.4f}.",
            severity=severity.lower(),
            status="detected",
            source=source,
            anomaly_score=score,
            snapshot_id=snapshot_id,
            detected_at=now,
            updated_at=now,
        )
        session.add(new_incident)
        await session.flush()  # Flush to generate new_incident.id

        anomaly_record = AnomalyRecord(
            incident_id=new_incident.id,
            timestamp=now,
            score=score,
            threshold=threshold,
            severity=severity,
            is_anomaly=is_anomaly,
            top_features=top_features or [],
            raw_features=raw_features or {},
        )
        session.add(anomaly_record)

        audit_entry = AuditLogRecord(
            incident_id=new_incident.id,
            timestamp=now,
            actor="system",
            action="incident_created",
            details={
                "initial_score": score,
                "threshold": threshold,
                "severity": severity,
                "source": source,
            },
        )
        session.add(audit_entry)

        logger.info(
            "New incident created: %s [%s] (id=%s, score=%.4f)",
            new_incident.title,
            severity,
            new_incident.id,
            score,
        )
        return new_incident, anomaly_record, True

    # ── CRUD Operations ──────────────────────────────────────────────────────

    @staticmethod
    async def create_incident(
        session: AsyncSession,
        data: IncidentCreate,
    ) -> Incident:
        """Manually creates an incident record."""
        now = datetime.now(timezone.utc)
        title = data.title or f"[{data.severity.value.upper()}] Manual Incident"
        incident = Incident(
            title=title,
            description=data.description,
            severity=data.severity.value,
            status="detected",
            source=data.source,
            snapshot_id=data.snapshot_id,
            anomaly_score=data.anomaly_score,
            detected_at=now,
            updated_at=now,
        )
        session.add(incident)
        await session.flush()

        audit = AuditLogRecord(
            incident_id=incident.id,
            timestamp=now,
            actor="human_admin",
            action="incident_created_manual",
            details={"title": title, "severity": data.severity.value},
        )
        session.add(audit)
        return incident

    @staticmethod
    async def get_incident(
        session: AsyncSession,
        incident_id: str,
        include_children: bool = False,
    ) -> Optional[Incident]:
        """Fetch an incident by ID, optionally eager-loading child relations."""
        if include_children:
            query = (
                select(Incident)
                .options(
                    selectinload(Incident.anomalies),
                    selectinload(Incident.actions),
                    selectinload(Incident.audit_logs),
                )
                .where(Incident.id == incident_id)
            )
        else:
            query = select(Incident).where(Incident.id == incident_id)

        result = await session.execute(query)
        return result.scalar_one_or_none()

    @staticmethod
    async def list_incidents(
        session: AsyncSession,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Incident], int]:
        """List incidents with optional filtering and pagination."""
        query = select(Incident)

        if status:
            query = query.where(Incident.status == status.lower())
        if severity:
            query = query.where(Incident.severity == severity.lower())
        if source:
            query = query.where(Incident.source == source)

        # Count total matches
        count_query = select(func.count()).select_from(query.subquery())
        count_result = await session.execute(count_query)
        total = count_result.scalar_one()

        # Fetch page ordered by detected_at desc
        page_query = query.order_by(desc(Incident.detected_at)).limit(limit).offset(offset)
        result = await session.execute(page_query)
        incidents = list(result.scalars().all())

        return incidents, total

    @staticmethod
    async def transition_status(
        session: AsyncSession,
        incident_id: str,
        target_status: str,
        actor: str = "human_admin",
        reason: Optional[str] = None,
    ) -> Incident:
        """Transitions incident status according to the lifecycle state machine."""
        incident = await IncidentService.get_incident(session, incident_id)
        if incident is None:
            raise ValueError(f"Incident with id '{incident_id}' not found.")

        audit_entry = IncidentStateMachine.transition(
            incident=incident,
            target_status=target_status,
            actor=actor,
            reason=reason,
        )
        session.add(audit_entry)
        return incident

    @staticmethod
    async def update_investigation(
        session: AsyncSession,
        incident_id: str,
        root_cause: Optional[str] = None,
        confidence: Optional[float] = None,
        recommended_actions: Optional[List[str]] = None,
        diagnosis: Optional[Dict[str, Any]] = None,
        security_assessment: Optional[Dict[str, Any]] = None,
    ) -> Incident:
        """Updates incident diagnosis and root-cause details from AI agents."""
        incident = await IncidentService.get_incident(session, incident_id)
        if incident is None:
            raise ValueError(f"Incident with id '{incident_id}' not found.")

        if root_cause is not None:
            incident.root_cause = root_cause
        if confidence is not None:
            incident.confidence = confidence
        if recommended_actions is not None:
            incident.recommended_actions = recommended_actions
        if diagnosis is not None:
            incident.diagnosis = diagnosis
        if security_assessment is not None:
            incident.security_assessment = security_assessment

        incident.updated_at = datetime.now(timezone.utc)
        return incident

    # ── Actions & Child Entities ──────────────────────────────────────────────

    @staticmethod
    async def add_remediation_action(
        session: AsyncSession,
        incident_id: str,
        action_data: RemediationActionCreate,
    ) -> RemediationActionRecord:
        """Adds a proposed remediation action for an incident."""
        incident = await IncidentService.get_incident(session, incident_id)
        if incident is None:
            raise ValueError(f"Incident with id '{incident_id}' not found.")

        now = datetime.now(timezone.utc)
        action = RemediationActionRecord(
            incident_id=incident_id,
            action_type=action_data.action_type,
            description=action_data.description,
            risk_level=action_data.risk_level.value,
            status="proposed",
            parameters=action_data.parameters or {},
            rollback_plan=action_data.rollback_plan,
            proposed_by=action_data.proposed_by,
            created_at=now,
        )
        session.add(action)
        await session.flush()

        audit = AuditLogRecord(
            incident_id=incident_id,
            timestamp=now,
            actor=action_data.proposed_by,
            action="action_proposed",
            details={
                "action_id": action.id,
                "action_type": action.action_type,
                "risk_level": action.risk_level,
            },
        )
        session.add(audit)
        return action

    @staticmethod
    async def update_action_status(
        session: AsyncSession,
        action_id: str,
        status: str,
        actor: str = "human_admin",
        execution_result: Optional[Dict[str, Any]] = None,
    ) -> RemediationActionRecord:
        """Update remediation action status (e.g. approved, rejected, executed)."""
        query = select(RemediationActionRecord).where(RemediationActionRecord.id == action_id)
        result = await session.execute(query)
        action = result.scalar_one_or_none()
        if action is None:
            raise ValueError(f"RemediationAction with id '{action_id}' not found.")

        now = datetime.now(timezone.utc)
        action.status = status.lower()

        if status.lower() == "approved":
            action.approved_by = actor
        elif status.lower() in ["executed", "failed"]:
            action.executed_at = now
            if execution_result:
                action.execution_result = execution_result

        audit = AuditLogRecord(
            incident_id=action.incident_id,
            timestamp=now,
            actor=actor,
            action=f"action_{status.lower()}",
            details={"action_id": action_id, "action_type": action.action_type},
        )
        session.add(audit)
        return action

    @staticmethod
    async def get_incident_anomalies(
        session: AsyncSession,
        incident_id: str,
    ) -> List[AnomalyRecord]:
        """Fetch all anomaly records associated with an incident."""
        query = (
            select(AnomalyRecord)
            .where(AnomalyRecord.incident_id == incident_id)
            .order_by(desc(AnomalyRecord.timestamp))
        )
        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_incident_actions(
        session: AsyncSession,
        incident_id: str,
    ) -> List[RemediationActionRecord]:
        """Fetch all remediation actions associated with an incident."""
        query = (
            select(RemediationActionRecord)
            .where(RemediationActionRecord.incident_id == incident_id)
            .order_by(desc(RemediationActionRecord.created_at))
        )
        result = await session.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_incident_audit_logs(
        session: AsyncSession,
        incident_id: str,
    ) -> List[AuditLogRecord]:
        """Fetch the full audit trail for an incident."""
        query = (
            select(AuditLogRecord)
            .where(AuditLogRecord.incident_id == incident_id)
            .order_by(desc(AuditLogRecord.timestamp))
        )
        result = await session.execute(query)
        return list(result.scalars().all())

    # ── Incident Statistics Summary ──────────────────────────────────────────

    @staticmethod
    async def get_stats_summary(session: AsyncSession) -> IncidentStatsSummary:
        """Calculate high-level incident aggregation counters."""
        total_query = select(func.count()).select_from(Incident)
        total_res = await session.execute(total_query)
        total = total_res.scalar_one()

        # Status counts
        status_query = select(Incident.status, func.count()).group_by(Incident.status)
        status_res = await session.execute(status_query)
        by_status = {row[0]: row[1] for row in status_res.all()}

        # Severity counts
        severity_query = select(Incident.severity, func.count()).group_by(Incident.severity)
        severity_res = await session.execute(severity_query)
        by_severity = {row[0]: row[1] for row in severity_res.all()}

        active = sum(by_status.get(s, 0) for s in ACTIVE_STATUSES)
        resolved = by_status.get("resolved", 0)
        dismissed = by_status.get("dismissed", 0)

        return IncidentStatsSummary(
            total=total,
            active=active,
            resolved=resolved,
            dismissed=dismissed,
            by_severity=by_severity,
            by_status=by_status,
        )
