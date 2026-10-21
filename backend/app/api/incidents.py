"""
backend/app/api/incidents.py
============================
Incidents REST API endpoints backed by SQLAlchemy async SQLite persistence.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.schemas.incident import (
    AnomalyRecordResponse,
    AuditLogResponse,
    IncidentCreate,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentResponse,
    IncidentStatsSummary,
    IncidentUpdateStatus,
    RemediationActionCreate,
    RemediationActionResponse,
)
from backend.app.services.incident_service import IncidentService
from database.session import get_db
from database.state_machine import InvalidStateTransitionError

router = APIRouter()


# ── Listing & Aggregations ───────────────────────────────────────────────────

@router.get("", response_model=IncidentListResponse)
@router.get("/", response_model=IncidentListResponse, include_in_schema=False)
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status (e.g. 'detected', 'investigating', 'resolved')"),
    severity: Optional[str] = Query(None, description="Filter by severity ('low', 'medium', 'high', 'critical')"),
    source: Optional[str] = Query(None, description="Filter by source ('live', 'simulated')"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    """List all incidents with optional filtering and pagination."""
    incidents, total = await IncidentService.list_incidents(
        session=session,
        status=status,
        severity=severity,
        source=source,
        limit=limit,
        offset=offset,
    )
    return IncidentListResponse(
        total=total,
        incidents=[IncidentResponse.model_validate(inc) for inc in incidents],
    )


@router.get("/stats/summary", response_model=IncidentStatsSummary)
async def get_stats_summary(
    session: AsyncSession = Depends(get_db),
) -> IncidentStatsSummary:
    """Get high-level counters for dashboard widgets."""
    return await IncidentService.get_stats_summary(session)


# ── Single Incident Operations ────────────────────────────────────────────────

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_incident(
    data: IncidentCreate,
    session: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    """Manually create an incident ticket."""
    incident = await IncidentService.create_incident(session, data)
    return IncidentResponse.model_validate(incident)


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> IncidentDetailResponse:
    """Fetch full incident details including related anomalies, actions, and audit logs."""
    incident = await IncidentService.get_incident(session, incident_id, include_children=True)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )
    return IncidentDetailResponse.model_validate(incident)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    payload: IncidentUpdateStatus,
    session: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    """
    Transition an incident's lifecycle state via the state machine.
    Validates transition rules and generates an audit log entry.
    """
    try:
        incident = await IncidentService.transition_status(
            session=session,
            incident_id=incident_id,
            target_status=payload.status.value,
            actor=payload.actor,
            reason=payload.reason,
        )
        return IncidentResponse.model_validate(incident)
    except InvalidStateTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# ── Child Entity Endpoints ───────────────────────────────────────────────────

@router.get("/{incident_id}/anomalies", response_model=List[AnomalyRecordResponse])
async def get_incident_anomalies(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> List[AnomalyRecordResponse]:
    """Retrieve all anomaly events correlated with this incident."""
    incident = await IncidentService.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    anomalies = await IncidentService.get_incident_anomalies(session, incident_id)
    return [AnomalyRecordResponse.model_validate(a) for a in anomalies]


@router.get("/{incident_id}/actions", response_model=List[RemediationActionResponse])
async def get_incident_actions(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> List[RemediationActionResponse]:
    """Retrieve all proposed or executed remediation actions for this incident."""
    incident = await IncidentService.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    actions = await IncidentService.get_incident_actions(session, incident_id)
    return [RemediationActionResponse.model_validate(a) for a in actions]


@router.post("/{incident_id}/actions", response_model=RemediationActionResponse, status_code=status.HTTP_201_CREATED)
async def add_incident_action(
    incident_id: str,
    payload: RemediationActionCreate,
    session: AsyncSession = Depends(get_db),
) -> RemediationActionResponse:
    """Propose a new remediation action for this incident."""
    try:
        action = await IncidentService.add_remediation_action(session, incident_id, payload)
        return RemediationActionResponse.model_validate(action)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{incident_id}/audit-logs", response_model=List[AuditLogResponse])
async def get_incident_audit_logs(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> List[AuditLogResponse]:
    """Retrieve the complete audit trail for this incident."""
    incident = await IncidentService.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    logs = await IncidentService.get_incident_audit_logs(session, incident_id)
    return [AuditLogResponse.model_validate(log) for log in logs]


# ── Multi-Agent AI Investigation Endpoints ────────────────────────────────────

@router.post("/{incident_id}/investigate")
async def investigate_incident(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """
    Trigger Multi-Agent AI (Diagnosis -> Security -> Remediation) investigation
    over the incident using LangGraph and local Ollama.
    """
    from backend.app.services.investigation_service import InvestigationService
    try:
        service = InvestigationService.get_instance()
        result = await service.investigate_incident(incident_id=incident_id, db=session)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation workflow failed: {str(e)}",
        )


@router.get("/{incident_id}/investigation")
async def get_incident_investigation(
    incident_id: str,
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Retrieve the stored Multi-Agent investigation report for this incident."""
    incident = await IncidentService.get_incident(session, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {
        "incident_id": incident.id,
        "status": incident.status,
        "root_cause": incident.root_cause,
        "confidence": incident.confidence,
        "diagnosis": incident.diagnosis,
        "security_assessment": incident.security_assessment,
        "recommended_actions": incident.recommended_actions,
    }
