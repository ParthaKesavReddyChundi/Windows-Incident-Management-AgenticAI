"""
backend/app/schemas/incident.py
================================
Pydantic schemas for incidents, investigations, actions, audit logs, and statistics.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    REMEDIATING = "remediating"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"


# ── Evidence & Investigation Models ───────────────────────────────────────────

class EvidenceItem(BaseModel):
    source: str = Field(..., description="Evidence source (e.g. 'cpu_collector', 'event_log')")
    content: str = Field(..., description="Human-readable description of the evidence")
    raw: Optional[Dict[str, Any]] = Field(None, description="Raw data object")
    timestamp: Optional[datetime] = None


class DiagnosisResult(BaseModel):
    probable_root_cause: str
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0, description="0–1 confidence score")
    uncertainty_notes: Optional[str] = None
    investigated_at: datetime = Field(default_factory=datetime.utcnow)


class SecurityAssessment(BaseModel):
    risk_level: Severity
    summary: str
    indicators: List[str] = Field(default_factory=list)
    is_confirmed_threat: bool = False
    notes: str = ""
    assessed_at: datetime = Field(default_factory=datetime.utcnow)


# ── Anomaly Record Schemas ───────────────────────────────────────────────────

class AnomalyRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: Optional[str] = None
    timestamp: datetime
    score: float
    threshold: float
    severity: str
    is_anomaly: bool
    top_features: Optional[List[Dict[str, Any]]] = None
    raw_features: Optional[Dict[str, Any]] = None


# ── Remediation Action Schemas ────────────────────────────────────────────────

class RemediationActionCreate(BaseModel):
    action_type: str = Field(..., description="Action identifier, e.g. 'restart_service', 'kill_process'")
    description: str = Field(..., description="Human-readable rationale for the action")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="Operational risk tier")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Action arguments")
    rollback_plan: Optional[str] = Field(None, description="Step-by-step fallback or undo strategy")
    proposed_by: str = Field(default="ai_agent", description="Actor who generated this plan")


class RemediationActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    action_type: str
    description: str
    risk_level: str
    status: str
    parameters: Optional[Dict[str, Any]] = None
    rollback_plan: Optional[str] = None
    proposed_by: str
    approved_by: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None
    created_at: datetime
    executed_at: Optional[datetime] = None


# ── Audit Log Schemas ────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: Optional[str] = None
    timestamp: datetime
    actor: str
    action: str
    details: Optional[Dict[str, Any]] = None


# ── Incident CRUD Schemas ────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: Optional[str] = Field(None, description="Incident title; auto-generated if omitted")
    description: Optional[str] = None
    severity: Severity = Field(default=Severity.MEDIUM)
    source: str = Field(default="live", description="'live' | 'simulated'")
    snapshot_id: Optional[str] = None
    anomaly_score: float = Field(default=0.0, ge=0.0)


class IncidentUpdateStatus(BaseModel):
    status: IncidentStatus = Field(..., description="Target lifecycle status")
    actor: str = Field(default="human_admin", description="Actor initiating the transition")
    reason: Optional[str] = Field(None, description="Justification for the state change")


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: Optional[str] = None
    severity: Severity
    status: IncidentStatus
    source: str
    anomaly_score: float
    snapshot_id: Optional[str] = None

    root_cause: Optional[str] = None
    confidence: Optional[float] = None
    recommended_actions: List[str] = Field(default_factory=list)
    diagnosis: Optional[Dict[str, Any]] = None
    security_assessment: Optional[Dict[str, Any]] = None

    detected_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None


class IncidentDetailResponse(IncidentResponse):
    """Detailed incident response including associated child records."""
    anomalies: List[AnomalyRecordResponse] = Field(default_factory=list)
    actions: List[RemediationActionResponse] = Field(default_factory=list)
    audit_logs: List[AuditLogResponse] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    total: int
    incidents: List[IncidentResponse]


class IncidentStatsSummary(BaseModel):
    total: int
    active: int
    resolved: int
    dismissed: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]

    total_incidents: Optional[int] = None
    active_incidents: Optional[int] = None
    resolved_incidents: Optional[int] = None
    dismissed_incidents: Optional[int] = None
    severity_breakdown: Optional[Dict[str, int]] = None
    status_breakdown: Optional[Dict[str, int]] = None

    def model_post_init(self, __context: Any) -> None:
        if self.total_incidents is None:
            self.total_incidents = self.total
        if self.active_incidents is None:
            self.active_incidents = self.active
        if self.resolved_incidents is None:
            self.resolved_incidents = self.resolved
        if self.dismissed_incidents is None:
            self.dismissed_incidents = self.dismissed
        if self.severity_breakdown is None:
            self.severity_breakdown = self.by_severity
        if self.status_breakdown is None:
            self.status_breakdown = self.by_status
