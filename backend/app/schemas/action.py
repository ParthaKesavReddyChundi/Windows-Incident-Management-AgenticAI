"""
Pydantic schemas for remediation actions and human approval workflow.

SAFETY NOTE: The allowlist of executable actions is defined in
remediation/allowlist.py. These schemas only describe the data shapes
for proposals and approvals — they do not grant execution permissions.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ActionProposal(BaseModel):
    """A remediation action proposed by the Remediation Agent."""
    action_id: str = Field(..., description="Unique identifier for this proposal")
    incident_id: str
    action_type: str = Field(..., description="Must match an entry in the allowlist")
    display_name: str = Field(..., description="Human-readable action name")
    description: str = Field(..., description="What this action will do")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    risk: ActionRisk
    risk_explanation: str
    prerequisites: List[str] = Field(default_factory=list)
    possible_side_effects: List[str] = Field(default_factory=list)
    is_reversible: bool = False
    rollback_description: Optional[str] = None
    rag_sources: List[str] = Field(default_factory=list, description="Retrieved knowledge sources")
    proposed_at: datetime = Field(default_factory=datetime.utcnow)
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_timeout_seconds: int = 300


class ApprovalRequest(BaseModel):
    """Human submits an approval or rejection decision."""
    action_id: str
    decision: ApprovalStatus = Field(
        ..., description="Must be 'approved' or 'rejected'"
    )
    reviewer_notes: Optional[str] = None

    def is_valid_decision(self) -> bool:
        return self.decision in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED)


class ActionResult(BaseModel):
    """Result of executing an approved action."""
    action_id: str
    incident_id: str
    executed_at: datetime
    success: bool
    output: str
    error: Optional[str] = None
    rollback_available: bool = False


class AuditLogEntry(BaseModel):
    """Immutable audit trail record."""
    entry_id: str
    timestamp: datetime
    actor: str = Field(..., description="'system', 'agent', or 'human'")
    action: str
    incident_id: Optional[str] = None
    action_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    outcome: str
