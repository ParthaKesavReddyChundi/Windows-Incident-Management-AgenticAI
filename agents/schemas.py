"""
agents/schemas.py
=================
Structured Pydantic input and output schemas for the Multi-Agent AI system:
- DiagnosisAgentOutput
- SecurityAgentOutput
- RemediationActionProposal & RemediationAgentOutput
- InvestigationWorkflowState (LangGraph State)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from typing_extensions import TypedDict

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DiagnosisAgentOutput(BaseModel):
    """Structured output produced by the Diagnosis Agent."""

    probable_root_cause: str = Field(
        ...,
        description="Concise description of the primary root cause identified",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score from 0.0 to 1.0 based on evidence strength",
    )
    affected_subsystems: List[str] = Field(
        default_factory=list,
        description="Impacted operating system components (e.g. CPU, RAM, Network, Storage, Service)",
    )
    supporting_evidence: List[str] = Field(
        default_factory=list,
        description="Key telemetry metrics, logs, or deviant features supporting this diagnosis",
    )
    technical_analysis: str = Field(
        ...,
        description="In-depth technical explanation of why this incident occurred",
    )
    uncertainty_notes: Optional[str] = Field(
        None,
        description="Any caveats, missing telemetry, or alternate explanations",
    )

    model_config = ConfigDict(extra="ignore")


class SecurityAgentOutput(BaseModel):
    """Structured output produced by the Security Agent."""

    threat_classification: str = Field(
        ...,
        description=(
            "Classification of the incident (e.g. 'benign_performance_spike', "
            "'malware_or_cryptominer', 'denial_of_service', 'data_exfiltration', "
            "'privilege_escalation', 'unauthorized_access')"
        ),
    )
    risk_level: str = Field(
        ...,
        description="Operational risk level: 'low', 'medium', 'high', or 'critical'",
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="Associated MITRE ATT&CK technique IDs (e.g. ['T1059', 'T1499'])",
    )
    threat_indicators: List[str] = Field(
        default_factory=list,
        description="Observable indicators of compromise or suspicious activity",
    )
    is_confirmed_threat: bool = Field(
        default=False,
        description="True if malicious cyber activity is detected; False if benign operational issue",
    )
    containment_required: bool = Field(
        default=False,
        description="True if immediate host or network isolation is required",
    )
    summary: str = Field(
        ...,
        description="Summary of security assessment and potential impact",
    )

    @field_validator("risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.lower().strip()
        return "medium"

    model_config = ConfigDict(extra="ignore")


class RemediationActionProposal(BaseModel):
    """Individual allowlisted remediation action proposal."""

    action_type: str = Field(
        ...,
        description=(
            "Standard action identifier: 'throttle_process', 'kill_process', "
            "'restart_service', 'flush_memory', 'block_ip', 'isolate_network'"
        ),
    )
    target: str = Field(
        ...,
        description="Target identifier (e.g. PID '4120', service name 'Spooler', IP '192.168.1.5')",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters required to execute the action",
    )
    description: str = Field(
        ...,
        description="Clear operational rationale explaining what the action will do",
    )
    risk_level: str = Field(
        default="low",
        description="Operational risk level: 'read_only', 'low', 'medium', 'high'",
    )
    command_template: str = Field(
        ...,
        description="PowerShell command string that would execute this action",
    )
    expected_impact: str = Field(
        ...,
        description="Anticipated system outcome (e.g. 'CPU usage drops below 20%')",
    )
    verification_step: str = Field(
        ...,
        description="How to verify that the remediation succeeded",
    )
    rollback_plan: str = Field(
        ...,
        description="Fallback procedure if the action causes adverse behavior",
    )
    requires_human_approval: bool = Field(
        default=True,
        description="Whether human administrator approval is required prior to execution",
    )

    @field_validator("risk_level", mode="before")
    @classmethod
    def normalize_risk_level(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.lower().strip()
        return "low"

    model_config = ConfigDict(extra="ignore")


class RemediationAgentOutput(BaseModel):
    """Structured output produced by the Remediation Agent."""

    executive_summary: str = Field(
        ...,
        description="Executive summary of the remediation plan",
    )
    proposed_actions: List[RemediationActionProposal] = Field(
        default_factory=list,
        description="Ordered list of allowlisted mitigation steps",
    )
    estimated_resolution_time_sec: int = Field(
        default=30,
        description="Estimated seconds required for mitigation",
    )

    model_config = ConfigDict(extra="ignore")


class InvestigationWorkflowState(TypedDict, total=False):
    """State object passed along the LangGraph multi-agent execution pipeline."""

    incident_id: str
    title: str
    description: str
    severity: str
    anomaly_score: float
    top_deviant_features: List[str]
    telemetry_summary: Dict[str, Any]
    rag_context: str
    diagnosis: Optional[Dict[str, Any]]
    security_assessment: Optional[Dict[str, Any]]
    remediation: Optional[Dict[str, Any]]
    current_step: str
    errors: List[str]
