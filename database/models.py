"""
database/models.py
==================
SQLAlchemy ORM models for incidents, anomalies, remediation actions, and audit logs.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy declarative models."""
    pass


class Incident(Base):
    """
    Core Incident entity representing a detected system disruption or anomaly.
    """
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Untitled Incident")
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")  # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="detected")   # detected, investigating, awaiting_approval, remediating, mitigated, resolved, dismissed
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="live")      # live, simulated, benchmark
    
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    snapshot_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    
    # Root Cause & Investigation
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recommended_actions: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True, default=list)
    diagnosis: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    security_assessment: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    anomalies: Mapped[List["AnomalyRecord"]] = relationship(
        "AnomalyRecord", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    actions: Mapped[List["RemediationActionRecord"]] = relationship(
        "RemediationActionRecord", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    audit_logs: Mapped[List["AuditLogRecord"]] = relationship(
        "AuditLogRecord", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_detected_at", "detected_at"),
    )


class AnomalyRecord(Base):
    """
    Individual anomaly detection event from the Autoencoder or rule engine.
    """
    __tablename__ = "anomaly_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    
    score: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    
    top_features: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True, default=list)
    raw_features: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)

    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="anomalies")

    __table_args__ = (
        Index("ix_anomalies_timestamp", "timestamp"),
    )


class RemediationActionRecord(Base):
    """
    Remediation or mitigation action proposed, approved, or executed for an incident.
    """
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)  # restart_service, kill_process, adjust_priority, flush_dns, etc.
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="low")  # read_only, low, medium, high
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="proposed")  # proposed, approved, rejected, executing, executed, failed
    
    parameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)
    rollback_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    proposed_by: Mapped[str] = mapped_column(String(50), nullable=False, default="ai_agent")  # ai_agent, rule_engine, human_admin
    approved_by: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)             # human_admin
    execution_result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="actions")

    __table_args__ = (
        Index("ix_actions_status", "status"),
    )


class AuditLogRecord(Base):
    """
    Immutable audit trail recording state transitions, approvals, and actions.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    actor: Mapped[str] = mapped_column(String(50), nullable=False)  # system, ai_agent, human_admin
    action: Mapped[str] = mapped_column(String(100), nullable=False) # created, state_transition, action_proposed, action_approved, action_rejected, action_executed
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True, default=dict)

    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_timestamp", "timestamp"),
    )
