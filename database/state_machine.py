r"""
database/state_machine.py
=========================
Incident lifecycle state machine and transition validation.

Valid Lifecycle:
  DETECTED -> INVESTIGATING -> AWAITING_APPROVAL -> REMEDIATING -> MITIGATED -> RESOLVED
                                                 \-> DISMISSED
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Optional, Set

from database.models import AuditLogRecord, Incident

logger = logging.getLogger(__name__)


class InvalidStateTransitionError(ValueError):
    """Raised when an invalid incident state transition is attempted."""
    def __init__(self, current_status: str, target_status: str, allowed: Set[str]) -> None:
        super().__init__(
            f"Invalid incident state transition: '{current_status}' -> '{target_status}'. "
            f"Allowed next states from '{current_status}': {sorted(list(allowed))}"
        )
        self.current_status = current_status
        self.target_status = target_status
        self.allowed = allowed


class IncidentStateMachine:
    """
    Enforces valid transitions across the incident response lifecycle.
    """

    ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
        "detected": {"investigating", "dismissed"},
        "investigating": {"awaiting_approval", "remediating", "resolved", "dismissed"},
        "awaiting_approval": {"remediating", "investigating", "dismissed"},
        "remediating": {"mitigated", "investigating", "resolved"},
        "mitigated": {"resolved", "investigating"},
        "resolved": {"investigating"},  # Allows reopening incident if re-triggered
        "dismissed": {"investigating"},  # Allows reopening if determined not false-positive
    }

    @classmethod
    def can_transition(cls, current_status: str, target_status: str) -> bool:
        """Return True if transition from current_status to target_status is permitted."""
        current = current_status.lower()
        target = target_status.lower()
        if current == target:
            return True
        allowed = cls.ALLOWED_TRANSITIONS.get(current, set())
        return target in allowed

    @classmethod
    def validate_transition(cls, current_status: str, target_status: str) -> None:
        """Validate transition, raising InvalidStateTransitionError if prohibited."""
        current = current_status.lower()
        target = target_status.lower()
        if current == target:
            return
        allowed = cls.ALLOWED_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise InvalidStateTransitionError(current, target, allowed)

    @classmethod
    def transition(
        cls,
        incident: Incident,
        target_status: str,
        actor: str = "system",
        reason: Optional[str] = None,
    ) -> AuditLogRecord:
        """
        Validates and transitions the incident to target_status, updating timestamps
        and returning an AuditLogRecord for logging the state change.
        """
        old_status = incident.status
        target = target_status.lower()
        cls.validate_transition(old_status, target)

        now = datetime.now(timezone.utc)
        incident.status = target
        incident.updated_at = now

        if target == "resolved":
            incident.resolved_at = now
        elif old_status == "resolved" and target != "resolved":
            incident.resolved_at = None

        audit_entry = AuditLogRecord(
            incident_id=incident.id,
            timestamp=now,
            actor=actor,
            action="state_transition",
            details={
                "from_status": old_status,
                "to_status": target,
                "reason": reason,
            },
        )
        logger.info(
            "Incident %s transitioned: %s -> %s by actor=%s (reason=%s)",
            incident.id,
            old_status,
            target,
            actor,
            reason,
        )
        return audit_entry
