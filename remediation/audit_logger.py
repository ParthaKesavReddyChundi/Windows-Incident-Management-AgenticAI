"""
remediation/audit_logger.py
============================
Immutable, hash-chained audit log for remediation actions.

Every action approval, rejection, execution, verification, and rollback is
recorded as an immutable JSON log entry. Each entry carries the SHA-256 hash
of the previous entry, forming a tamper-evident hash chain. Entries are
appended to a dedicated audit log file in the logs directory and also persisted
to the database AuditLogRecord table.

Design:
    - Append-only file log (never delete, never overwrite)
    - SHA-256 hash chain linking entries sequentially
    - Structured JSON per line for easy grep / SIEM ingestion
    - Separate from general application logs for compliance isolation
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from config.settings import settings

logger = logging.getLogger("remediation.audit")

# Path to the dedicated remediation audit log file
_AUDIT_LOG_PATH: Path = settings.logs_dir / "remediation_audit.jsonl"

# Thread lock for safe concurrent append
_WRITE_LOCK = threading.Lock()


class AuditLogger:
    """
    Writes tamper-evident, hash-chained audit entries for all remediation events.
    Entries are appended to a `.jsonl` file and returned for database persistence.
    """

    _previous_hash: str = "GENESIS"  # Hash of the genesis (first) entry

    @classmethod
    def _get_previous_hash(cls) -> str:
        """Get the current previous hash, recovering from disk if available."""
        if cls._previous_hash != "GENESIS":
            return cls._previous_hash
        if _AUDIT_LOG_PATH.exists():
            try:
                lines = _AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        data = json.loads(line)
                        if "entry_hash" in data:
                            cls._previous_hash = data["entry_hash"]
                            return cls._previous_hash
            except Exception:
                pass
        return "GENESIS"

    @classmethod
    def _compute_hash(cls, entry: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of the serialized JSON entry."""
        raw = json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _write_entry(cls, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build, chain, and write an audit entry.

        Args:
            event_type: Classification of the event (see event types below).
            payload: Event-specific fields.

        Returns:
            The full audit entry dictionary.
        """
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "previous_hash": cls._get_previous_hash(),
            **payload,
        }
        entry_hash = cls._compute_hash(entry)
        entry["entry_hash"] = entry_hash

        with _WRITE_LOCK:
            # Ensure log directory exists
            _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(_AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            cls._previous_hash = entry_hash

        logger.info(
            f"AuditLogger [{event_type}] hash={entry_hash[:16]}... "
            f"incident={payload.get('incident_id', 'N/A')} "
            f"action={payload.get('action_id', 'N/A')}"
        )
        return entry

    # ── Public event-specific methods ──────────────────────────────────────────

    @classmethod
    def log_action_proposed(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        target: str,
        risk_level: str,
        proposed_by: str,
        description: str,
    ) -> Dict[str, Any]:
        """Log an AI-proposed remediation action awaiting human approval."""
        return cls._write_entry(
            "action_proposed",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "target": target,
                "risk_level": risk_level,
                "proposed_by": proposed_by,
                "description": description,
            },
        )

    @classmethod
    def log_action_approved(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        approved_by: str,
    ) -> Dict[str, Any]:
        """Log human approval of a proposed action."""
        return cls._write_entry(
            "action_approved",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "approved_by": approved_by,
            },
        )

    @classmethod
    def log_action_rejected(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        rejected_by: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Log human rejection of a proposed action."""
        return cls._write_entry(
            "action_rejected",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "rejected_by": rejected_by,
                "reason": reason or "No reason provided",
            },
        )

    @classmethod
    def log_safety_violation(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        violation_message: str,
    ) -> Dict[str, Any]:
        """Log a safety policy violation that blocked execution."""
        return cls._write_entry(
            "safety_violation",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "violation_message": violation_message,
            },
        )

    @classmethod
    def log_execution_started(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        target: str,
        actor: str,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Log the start of action execution."""
        return cls._write_entry(
            "execution_started",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "target": target,
                "actor": actor,
                "dry_run": dry_run,
            },
        )

    @classmethod
    def log_execution_completed(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        success: bool,
        returncode: Optional[int],
        stdout: str,
        stderr: str,
        elapsed_seconds: float,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Log execution completion with full output capture."""
        return cls._write_entry(
            "execution_completed",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "success": success,
                "returncode": returncode,
                "stdout": stdout[:500],    # Truncate for log readability
                "stderr": stderr[:500],
                "elapsed_seconds": elapsed_seconds,
                "error_message": error_message,
            },
        )

    @classmethod
    def log_verification_result(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        verified: bool,
        check_output: str,
        details: str,
    ) -> Dict[str, Any]:
        """Log the automated post-execution verification result."""
        return cls._write_entry(
            "verification_result",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "verified": verified,
                "check_output": check_output[:500],
                "details": details,
            },
        )

    @classmethod
    def log_rollback_result(
        cls,
        incident_id: str,
        action_id: str,
        action_type: str,
        rollback_triggered: bool,
        rollback_success: bool,
        stdout: str,
        error_message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Log the rollback execution result."""
        return cls._write_entry(
            "rollback_result",
            {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "rollback_triggered": rollback_triggered,
                "rollback_success": rollback_success,
                "stdout": stdout[:500],
                "error_message": error_message,
            },
        )

    @classmethod
    def get_audit_log_path(cls) -> Path:
        """Return the path to the audit log file."""
        return _AUDIT_LOG_PATH

    @classmethod
    def read_entries(cls, limit: int = 100) -> list:
        """Read and return the last N audit log entries."""
        if not _AUDIT_LOG_PATH.exists():
            return []
        try:
            lines = _AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
            tail = lines[-limit:] if len(lines) > limit else lines
            return [json.loads(line) for line in tail if line.strip()]
        except Exception as e:
            logger.error(f"AuditLogger: Failed to read log: {e}")
            return []
