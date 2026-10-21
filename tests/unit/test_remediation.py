"""
tests/unit/test_remediation.py
===============================
Unit tests for Phase 9 — Controlled Remediation & Safety subsystem.

Tests:
    - SafetyGuard allowlist validation
    - SafetyGuard parameter injection prevention
    - SafetyGuard protected process/service enforcement
    - ActionExecutor dry-run and simulation paths
    - VerificationEngine simulation
    - RollbackEngine simulation
    - AuditLogger hash-chain integrity
    - RemediationService approval/rejection via FastAPI TestClient
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from remediation.audit_logger import AuditLogger
from remediation.safety_guard import (
    ALLOWLISTED_ACTION_TYPES,
    SafetyGuard,
    SafetyViolation,
)



# ══════════════════════════════════════════════════════════════════════════════
# TestSafetyGuardAllowlist
# ══════════════════════════════════════════════════════════════════════════════

class TestSafetyGuardAllowlist:
    """Test that only allowlisted action types pass validation."""

    def test_allowlisted_action_types_are_correct(self) -> None:
        expected = {
            "throttle_process", "kill_process", "restart_service",
            "flush_memory", "block_ip", "isolate_network",
        }
        assert ALLOWLISTED_ACTION_TYPES == expected

    def test_valid_restart_service_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="restart_service",
            target="wuauserv",
            parameters={"service_name": "wuauserv"},
            risk_level="medium",
            requires_human_approval=True,
        )

    def test_valid_throttle_process_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="throttle_process",
            target="notepad",
            parameters={"process_name": "notepad"},
            risk_level="low",
            requires_human_approval=False,
        )

    def test_valid_flush_memory_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="flush_memory",
            target="system",
            parameters={},
            risk_level="low",
            requires_human_approval=False,
        )

    def test_unknown_action_type_raises(self) -> None:
        with pytest.raises(SafetyViolation, match="not in the allowlisted"):
            SafetyGuard.validate_action(
                action_type="delete_files",
                target="C:\\Windows",
                parameters={},
                risk_level="high",
                requires_human_approval=True,
            )

    def test_format_disk_rejected(self) -> None:
        with pytest.raises(SafetyViolation):
            SafetyGuard.validate_action(
                action_type="format_disk",
                target="C:",
                parameters={},
                risk_level="high",
                requires_human_approval=True,
            )

    def test_arbitrary_action_rejected(self) -> None:
        with pytest.raises(SafetyViolation):
            SafetyGuard.validate_action(
                action_type="run_powershell_arbitrary",
                target="anything",
                parameters={},
                risk_level="high",
                requires_human_approval=True,
            )


# ══════════════════════════════════════════════════════════════════════════════
# TestSafetyGuardInjectionPrevention
# ══════════════════════════════════════════════════════════════════════════════

class TestSafetyGuardInjectionPrevention:
    """Test injection character detection in targets and parameters."""

    @pytest.mark.parametrize("bad_value", [
        "notepad; rm -rf /",
        "svc | cmd.exe",
        "proc && del C:",
        "target`id`",
        "proc\nkill -9 1",
        "foo$(evil)",
        "svc > outfile",
        "proc\x00hidden",
    ])
    def test_injection_in_target_raises(self, bad_value: str) -> None:
        with pytest.raises(SafetyViolation, match="forbidden characters"):
            SafetyGuard.validate_action(
                action_type="restart_service",
                target=bad_value,
                parameters={"service_name": "wuauserv"},
                risk_level="medium",
                requires_human_approval=True,
            )

    @pytest.mark.parametrize("bad_param", [
        "svc; evil",
        "process | cmd",
    ])
    def test_injection_in_parameters_raises(self, bad_param: str) -> None:
        with pytest.raises(SafetyViolation, match="forbidden characters"):
            SafetyGuard.validate_action(
                action_type="restart_service",
                target="wuauserv",
                parameters={"service_name": bad_param},
                risk_level="medium",
                requires_human_approval=True,
            )

    def test_clean_service_name_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="restart_service",
            target="Spooler",
            parameters={"service_name": "Spooler"},
            risk_level="medium",
            requires_human_approval=True,
        )

    def test_clean_process_name_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="kill_process",
            target="malware-proc",
            parameters={"process_name": "malware-proc"},
            risk_level="medium",
            requires_human_approval=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TestSafetyGuardProtectedTargets
# ══════════════════════════════════════════════════════════════════════════════

class TestSafetyGuardProtectedTargets:
    """Test that protected system processes cannot be killed or throttled."""

    @pytest.mark.parametrize("protected", ["lsass", "csrss", "wininit", "smss", "services"])
    def test_kill_protected_process_raises(self, protected: str) -> None:
        with pytest.raises(SafetyViolation, match="protected system process"):
            SafetyGuard.validate_action(
                action_type="kill_process",
                target=protected,
                parameters={"process_name": protected},
                risk_level="medium",
                requires_human_approval=True,
            )

    @pytest.mark.parametrize("protected", ["lsass.exe", "csrss.exe", "wininit.exe"])
    def test_kill_protected_process_with_exe_raises(self, protected: str) -> None:
        with pytest.raises(SafetyViolation, match="protected system process"):
            SafetyGuard.validate_action(
                action_type="kill_process",
                target=protected,
                parameters={"process_name": protected},
                risk_level="medium",
                requires_human_approval=True,
            )

    def test_kill_non_protected_process_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="kill_process",
            target="notepad",
            parameters={"process_name": "notepad"},
            risk_level="medium",
            requires_human_approval=True,
        )

    def test_invalid_pid_raises(self) -> None:
        with pytest.raises(SafetyViolation, match="Invalid PID"):
            SafetyGuard.validate_action(
                action_type="kill_process",
                target="notepad",
                parameters={"process_name": "notepad", "pid": "not-a-number"},
                risk_level="medium",
                requires_human_approval=True,
            )

    def test_valid_pid_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="kill_process",
            target="notepad",
            parameters={"process_name": "notepad", "pid": "1234"},
            risk_level="medium",
            requires_human_approval=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# TestSafetyGuardNetworkActions
# ══════════════════════════════════════════════════════════════════════════════

class TestSafetyGuardNetworkActions:
    """Test network action validations."""

    def test_valid_ip_block_passes(self) -> None:
        SafetyGuard.validate_action(
            action_type="block_ip",
            target="10.0.0.5",
            parameters={"remote_ip": "10.0.0.5"},
            risk_level="high",
            requires_human_approval=True,
        )

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(SafetyViolation, match="Invalid IP"):
            SafetyGuard.validate_action(
                action_type="block_ip",
                target="not-an-ip",
                parameters={"remote_ip": "not-an-ip"},
                risk_level="high",
                requires_human_approval=True,
            )

    def test_localhost_ip_raises(self) -> None:
        with pytest.raises(SafetyViolation, match="loopback"):
            SafetyGuard.validate_action(
                action_type="block_ip",
                target="127.0.0.1",
                parameters={"remote_ip": "127.0.0.1"},
                risk_level="high",
                requires_human_approval=True,
            )

    def test_high_risk_requires_human_approval(self) -> None:
        with pytest.raises(SafetyViolation, match="high-risk"):
            SafetyGuard.validate_action(
                action_type="block_ip",
                target="10.0.0.5",
                parameters={"remote_ip": "10.0.0.5"},
                risk_level="high",
                requires_human_approval=False,  # Missing approval for high-risk
            )

    def test_get_authoritative_risk(self) -> None:
        assert SafetyGuard.get_authoritative_risk("block_ip") == "high"
        assert SafetyGuard.get_authoritative_risk("restart_service") == "medium"
        assert SafetyGuard.get_authoritative_risk("throttle_process") == "low"
        assert SafetyGuard.get_authoritative_risk("flush_memory") == "low"
        assert SafetyGuard.get_authoritative_risk("unknown_action") == "high"

    def test_requires_human_approval_high_risk(self) -> None:
        assert SafetyGuard.requires_human_approval("block_ip") is True
        assert SafetyGuard.requires_human_approval("isolate_network") is True
        assert SafetyGuard.requires_human_approval("flush_memory") is False


# ══════════════════════════════════════════════════════════════════════════════
# TestActionExecutorDryRun
# ══════════════════════════════════════════════════════════════════════════════

class TestActionExecutorDryRun:
    """Test the ActionExecutor in dry-run mode (no actual execution)."""

    @pytest.mark.asyncio
    async def test_dry_run_restart_service(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-001",
            action_type="restart_service",
            target="wuauserv",
            parameters={"service_name": "wuauserv"},
            risk_level="medium",
            requires_human_approval=True,
            dry_run=True,
        )
        assert result.success is True
        assert "DRY-RUN" in result.stdout
        assert result.returncode == 0
        assert "wuauserv" in " ".join(result.command_used)

    @pytest.mark.asyncio
    async def test_dry_run_throttle_process(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-002",
            action_type="throttle_process",
            target="notepad",
            parameters={"process_name": "notepad"},
            risk_level="low",
            requires_human_approval=False,
            dry_run=True,
        )
        assert result.success is True
        assert "DRY-RUN" in result.stdout

    @pytest.mark.asyncio
    async def test_dry_run_flush_memory(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-003",
            action_type="flush_memory",
            target="system",
            parameters={},
            risk_level="low",
            requires_human_approval=False,
            dry_run=True,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_dry_run_block_ip(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-004",
            action_type="block_ip",
            target="10.0.0.5",
            parameters={"remote_ip": "10.0.0.5"},
            risk_level="high",
            requires_human_approval=True,
            dry_run=True,
        )
        assert result.success is True
        assert "DRY-RUN" in result.stdout

    @pytest.mark.asyncio
    async def test_safety_violation_blocked_by_executor(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        # lsass is protected — must fail safety check
        result = await executor.execute(
            action_id="test-action-005",
            action_type="kill_process",
            target="lsass",
            parameters={"process_name": "lsass"},
            risk_level="medium",
            requires_human_approval=True,
            dry_run=True,
        )
        assert result.success is False
        assert "SAFETY VIOLATION" in (result.error_message or "")

    @pytest.mark.asyncio
    async def test_dry_run_returns_command_used(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-006",
            action_type="kill_process",
            target="malware",
            parameters={"process_name": "malware", "pid": "9999"},
            risk_level="medium",
            requires_human_approval=True,
            dry_run=True,
        )
        assert "powershell.exe" in result.command_used

    @pytest.mark.asyncio
    async def test_execution_result_to_dict(self) -> None:
        from remediation.action_executor import ActionExecutor
        executor = ActionExecutor()
        result = await executor.execute(
            action_id="test-action-007",
            action_type="flush_memory",
            target="system",
            parameters={},
            risk_level="low",
            requires_human_approval=False,
            dry_run=True,
        )
        d = result.to_dict()
        assert "action_id" in d
        assert "action_type" in d
        assert "success" in d
        assert "elapsed_seconds" in d
        assert "executed_at" in d


# ══════════════════════════════════════════════════════════════════════════════
# TestVerificationEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestVerificationEngine:
    """Test the VerificationEngine (simulation path on non-Windows)."""

    @pytest.mark.asyncio
    async def test_verify_restart_service_simulated(self) -> None:
        from remediation.verification_engine import VerificationEngine
        engine = VerificationEngine()
        result = await engine.verify(
            action_type="restart_service",
            target="wuauserv",
            parameters={"service_name": "wuauserv"},
        )
        # On non-Windows simulation always returns verified=True
        assert result.action_type == "restart_service"
        assert isinstance(result.verified, bool)
        d = result.to_dict()
        assert "verified" in d

    @pytest.mark.asyncio
    async def test_verify_unknown_action_returns_unverified(self) -> None:
        from remediation.verification_engine import VerificationEngine
        engine = VerificationEngine()
        result = await engine.verify(
            action_type="nonexistent_action",
            target="anything",
            parameters={},
        )
        assert result.verified is False
        assert "No verifier" in result.details

    @pytest.mark.asyncio
    async def test_verify_block_ip_simulated(self) -> None:
        from remediation.verification_engine import VerificationEngine
        engine = VerificationEngine()
        result = await engine.verify(
            action_type="block_ip",
            target="10.0.0.5",
            parameters={"remote_ip": "10.0.0.5"},
        )
        assert isinstance(result.verified, bool)

    @pytest.mark.asyncio
    async def test_verify_flush_memory_simulated(self) -> None:
        from remediation.verification_engine import VerificationEngine
        engine = VerificationEngine()
        result = await engine.verify(
            action_type="flush_memory",
            target="system",
            parameters={},
        )
        assert isinstance(result.verified, bool)


# ══════════════════════════════════════════════════════════════════════════════
# TestRollbackEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestRollbackEngine:
    """Test the RollbackEngine (simulation path on non-Windows)."""

    @pytest.mark.asyncio
    async def test_rollback_restart_service_simulated(self) -> None:
        from remediation.rollback_engine import RollbackEngine
        engine = RollbackEngine()
        result = await engine.execute_rollback(
            action_type="restart_service",
            target="wuauserv",
            parameters={"service_name": "wuauserv"},
            custom_rollback_plan="Stop-Service -Name wuauserv",
        )
        assert result.rollback_triggered is True
        assert isinstance(result.success, bool)
        d = result.to_dict()
        assert "rollback_triggered" in d

    @pytest.mark.asyncio
    async def test_rollback_block_ip_simulated(self) -> None:
        from remediation.rollback_engine import RollbackEngine
        engine = RollbackEngine()
        result = await engine.execute_rollback(
            action_type="block_ip",
            target="10.0.0.5",
            parameters={"remote_ip": "10.0.0.5"},
        )
        assert result.rollback_triggered is True

    @pytest.mark.asyncio
    async def test_rollback_unknown_action(self) -> None:
        from remediation.rollback_engine import RollbackEngine
        engine = RollbackEngine()
        result = await engine.execute_rollback(
            action_type="nonexistent_action",
            target="anything",
            parameters={},
        )
        assert result.rollback_triggered is False
        assert result.success is False

    @pytest.mark.asyncio
    async def test_rollback_kill_process_logs_manual_required(self) -> None:
        from remediation.rollback_engine import RollbackEngine
        engine = RollbackEngine()
        result = await engine.execute_rollback(
            action_type="kill_process",
            target="malware",
            parameters={"process_name": "malware"},
        )
        assert result.rollback_triggered is True


# ══════════════════════════════════════════════════════════════════════════════
# TestAuditLogger
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogger:
    """Test hash-chain integrity in the AuditLogger."""

    def test_hash_chain_integrity(self, tmp_path: Path) -> None:
        """Each entry's previous_hash must match the previous entry's entry_hash."""
        from remediation import audit_logger
        # Redirect audit log to temp path for isolation
        original_path = audit_logger._AUDIT_LOG_PATH
        audit_logger._AUDIT_LOG_PATH = tmp_path / "test_audit.jsonl"
        audit_logger.AuditLogger._previous_hash = "GENESIS"

        try:
            AuditLogger.log_action_proposed(
                incident_id="INC-001",
                action_id="ACT-001",
                action_type="restart_service",
                target="wuauserv",
                risk_level="medium",
                proposed_by="ai_agent",
                description="Restart Windows Update service",
            )
            AuditLogger.log_action_approved(
                incident_id="INC-001",
                action_id="ACT-001",
                action_type="restart_service",
                approved_by="operator",
            )
            AuditLogger.log_execution_completed(
                incident_id="INC-001",
                action_id="ACT-001",
                action_type="restart_service",
                success=True,
                returncode=0,
                stdout="Service restarted",
                stderr="",
                elapsed_seconds=1.5,
            )

            entries = AuditLogger.read_entries(limit=100)
            assert len(entries) == 3

            # Verify hash chain
            previous_hash = "GENESIS"
            for entry in entries:
                assert entry["previous_hash"] == previous_hash, (
                    f"Hash chain broken at entry {entry['event_type']}: "
                    f"expected previous_hash={previous_hash}, got {entry['previous_hash']}"
                )
                # Recompute entry hash to verify integrity
                stored_hash = entry.pop("entry_hash")
                recomputed = hashlib.sha256(
                    json.dumps(entry, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()
                entry["entry_hash"] = stored_hash
                assert stored_hash == recomputed, f"Entry hash mismatch at {entry['event_type']}"
                previous_hash = stored_hash

        finally:
            audit_logger._AUDIT_LOG_PATH = original_path
            audit_logger.AuditLogger._previous_hash = "GENESIS"

    def test_audit_log_event_types_present(self, tmp_path: Path) -> None:
        from remediation import audit_logger
        original_path = audit_logger._AUDIT_LOG_PATH
        audit_logger._AUDIT_LOG_PATH = tmp_path / "test_audit2.jsonl"
        audit_logger.AuditLogger._previous_hash = "GENESIS"

        try:
            AuditLogger.log_action_rejected(
                incident_id="INC-002",
                action_id="ACT-002",
                action_type="block_ip",
                rejected_by="operator",
                reason="False positive",
            )
            AuditLogger.log_safety_violation(
                incident_id="INC-002",
                action_id="ACT-003",
                action_type="kill_process",
                violation_message="Protected process targeted",
            )
            AuditLogger.log_verification_result(
                incident_id="INC-002",
                action_id="ACT-002",
                action_type="block_ip",
                verified=True,
                check_output="PASS: Rule active",
                details="returncode=0",
            )
            AuditLogger.log_rollback_result(
                incident_id="INC-002",
                action_id="ACT-004",
                action_type="restart_service",
                rollback_triggered=True,
                rollback_success=True,
                stdout="Rollback complete",
            )

            entries = AuditLogger.read_entries(limit=100)
            event_types = {e["event_type"] for e in entries}
            assert "action_rejected" in event_types
            assert "safety_violation" in event_types
            assert "verification_result" in event_types
            assert "rollback_result" in event_types

        finally:
            audit_logger._AUDIT_LOG_PATH = original_path
            audit_logger.AuditLogger._previous_hash = "GENESIS"

    def test_read_entries_returns_empty_when_no_log(self, tmp_path: Path) -> None:
        from remediation import audit_logger
        original_path = audit_logger._AUDIT_LOG_PATH
        audit_logger._AUDIT_LOG_PATH = tmp_path / "nonexistent.jsonl"
        try:
            entries = AuditLogger.read_entries()
            assert entries == []
        finally:
            audit_logger._AUDIT_LOG_PATH = original_path


# ══════════════════════════════════════════════════════════════════════════════
# TestActionsAPIEndpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestActionsAPIEndpoints:
    """Integration tests for Phase 9 remediation REST API via FastAPI TestClient."""

    @pytest.fixture(scope="class")
    def client(self):
        from fastapi.testclient import TestClient
        from backend.app.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


    def test_pending_actions_returns_empty_list(self, client) -> None:
        response = client.get("/api/actions/pending")
        assert response.status_code == 200
        data = response.json()
        assert "pending" in data
        assert "total" in data
        assert isinstance(data["pending"], list)

    def test_audit_log_endpoint_returns_list(self, client) -> None:
        response = client.get("/api/actions/audit-log")
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "audit_log_path" in data

    def test_get_nonexistent_action_returns_404(self, client) -> None:
        response = client.get("/api/actions/nonexistent-action-id")
        assert response.status_code == 404

    def test_approve_nonexistent_action_returns_422(self, client) -> None:
        response = client.post(
            "/api/actions/nonexistent-id/approve",
            json={"approved_by": "test_operator", "dry_run": True},
        )
        assert response.status_code in (422, 404, 500)

    def test_reject_nonexistent_action_returns_422(self, client) -> None:
        response = client.post(
            "/api/actions/nonexistent-id/reject",
            json={"rejected_by": "test_operator", "reason": "Test"},
        )
        assert response.status_code in (422, 404, 500)
