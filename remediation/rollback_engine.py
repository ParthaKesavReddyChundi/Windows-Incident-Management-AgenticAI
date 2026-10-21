"""
remediation/rollback_engine.py
==============================
Automated rollback execution engine.

If the VerificationEngine determines that an action failed to resolve the
anomaly (or caused new issues), the RollbackEngine executes the action's
pre-defined rollback plan using safe subprocess calls.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("remediation.rollback")

_MAX_OUTPUT_BYTES = 4096
_ROLLBACK_TIMEOUT = 30  # seconds


class RollbackResult:
    """Result of a rollback operation."""

    def __init__(
        self,
        action_type: str,
        rollback_triggered: bool,
        success: bool,
        stdout: str,
        stderr: str,
        error_message: Optional[str] = None,
    ) -> None:
        self.action_type = action_type
        self.rollback_triggered = rollback_triggered
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "rollback_triggered": self.rollback_triggered,
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error_message": self.error_message,
        }


# ── Built-in rollback command builders ─────────────────────────────────────────

def _rollback_throttle_process(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Restore process priority to Normal."""
    proc_name = parameters.get("process_name", target)
    ps = (
        f"$procs = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
        f"if ($procs) {{ foreach ($p in $procs) {{ $p.PriorityClass = 'Normal' }} "
        f"Write-Output \"Priority restored to Normal for '{proc_name}'\" }}"
        f"else {{ Write-Output 'Process not running; no rollback needed' }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _rollback_kill_process(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Log that a kill cannot be rolled back automatically."""
    proc_name = parameters.get("process_name", target)
    ps = f"Write-Output 'ROLLBACK NOTE: Killed process {proc_name} cannot be automatically restarted. Manual operator action required.'"
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _rollback_restart_service(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Attempt to stop service that was restarted (if operator decides rollback)."""
    service_name = parameters.get("service_name", target)
    ps = (
        f"Stop-Service -Name '{service_name}' -Force -ErrorAction SilentlyContinue; "
        f"Write-Output \"Rollback: Stopped service '{service_name}'\""
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _rollback_flush_memory(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Memory flush has no meaningful rollback; log it."""
    ps = "Write-Output 'ROLLBACK: Memory flush is irreversible but harmless; no rollback required'"
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _rollback_block_ip(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Remove the firewall block rule."""
    remote_ip = parameters.get("remote_ip", target)
    rule_name = f"AGY-Block-{remote_ip}"
    ps = (
        f"Remove-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue; "
        f"Remove-NetFirewallRule -DisplayName '{rule_name}-In' -ErrorAction SilentlyContinue; "
        f"Write-Output \"Rollback: Removed firewall rules for {remote_ip}\""
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _rollback_isolate_network(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Re-enable all network adapters."""
    ps = (
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Disabled' } | "
        "ForEach-Object { Enable-NetAdapter -Name $_.Name -Confirm:$false; "
        "Write-Output \"Re-enabled adapter: $($_.Name)\" }; "
        "Write-Output 'Network isolation rollback complete'"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


_ROLLBACK_BUILDERS: Dict[str, Any] = {
    "throttle_process": _rollback_throttle_process,
    "kill_process": _rollback_kill_process,
    "restart_service": _rollback_restart_service,
    "flush_memory": _rollback_flush_memory,
    "block_ip": _rollback_block_ip,
    "isolate_network": _rollback_isolate_network,
}


class RollbackEngine:
    """
    Executes rollback plans when verification confirms an action failed or
    caused adverse effects. Also supports custom rollback plan strings from
    the AI agent.
    """

    async def execute_rollback(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        custom_rollback_plan: Optional[str] = None,
    ) -> RollbackResult:
        """
        Execute the rollback for a failed remediation action.

        Args:
            action_type: The type of action that failed.
            target: The primary target identifier.
            parameters: The action parameters.
            custom_rollback_plan: Optional human-readable rollback plan (logged only,
                                  not executed directly for safety).

        Returns:
            RollbackResult with execution details.
        """
        logger.warning(
            f"RollbackEngine: Triggering rollback for action_type={action_type} target={target}"
        )
        if custom_rollback_plan:
            logger.info(f"AI-proposed rollback plan: {custom_rollback_plan}")

        builder = _ROLLBACK_BUILDERS.get(action_type)
        if not builder:
            return RollbackResult(
                action_type=action_type,
                rollback_triggered=False,
                success=False,
                stdout="",
                stderr="",
                error_message=f"No rollback builder for action type '{action_type}'",
            )

        cmd = builder(target, parameters)

        # Non-Windows: simulate success
        if sys.platform != "win32":
            return RollbackResult(
                action_type=action_type,
                rollback_triggered=True,
                success=True,
                stdout=f"[SIMULATION] Rollback command: {' '.join(cmd)}",
                stderr="",
            )

        try:
            def _run_rollback():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_ROLLBACK_TIMEOUT,
                    errors="replace",
                )

            res = await asyncio.to_thread(_run_rollback)
            stdout = res.stdout[:_MAX_OUTPUT_BYTES].strip()
            stderr = res.stderr[:_MAX_OUTPUT_BYTES].strip()
            success = res.returncode == 0

            logger.info(
                f"RollbackEngine: action_type={action_type} success={success} output={stdout[:120]}"
            )
            return RollbackResult(
                action_type=action_type,
                rollback_triggered=True,
                success=success,
                stdout=stdout,
                stderr=stderr,
                error_message=stderr if not success else None,
            )
        except subprocess.TimeoutExpired:
            return RollbackResult(
                action_type=action_type,
                rollback_triggered=True,
                success=False,
                stdout="",
                stderr="",
                error_message=f"Rollback timed out after {_ROLLBACK_TIMEOUT}s",
            )

        except Exception as e:
            logger.error(f"RollbackEngine error for {action_type}: {e}", exc_info=True)
            return RollbackResult(
                action_type=action_type,
                rollback_triggered=True,
                success=False,
                stdout="",
                stderr="",
                error_message=f"Rollback exception: {e}",
            )
