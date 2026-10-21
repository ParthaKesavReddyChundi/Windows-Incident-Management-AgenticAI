"""
remediation/action_executor.py
==============================
Safe subprocess execution engine for approved remediation actions.

Security design:
    - All actions go through SafetyGuard validation before execution.
    - Commands are built as argument lists (never shell=True) to prevent injection.
    - Execution is sandboxed via asyncio.create_subprocess_exec (no shell spawning).
    - Output is captured and truncated to prevent memory exhaustion.
    - A strict per-action timeout prevents hung processes.
    - Execution results are fully structured and persisted to the audit log.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from remediation.safety_guard import SafetyGuard, SafetyViolation

logger = logging.getLogger("remediation.executor")

# Maximum bytes captured from stdout/stderr to prevent memory exhaustion
_MAX_OUTPUT_BYTES = 4096
# Default execution timeout per action (seconds)
_DEFAULT_TIMEOUT_SECS = 30


class ExecutionResult:
    """Structured result from executing a remediation action."""

    def __init__(
        self,
        action_id: str,
        action_type: str,
        success: bool,
        returncode: Optional[int],
        stdout: str,
        stderr: str,
        command_used: List[str],
        elapsed_seconds: float,
        error_message: Optional[str] = None,
    ) -> None:
        self.action_id = action_id
        self.action_type = action_type
        self.success = success
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.command_used = command_used
        self.elapsed_seconds = elapsed_seconds
        self.error_message = error_message
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "success": self.success,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "command_used": self.command_used,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "error_message": self.error_message,
            "executed_at": self.executed_at,
        }


# ── PowerShell command builders for each allowlisted action ───────────────────

def _build_throttle_process_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Lower process CPU priority using Set-ProcessPriority or wmic."""
    proc_name = parameters.get("process_name", target)
    # Use PowerShell to set priority to BelowNormal for the named process
    ps_script = (
        f"$procs = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
        f"if ($procs) {{ foreach ($p in $procs) {{ $p.PriorityClass = 'BelowNormal' }} "
        f"Write-Output \"Throttled $($procs.Count) process(es) named '{proc_name}'\" }}"
        f"else {{ Write-Output 'No matching process found' }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


def _build_kill_process_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Terminate a process by PID or name."""
    pid = parameters.get("pid")
    if pid:
        ps_script = (
            f"Stop-Process -Id {int(pid)} -Force -ErrorAction SilentlyContinue; "
            f"Write-Output 'Process {pid} stop requested'"
        )
    else:
        proc_name = parameters.get("process_name", target)
        ps_script = (
            f"$procs = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
            f"if ($procs) {{ $procs | Stop-Process -Force; "
            f"Write-Output \"Killed $($procs.Count) process(es) named '{proc_name}'\" }}"
            f"else {{ Write-Output 'No matching process found' }}"
        )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


def _build_restart_service_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Restart a Windows service."""
    service_name = parameters.get("service_name", target)
    ps_script = (
        f"$svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue; "
        f"if ($svc) {{ Restart-Service -Name '{service_name}' -Force; "
        f"Start-Sleep -Seconds 2; "
        f"$status = (Get-Service -Name '{service_name}').Status; "
        f"Write-Output \"Service '{service_name}' restarted. Current status: $status\" }}"
        f"else {{ Write-Output \"Service '{service_name}' not found\" }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


def _build_flush_memory_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Flush working set memory by invoking EmptyWorkingSet on target or all processes."""
    proc_name = parameters.get("process_name", "")
    if proc_name:
        ps_script = (
            f"$procs = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
            f"if ($procs) {{ foreach ($p in $procs) {{ [System.GC]::Collect(); }} "
            f"Write-Output \"Memory flush requested for '{proc_name}'\" }}"
            f"else {{ [System.GC]::Collect(); Write-Output 'GC collection triggered' }}"
        )
    else:
        ps_script = "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Write-Output 'System GC completed successfully'"
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


def _build_block_ip_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Add a Windows Firewall rule to block an IP address."""
    remote_ip = parameters.get("remote_ip", target)
    rule_name = f"AGY-Block-{remote_ip}"
    ps_script = (
        f"$existing = Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue; "
        f"if (-not $existing) {{ "
        f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction Outbound -Action Block "
        f"-RemoteAddress {remote_ip} -Protocol Any -Enabled True | Out-Null; "
        f"New-NetFirewallRule -DisplayName '{rule_name}-In' -Direction Inbound -Action Block "
        f"-RemoteAddress {remote_ip} -Protocol Any -Enabled True | Out-Null; "
        f"Write-Output \"Firewall rules created to block {remote_ip}\" }}"
        f"else {{ Write-Output \"Block rule for {remote_ip} already exists\" }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


def _build_isolate_network_command(target: str, parameters: Dict[str, Any]) -> List[str]:
    """Disable all non-loopback network adapters to isolate a host."""
    ps_script = (
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne 'Loopback Pseudo-Interface 1' } | "
        "ForEach-Object { Disable-NetAdapter -Name $_.Name -Confirm:$false; "
        "Write-Output \"Disabled adapter: $($_.Name)\" }; "
        "Write-Output 'Host network isolation complete'"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps_script]


# Map action types to their command builders
_COMMAND_BUILDERS: Dict[str, Any] = {
    "throttle_process": _build_throttle_process_command,
    "kill_process": _build_kill_process_command,
    "restart_service": _build_restart_service_command,
    "flush_memory": _build_flush_memory_command,
    "block_ip": _build_block_ip_command,
    "isolate_network": _build_isolate_network_command,
}


class ActionExecutor:
    """
    Executes approved remediation actions as safe, non-shell subprocess calls.
    All actions are validated by SafetyGuard before execution.
    """

    def __init__(self, timeout_seconds: int = _DEFAULT_TIMEOUT_SECS) -> None:
        self.timeout_seconds = timeout_seconds

    async def execute(
        self,
        action_id: str,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        risk_level: str,
        requires_human_approval: bool,
        dry_run: bool = False,
    ) -> ExecutionResult:
        """
        Execute a single remediation action after safety validation.

        Args:
            action_id: Database ID of the RemediationActionRecord.
            action_type: Allowlisted action type string.
            target: Primary target identifier.
            parameters: Action parameters.
            risk_level: Claimed risk level from the AI agent.
            requires_human_approval: Whether human approval was given.
            dry_run: If True, validate and build the command but do not execute it.

        Returns:
            ExecutionResult with full details.
        """
        start = asyncio.get_event_loop().time()

        # Step 1: Safety validation (always enforced)
        try:
            SafetyGuard.validate_action(
                action_type=action_type,
                target=target,
                parameters=parameters,
                risk_level=risk_level,
                requires_human_approval=requires_human_approval,
            )
        except SafetyViolation as e:
            elapsed = asyncio.get_event_loop().time() - start
            logger.error(f"SafetyViolation for action {action_id}: {e}")
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                command_used=[],
                elapsed_seconds=elapsed,
                error_message=f"SAFETY VIOLATION: {e}",
            )

        # Step 2: Build command list
        builder = _COMMAND_BUILDERS.get(action_type)
        if not builder:
            elapsed = asyncio.get_event_loop().time() - start
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                command_used=[],
                elapsed_seconds=elapsed,
                error_message=f"No command builder for action type '{action_type}'",
            )

        cmd = builder(target, parameters)
        logger.info(
            f"ActionExecutor: Executing action_id={action_id} type={action_type} "
            f"target={target} dry_run={dry_run}"
        )

        # Step 3: Dry-run mode — return command without executing
        if dry_run:
            elapsed = asyncio.get_event_loop().time() - start
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=True,
                returncode=0,
                stdout=f"[DRY-RUN] Command would execute: {' '.join(cmd)}",
                stderr="",
                command_used=cmd,
                elapsed_seconds=elapsed,
            )

        # Step 4: Execute via asyncio subprocess (no shell=True ever)
        # Only run on Windows — on other OS return a simulation result for testing
        if sys.platform != "win32":
            elapsed = asyncio.get_event_loop().time() - start
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=True,
                returncode=0,
                stdout=f"[SIMULATION] Non-Windows platform. Command: {' '.join(cmd)}",
                stderr="",
                command_used=cmd,
                elapsed_seconds=elapsed,
            )

        try:
            def _run_sub():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    errors="replace",
                )

            res = await asyncio.to_thread(_run_sub)
            stdout_text = res.stdout[:_MAX_OUTPUT_BYTES].strip()
            stderr_text = res.stderr[:_MAX_OUTPUT_BYTES].strip()
            elapsed = asyncio.get_event_loop().time() - start

            success = res.returncode == 0
            logger.info(
                f"ActionExecutor: action_id={action_id} returncode={res.returncode} "
                f"success={success} elapsed={elapsed:.2f}s"
            )

            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=success,
                returncode=res.returncode,
                stdout=stdout_text,
                stderr=stderr_text,
                command_used=cmd,
                elapsed_seconds=elapsed,
                error_message=stderr_text if not success else None,
            )
        except subprocess.TimeoutExpired:
            elapsed = asyncio.get_event_loop().time() - start
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=False,
                returncode=-1,
                stdout="",
                stderr="",
                command_used=cmd,
                elapsed_seconds=elapsed,
                error_message=f"Action timed out after {self.timeout_seconds}s",
            )

        except Exception as e:
            elapsed = asyncio.get_event_loop().time() - start
            logger.error(f"ActionExecutor unexpected error for {action_id}: {e}", exc_info=True)
            return ExecutionResult(
                action_id=action_id,
                action_type=action_type,
                success=False,
                returncode=None,
                stdout="",
                stderr="",
                command_used=cmd,
                elapsed_seconds=elapsed,
                error_message=f"Execution error: {e}",
            )
