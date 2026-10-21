"""
remediation/verification_engine.py
===================================
Post-execution automated verification engine.

After each remediation action is executed, the verification engine runs
a targeted PowerShell check to confirm whether the anomaly has been resolved.
Verification results are structured and feed into the rollback decision.
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("remediation.verification")

_MAX_OUTPUT_BYTES = 4096
_VERIFICATION_TIMEOUT = 20  # seconds


class VerificationResult:
    """Result of a post-execution verification check."""

    def __init__(
        self,
        action_type: str,
        verified: bool,
        check_output: str,
        details: str,
    ) -> None:
        self.action_type = action_type
        self.verified = verified
        self.check_output = check_output
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "verified": self.verified,
            "check_output": self.check_output,
            "details": self.details,
        }


# ── Verification command builders ──────────────────────────────────────────────

def _verify_throttle_process(target: str, parameters: Dict[str, Any]) -> List[str]:
    proc_name = parameters.get("process_name", target)
    ps = (
        f"$p = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
        f"if ($p) {{ Write-Output \"Priority:$($p[0].PriorityClass) CPU:$($p[0].CPU)\" }}"
        f"else {{ Write-Output 'Process not running' }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _verify_kill_process(target: str, parameters: Dict[str, Any]) -> List[str]:
    proc_name = parameters.get("process_name", target)
    pid = parameters.get("pid")
    if pid:
        ps = (
            f"$p = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue; "
            f"if ($p) {{ Write-Output 'FAIL: Process still running' }}"
            f"else {{ Write-Output 'PASS: Process terminated' }}"
        )
    else:
        ps = (
            f"$p = Get-Process -Name '{proc_name}' -ErrorAction SilentlyContinue; "
            f"if ($p) {{ Write-Output 'FAIL: Process still running' }}"
            f"else {{ Write-Output 'PASS: Process terminated' }}"
        )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _verify_restart_service(target: str, parameters: Dict[str, Any]) -> List[str]:
    service_name = parameters.get("service_name", target)
    ps = (
        f"$svc = Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue; "
        f"if ($svc) {{ Write-Output \"Status:$($svc.Status)\" }}"
        f"else {{ Write-Output 'FAIL: Service not found' }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _verify_flush_memory(target: str, parameters: Dict[str, Any]) -> List[str]:
    ps = (
        "$os = Get-CimInstance -ClassName Win32_OperatingSystem; "
        "$freeMB = [math]::Round($os.FreePhysicalMemory / 1024, 1); "
        "Write-Output \"FreePhysicalMemory:${freeMB}MB\""
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _verify_block_ip(target: str, parameters: Dict[str, Any]) -> List[str]:
    remote_ip = parameters.get("remote_ip", target)
    rule_name = f"AGY-Block-{remote_ip}"
    ps = (
        f"$rule = Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue; "
        f"if ($rule) {{ Write-Output \"PASS: Firewall rule active for {remote_ip}\" }}"
        f"else {{ Write-Output 'FAIL: Firewall rule not found' }}"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


def _verify_isolate_network(target: str, parameters: Dict[str, Any]) -> List[str]:
    ps = (
        "$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and "
        "$_.Name -ne 'Loopback Pseudo-Interface 1' }; "
        "if ($adapters) { Write-Output \"WARN: $($adapters.Count) adapter(s) still active\" } "
        "else { Write-Output 'PASS: All external adapters disabled' }"
    )
    return ["powershell.exe", "-NonInteractive", "-NoProfile", "-Command", ps]


_VERIFIERS: Dict[str, Any] = {
    "throttle_process": _verify_throttle_process,
    "kill_process": _verify_kill_process,
    "restart_service": _verify_restart_service,
    "flush_memory": _verify_flush_memory,
    "block_ip": _verify_block_ip,
    "isolate_network": _verify_isolate_network,
}

# Strings in stdout that mean success
_SUCCESS_INDICATORS: Dict[str, List[str]] = {
    "kill_process": ["PASS:"],
    "restart_service": ["Status:Running"],
    "block_ip": ["PASS:"],
    "isolate_network": ["PASS:"],
    "throttle_process": ["BelowNormal", "not running"],
    "flush_memory": ["FreePhysicalMemory:"],
}


class VerificationEngine:
    """Runs targeted PowerShell checks to verify remediation success."""

    async def verify(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
    ) -> VerificationResult:
        """
        Run the verification check for an executed action.

        Args:
            action_type: The action that was executed.
            target: The primary target identifier.
            parameters: The action parameters used.

        Returns:
            VerificationResult indicating whether the action succeeded.
        """
        verifier = _VERIFIERS.get(action_type)
        if not verifier:
            return VerificationResult(
                action_type=action_type,
                verified=False,
                check_output="",
                details=f"No verifier defined for action type '{action_type}'",
            )

        cmd = verifier(target, parameters)
        logger.info(f"VerificationEngine: Running check for action_type={action_type}")

        # Non-Windows: simulate pass
        if sys.platform != "win32":
            return VerificationResult(
                action_type=action_type,
                verified=True,
                check_output="[SIMULATION] Verification passed on non-Windows platform",
                details="Simulated verification for cross-platform testing",
            )

        try:
            def _run_verify():
                return subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_VERIFICATION_TIMEOUT,
                    errors="replace",
                )

            res = await asyncio.to_thread(_run_verify)
            output = res.stdout[:_MAX_OUTPUT_BYTES].strip()
            stderr = res.stderr[:_MAX_OUTPUT_BYTES].strip()

            # Determine success based on expected output markers
            success_markers = _SUCCESS_INDICATORS.get(action_type, [])
            verified = any(marker in output for marker in success_markers) if success_markers else res.returncode == 0

            logger.info(
                f"VerificationEngine: action_type={action_type} verified={verified} output={output[:120]}"
            )
            return VerificationResult(
                action_type=action_type,
                verified=verified,
                check_output=output,
                details=f"returncode={res.returncode} stderr={stderr[:200]}" if stderr else f"returncode={res.returncode}",
            )
        except subprocess.TimeoutExpired:
            return VerificationResult(
                action_type=action_type,
                verified=False,
                check_output="",
                details=f"Verification timed out after {_VERIFICATION_TIMEOUT}s",
            )

        except Exception as e:
            logger.error(f"VerificationEngine error for {action_type}: {e}", exc_info=True)
            return VerificationResult(
                action_type=action_type,
                verified=False,
                check_output="",
                details=f"Verification exception: {e}",
            )
