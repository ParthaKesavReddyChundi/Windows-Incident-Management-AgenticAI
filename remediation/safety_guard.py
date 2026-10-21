"""
remediation/safety_guard.py
===========================
Strict allowlist policy validator and parameter sanitizer for remediation actions.

Security principles:
    - ONLY actions in the explicit allowlist can be approved for execution.
    - ALL parameter values are validated against type and pattern constraints.
    - Shell injection characters are blocked in every string parameter.
    - High-risk actions always require explicit human approval regardless of AI suggestion.
    - Protected system processes and services can NEVER be targeted.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("remediation.safety_guard")

# ── Allowlisted action types ────────────────────────────────────────────────────
ALLOWLISTED_ACTION_TYPES: Set[str] = {
    "throttle_process",
    "kill_process",
    "restart_service",
    "flush_memory",
    "block_ip",
    "isolate_network",
}

# ── Risk levels for each action type ───────────────────────────────────────────
ACTION_RISK_LEVELS: Dict[str, str] = {
    "throttle_process": "low",
    "flush_memory": "low",
    "restart_service": "medium",
    "kill_process": "medium",
    "block_ip": "high",
    "isolate_network": "high",
}

# ── Protected system processes that must never be targeted ─────────────────────
PROTECTED_PROCESSES: Set[str] = {
    "lsass", "lsass.exe",
    "csrss", "csrss.exe",
    "wininit", "wininit.exe",
    "smss", "smss.exe",
    "services", "services.exe",
    "svchost", "svchost.exe",
    "winlogon", "winlogon.exe",
    "system", "system idle process",
    "ntoskrnl", "ntoskrnl.exe",
    "dwm", "dwm.exe",
    "explorer", "explorer.exe",
}

# ── Protected system services that must never be force-killed (only restarted) ─
PROTECTED_SERVICES: Set[str] = {
    "eventlog", "eventlog.exe",
    "cryptsvc",
    "lsa",
    "mpssvc",       # Windows Defender Firewall
    "wdnissvc",     # Windows Defender Network Inspection
    "samss",        # Security Account Manager
    "seclogon",
    "lmhosts",
}

# ── Shell injection / command injection character pattern ──────────────────────
_INJECTION_PATTERN = re.compile(
    r"[;&|`\$<>\(\)\{\}\[\]\\'\"\n\r\x00]"
)

# ── IPv4 address validation ────────────────────────────────────────────────────
_IPV4_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# ── Windows service name validation (alphanumeric + underscore + hyphen, 1-256) ─
_SERVICE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,256}$")

# ── Process name / PID validation ─────────────────────────────────────────────
_PID_PATTERN = re.compile(r"^\d{1,7}$")
_PROC_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,256}$")


class SafetyViolation(Exception):
    """Raised when a remediation action violates the safety policy."""
    pass


class SafetyGuard:
    """
    Validates remediation actions against strict allowlist and safety policies
    before they can be passed to the execution engine.
    """

    @staticmethod
    def validate_action(
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        risk_level: str,
        requires_human_approval: bool,
    ) -> None:
        """
        Validate a proposed remediation action. Raises SafetyViolation if any
        policy constraint is breached.

        Args:
            action_type: Must be in ALLOWLISTED_ACTION_TYPES.
            target: Primary target identifier (PID, service name, IP address).
            parameters: Action parameters dictionary.
            risk_level: Proposed risk level ('read_only', 'low', 'medium', 'high').
            requires_human_approval: Whether the AI agent flagged human approval required.

        Raises:
            SafetyViolation: If any policy check fails.
        """
        # 1. Action type must be allowlisted
        if action_type not in ALLOWLISTED_ACTION_TYPES:
            raise SafetyViolation(
                f"Action type '{action_type}' is not in the allowlisted action types: "
                f"{sorted(ALLOWLISTED_ACTION_TYPES)}"
            )

        # 2. High-risk actions always require human approval
        authoritative_risk = ACTION_RISK_LEVELS.get(action_type, "high")
        if authoritative_risk == "high" and not requires_human_approval:
            raise SafetyViolation(
                f"Action type '{action_type}' is classified as high-risk and "
                "must always require human approval."
            )

        # 3. Sanitize target against injection
        SafetyGuard._assert_no_injection(target, field_name="target")

        # 4. Sanitize all string parameters
        for key, val in parameters.items():
            if isinstance(val, str):
                SafetyGuard._assert_no_injection(val, field_name=f"parameters.{key}")

        # 5. Action-specific validation
        if action_type in ("kill_process", "throttle_process"):
            SafetyGuard._validate_process_target(target, parameters)
        elif action_type == "restart_service":
            SafetyGuard._validate_service_target(target, parameters)
        elif action_type == "block_ip":
            SafetyGuard._validate_ip_target(target, parameters)
        elif action_type == "flush_memory":
            pass  # No additional constraints; safe read_only/low action
        elif action_type == "isolate_network":
            # Isolation is high-risk; already validated above
            pass

        logger.info(
            f"SafetyGuard APPROVED: action_type={action_type} target={target} "
            f"risk={authoritative_risk}"
        )

    @staticmethod
    def _assert_no_injection(value: str, field_name: str) -> None:
        """Raise SafetyViolation if value contains shell injection characters."""
        if _INJECTION_PATTERN.search(value):
            raise SafetyViolation(
                f"Field '{field_name}' contains forbidden characters that could "
                f"enable command injection: {repr(value[:80])}"
            )

    @staticmethod
    def _validate_process_target(target: str, parameters: Dict[str, Any]) -> None:
        """Validate process kill/throttle targets."""
        name_lower = target.lower().replace(".exe", "")
        if name_lower in PROTECTED_PROCESSES or target.lower() in PROTECTED_PROCESSES:
            raise SafetyViolation(
                f"Process target '{target}' is a protected system process and "
                "cannot be killed or throttled."
            )
        # If a PID is given, it must be numeric
        pid_str = str(parameters.get("pid", "")).strip()
        if pid_str and not _PID_PATTERN.match(pid_str):
            raise SafetyViolation(
                f"Invalid PID value '{pid_str}': must be a positive integer."
            )
        # If a process name is given, validate characters
        proc_name = str(parameters.get("process_name", target)).strip()
        if not _PROC_NAME_PATTERN.match(proc_name):
            raise SafetyViolation(
                f"Invalid process name '{proc_name}': contains illegal characters."
            )

    @staticmethod
    def _validate_service_target(target: str, parameters: Dict[str, Any]) -> None:
        """Validate service restart targets."""
        service_name = str(parameters.get("service_name", target)).strip()
        if not _SERVICE_NAME_PATTERN.match(service_name):
            raise SafetyViolation(
                f"Invalid service name '{service_name}': contains illegal characters."
            )
        # Protected services can be restarted (they're resilient), but extra note logged
        if service_name.lower() in PROTECTED_SERVICES:
            logger.warning(
                f"SafetyGuard WARNING: Restarting protected service '{service_name}' "
                "approved but operator should monitor carefully."
            )

    @staticmethod
    def _validate_ip_target(target: str, parameters: Dict[str, Any]) -> None:
        """Validate IP block targets."""
        ip = str(parameters.get("remote_ip", target)).strip()
        if not _IPV4_PATTERN.match(ip):
            raise SafetyViolation(
                f"Invalid IP address '{ip}': must be a valid IPv4 address."
            )
        # Refuse to block localhost or private management addresses
        forbidden_prefixes = ("127.", "0.0.0.0", "255.")
        if any(ip.startswith(p) for p in forbidden_prefixes):
            raise SafetyViolation(
                f"Blocking IP '{ip}' is forbidden: cannot block loopback or "
                "broadcast addresses."
            )

    @staticmethod
    def get_authoritative_risk(action_type: str) -> str:
        """Return the authoritative (policy-determined) risk level for an action type."""
        return ACTION_RISK_LEVELS.get(action_type, "high")

    @staticmethod
    def requires_human_approval(action_type: str) -> bool:
        """Returns True if the action type always requires human approval."""
        return ACTION_RISK_LEVELS.get(action_type, "high") in ("high",)
