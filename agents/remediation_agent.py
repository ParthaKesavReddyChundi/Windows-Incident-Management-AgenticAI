"""
agents/remediation_agent.py
===========================
Remediation Agent: Formulates controlled, allowlisted mitigation plans
with step-by-step verification checks and rollback procedures, adhering strictly
to safety policies and human-in-the-loop approval requirements.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from langchain_ollama import ChatOllama

from agents.diagnosis_agent import DiagnosisAgentOutput
from agents.llm_factory import get_chat_llm, invoke_structured_llm
from agents.schemas import RemediationActionProposal, RemediationAgentOutput, SecurityAgentOutput


logger = logging.getLogger("agents.remediation")

REMEDIATION_SYSTEM_PROMPT = """You are an expert Windows Site Reliability Engineer and Autonomous Remediation AI Agent.
Your responsibility is to synthesize the incident root-cause diagnosis, security risk evaluation,
and retrieved technical runbooks to formulate safe, effective, allowlisted remediation actions.

Strict Safety Rules:
1. ONLY propose actions conforming to allowlisted types:
   - 'throttle_process': Lower priority or set core affinity for runaway user processes.
   - 'kill_process': Terminate non-critical hung or rogue processes. Never target core OS processes (lsass, csrss, wininit).
   - 'restart_service': Restart stopped or crashed Windows services.
   - 'flush_memory': Call working set trimming / cache clearing.
   - 'block_ip': Firewall rule blocking malicious external IP.
   - 'isolate_network': Host network containment rule for severe security compromise.
2. Every action MUST include:
   - risk_level ('read_only', 'low', 'medium', 'high')
   - verification_step (how to confirm resolution)
   - rollback_plan (exact steps to undo if side effects occur)
   - requires_human_approval (True by default for medium/high risk)
"""


class RemediationAgent:
    """
    Formulates safe, allowlisted remediation proposals with rollback plans.
    """

    def __init__(self, llm: Optional[ChatOllama] = None) -> None:
        self.llm = llm or get_chat_llm(temperature=0.1)

    async def propose(
        self,
        incident_title: str,
        diagnosis: DiagnosisAgentOutput,
        security: SecurityAgentOutput,
        top_deviant_features: List[str],
        rag_context: str,
    ) -> RemediationAgentOutput:
        """Formulate remediation action plan."""
        features_formatted = (
            ", ".join(top_deviant_features)
            if top_deviant_features
            else "None specified"
        )

        prompt = f"""### Incident Context for Remediation
- **Title:** {incident_title}
- **Diagnosed Root Cause:** {diagnosis.probable_root_cause}
- **Affected Subsystems:** {', '.join(diagnosis.affected_subsystems)}
- **Security Classification:** {security.threat_classification} (Risk: {security.risk_level})
- **Containment Required:** {security.containment_required}
- **Top Deviant Features:** {features_formatted}

### Technical Runbooks & Reference Knowledge Context
{rag_context}

Formulate a safe, targeted remediation plan:
1. Executive summary of the remediation plan
2. Ordered list of proposed actions (using allowlisted action types: throttle_process, kill_process, restart_service, flush_memory, block_ip, isolate_network)
   For each action provide:
   - action_type
   - target
   - parameters
   - description
   - risk_level (read_only, low, medium, high)
   - command_template (valid PowerShell command string)
   - expected_impact
   - verification_step
   - rollback_plan
   - requires_human_approval (True/False)
3. Estimated resolution time in seconds
"""
        logger.info(f"Running Remediation Agent for: '{incident_title}'")
        result = await invoke_structured_llm(
            llm=self.llm,
            prompt=prompt,
            schema=RemediationAgentOutput,
            system_instruction=REMEDIATION_SYSTEM_PROMPT,
        )

        if not result.proposed_actions:
            logger.warning("Remediation Agent produced 0 actions; generating rule-guided fallback action")
            fallback = self._create_fallback_action(
                incident_title=incident_title,
                diagnosis=diagnosis,
                security=security,
            )
            result.proposed_actions.append(fallback)

        for act in result.proposed_actions:
            if act.action_type == "block_ip":
                if not act.parameters.get("remote_ip"):
                    act.parameters["remote_ip"] = "203.0.113.199"
                act.target = act.parameters["remote_ip"]
            elif act.action_type == "restart_service":
                if not act.parameters.get("service_name"):
                    act.parameters["service_name"] = act.target or "wuauserv"
            elif act.action_type == "flush_memory":
                act.target = act.target or "system"

        return result

    def _create_fallback_action(
        self,
        incident_title: str,
        diagnosis: DiagnosisAgentOutput,
        security: SecurityAgentOutput,
    ) -> RemediationActionProposal:
        """Create a targeted allowlisted fallback action matching diagnosed subsystems."""
        title_lower = incident_title.lower()
        subsystems = [s.lower() for s in diagnosis.affected_subsystems]

        if "service" in title_lower or any("service" in s for s in subsystems):
            return RemediationActionProposal(
                action_type="restart_service",
                target="wuauserv",
                parameters={"service_name": "wuauserv"},
                description=f"Restart Windows service to recover from disruption: {diagnosis.probable_root_cause}",
                risk_level="low",
                command_template="Restart-Service -Name wuauserv -Force",
                expected_impact="Service transitions to Running state",
                verification_step="(Get-Service -Name wuauserv).Status -eq 'Running'",
                rollback_plan="Start-Service -Name wuauserv",
                requires_human_approval=False,
            )
        elif "network" in title_lower or security.containment_required or any("net" in s for s in subsystems):
            return RemediationActionProposal(
                action_type="block_ip",
                target="suspicious_remote_ip",
                parameters={"remote_ip": "192.168.1.100"},
                description="Block suspicious external network traffic to prevent exfiltration",
                risk_level="low",
                command_template="New-NetFirewallRule -DisplayName 'Block-Suspicious-IP' -Direction Outbound -Action Block",
                expected_impact="Outbound transmission rate normalizes",
                verification_step="Get-NetFirewallRule -DisplayName 'Block-Suspicious-IP'",
                rollback_plan="Remove-NetFirewallRule -DisplayName 'Block-Suspicious-IP'",
                requires_human_approval=True,
            )
        elif "memory" in title_lower or any("mem" in s for s in subsystems):
            return RemediationActionProposal(
                action_type="flush_memory",
                target="system",
                parameters={},
                description="Trim process working sets and reclaim unreferenced memory",
                risk_level="read_only",
                command_template="[System.GC]::Collect()",
                expected_impact="Available memory increases by >100 MB",
                verification_step="(Get-Counter '\\Memory\\Available MBytes').CounterSamples[0].CookedValue -gt 500",
                rollback_plan="None required (read-only safe memory trim)",
                requires_human_approval=False,
            )
        else:
            return RemediationActionProposal(
                action_type="throttle_process",
                target="worker_process",
                parameters={"priority": "Idle"},
                description=f"Throttle process priority to relieve resource contention: {diagnosis.probable_root_cause}",
                risk_level="low",
                command_template="Set-Process -Name telemetry_worker -Priority Idle",
                expected_impact="Processor utilization drops below warning threshold",
                verification_step="(Get-Process -Name telemetry_worker).PriorityClass -eq 'Idle'",
                rollback_plan="Set-Process -Name telemetry_worker -Priority Normal",
                requires_human_approval=False,
            )
