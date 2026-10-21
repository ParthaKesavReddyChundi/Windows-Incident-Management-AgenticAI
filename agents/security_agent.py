"""
agents/security_agent.py
========================
Security Agent: Evaluates system disruptions for cyber threats, malicious indicators,
and security policy violations, mapping anomalies to MITRE ATT&CK techniques.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from langchain_ollama import ChatOllama

from agents.diagnosis_agent import DiagnosisAgentOutput
from agents.llm_factory import get_chat_llm, invoke_structured_llm
from agents.schemas import SecurityAgentOutput

logger = logging.getLogger("agents.security")

SECURITY_SYSTEM_PROMPT = """You are an expert Windows Cybersecurity Analyst and Threat Intelligence AI Agent.
Your responsibility is to evaluate system incidents for security threats, classify potential attacks
(e.g. DoS, brute-force logon, ransomware/cryptominers, data exfiltration, or benign system glitch),
map suspicious behavior to standard MITRE ATT&CK Windows techniques, and determine if containment is needed.

Guidelines:
1. Distinguish between benign hardware/software failures and cyber threats.
2. If network traffic bursts outward or unknown processes spawn shells, evaluate MITRE T1071 (C2) or T1059 (Command Execution).
3. If thousands of failed logons or service halts occur, consider T1110 (Brute Force) or T1499 (Denial of Service).
4. Set containment_required=True ONLY if active exfiltration or severe threat requires isolating the host.
"""


class SecurityAgent:
    """
    Evaluates cybersecurity risk and threat indicators for an incident.
    """

    def __init__(self, llm: Optional[ChatOllama] = None) -> None:
        self.llm = llm or get_chat_llm(temperature=0.1)

    async def assess(
        self,
        incident_title: str,
        diagnosis: DiagnosisAgentOutput,
        top_deviant_features: List[str],
        telemetry_summary: Dict[str, Any],
        rag_context: str,
    ) -> SecurityAgentOutput:
        """Execute cybersecurity threat assessment."""
        features_formatted = (
            ", ".join(top_deviant_features)
            if top_deviant_features
            else "None specified"
        )

        prompt = f"""### Incident Under Security Evaluation
- **Title:** {incident_title}
- **Diagnosis Root Cause:** {diagnosis.probable_root_cause}
- **Diagnosis Technical Analysis:** {diagnosis.technical_analysis}
- **Affected Subsystems:** {', '.join(diagnosis.affected_subsystems)}
- **Top Deviant Features:** {features_formatted}

### Telemetry Summary Metrics
{telemetry_summary}

### Retrieved Knowledge & MITRE Reference Context
{rag_context}

Evaluate the incident for cyber risk:
1. Threat classification (e.g. benign_performance_spike, denial_of_service, malware_or_cryptominer, data_exfiltration)
2. Risk level (low, medium, high, critical)
3. Relevant MITRE ATT&CK technique IDs (e.g. ['T1059', 'T1499', 'T1071'])
4. Observable threat indicators list
5. Whether it is a confirmed security threat (True/False)
6. Whether immediate network/host containment is required (True/False)
7. Concise security summary
"""
        logger.info(f"Running Security Agent for: '{incident_title}'")
        return await invoke_structured_llm(
            llm=self.llm,
            prompt=prompt,
            schema=SecurityAgentOutput,
            system_instruction=SECURITY_SYSTEM_PROMPT,
        )
