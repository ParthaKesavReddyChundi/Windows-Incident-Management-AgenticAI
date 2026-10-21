"""
agents/diagnosis_agent.py
=========================
Diagnosis Agent: Investigates Windows system incidents by synthesizing
telemetry anomalies, top deviant features from the PyTorch Autoencoder,
and domain knowledge retrieved from the RAG knowledge base.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from langchain_ollama import ChatOllama

from agents.llm_factory import get_chat_llm, invoke_structured_llm
from agents.schemas import DiagnosisAgentOutput

logger = logging.getLogger("agents.diagnosis")

DIAGNOSIS_SYSTEM_PROMPT = """You are an expert Windows Site Reliability Engineer and Systems Diagnostics AI Agent.
Your responsibility is to analyze Windows OS incident telemetry, deep learning reconstruction anomaly indicators,
and technical runbook context to identify the root cause of system disruptions.

Guidelines:
1. Rely on specific metrics (e.g. CPU %, Available RAM, Disk queue length, Network packets/sec, Event IDs).
2. Clearly distinguish between symptom (e.g. high CPU) and probable root cause (e.g. runaway thread loop, stuck WMI query, memory thrashing).
3. Assign a realistic confidence score (0.0 to 1.0) based strictly on evidence strength.
4. Specify affected OS subsystems accurately.
"""


class DiagnosisAgent:
    """
    Analyzes incident indicators and formulates a root cause diagnosis.
    """

    def __init__(self, llm: Optional[ChatOllama] = None) -> None:
        self.llm = llm or get_chat_llm(temperature=0.1)

    async def analyze(
        self,
        incident_title: str,
        description: str,
        severity: str,
        anomaly_score: float,
        top_deviant_features: List[str],
        telemetry_summary: Dict[str, Any],
        rag_context: str,
    ) -> DiagnosisAgentOutput:
        """Execute diagnostic root-cause analysis."""
        features_formatted = (
            ", ".join(top_deviant_features)
            if top_deviant_features
            else "None specified"
        )

        prompt = f"""### Incident Under Investigation
- **Title:** {incident_title}
- **Description:** {description}
- **Assigned Severity:** {severity}
- **Autoencoder Anomaly Score:** {anomaly_score:.6f}
- **Top Deviant Telemetry Features:** {features_formatted}

### Telemetry Summary Metrics
{telemetry_summary}

### Retrieved Technical Knowledge Context
{rag_context}

Analyze the incident and provide:
1. Probable root cause
2. Confidence score (0.0 to 1.0)
3. Affected subsystems
4. Supporting evidence list
5. In-depth technical analysis
6. Any uncertainty notes
"""
        logger.info(f"Running Diagnosis Agent for: '{incident_title}'")
        return await invoke_structured_llm(
            llm=self.llm,
            prompt=prompt,
            schema=DiagnosisAgentOutput,
            system_instruction=DIAGNOSIS_SYSTEM_PROMPT,
        )
