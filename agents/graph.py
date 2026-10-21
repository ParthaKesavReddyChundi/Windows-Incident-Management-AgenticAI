"""
agents/graph.py
===============
LangGraph orchestration graph connecting Diagnosis, Security, and Remediation
agents into a sequential, state-managed investigation pipeline.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agents.diagnosis_agent import DiagnosisAgent, DiagnosisAgentOutput
from agents.remediation_agent import RemediationAgent, RemediationAgentOutput
from agents.schemas import InvestigationWorkflowState, SecurityAgentOutput
from agents.security_agent import SecurityAgent

logger = logging.getLogger("agents.graph")


def build_investigation_graph(
    diagnosis_agent: Optional[DiagnosisAgent] = None,
    security_agent: Optional[SecurityAgent] = None,
    remediation_agent: Optional[RemediationAgent] = None,
) -> CompiledStateGraph:
    """
    Construct and compile the LangGraph incident investigation workflow.
    """
    diag_agent = diagnosis_agent or DiagnosisAgent()
    sec_agent = security_agent or SecurityAgent()
    rem_agent = remediation_agent or RemediationAgent()

    async def diagnose_node(state: InvestigationWorkflowState) -> Dict[str, Any]:
        """Diagnosis Agent execution node."""
        logger.info(f"LangGraph Node [diagnose] starting for incident {state.get('incident_id')}")
        try:
            diag_output = await diag_agent.analyze(
                incident_title=state.get("title", "Untitled Incident"),
                description=state.get("description", ""),
                severity=state.get("severity", "medium"),
                anomaly_score=state.get("anomaly_score", 0.0),
                top_deviant_features=state.get("top_deviant_features", []),
                telemetry_summary=state.get("telemetry_summary", {}),
                rag_context=state.get("rag_context", ""),
            )
            return {
                "diagnosis": diag_output.model_dump(),
                "current_step": "diagnosis_complete",
            }
        except Exception as e:
            logger.error(f"Error in diagnose_node: {e}", exc_info=True)
            errors = state.get("errors", []) + [f"Diagnosis error: {str(e)}"]
            return {"current_step": "diagnosis_failed", "errors": errors}

    async def security_node(state: InvestigationWorkflowState) -> Dict[str, Any]:
        """Security Agent execution node."""
        logger.info(f"LangGraph Node [security] starting for incident {state.get('incident_id')}")
        diag_raw = state.get("diagnosis")
        if not diag_raw:
            logger.warning("Skipping security node because diagnosis is missing")
            return {"current_step": "security_skipped"}

        try:
            diag_output = DiagnosisAgentOutput.model_validate(diag_raw)
            sec_output = await sec_agent.assess(
                incident_title=state.get("title", "Untitled Incident"),
                diagnosis=diag_output,
                top_deviant_features=state.get("top_deviant_features", []),
                telemetry_summary=state.get("telemetry_summary", {}),
                rag_context=state.get("rag_context", ""),
            )
            return {
                "security_assessment": sec_output.model_dump(),
                "current_step": "security_complete",
            }
        except Exception as e:
            logger.error(f"Error in security_node: {e}", exc_info=True)
            errors = state.get("errors", []) + [f"Security error: {str(e)}"]
            return {"current_step": "security_failed", "errors": errors}

    async def remediation_node(state: InvestigationWorkflowState) -> Dict[str, Any]:
        """Remediation Agent execution node."""
        logger.info(f"LangGraph Node [remediation] starting for incident {state.get('incident_id')}")
        diag_raw = state.get("diagnosis")
        sec_raw = state.get("security_assessment")

        if not diag_raw or not sec_raw:
            logger.warning("Skipping remediation node: missing prerequisite agent outputs")
            return {"current_step": "remediation_skipped"}

        try:
            diag_output = DiagnosisAgentOutput.model_validate(diag_raw)
            sec_output = SecurityAgentOutput.model_validate(sec_raw)

            rem_output = await rem_agent.propose(
                incident_title=state.get("title", "Untitled Incident"),
                diagnosis=diag_output,
                security=sec_output,
                top_deviant_features=state.get("top_deviant_features", []),
                rag_context=state.get("rag_context", ""),
            )
            return {
                "remediation": rem_output.model_dump(),
                "current_step": "investigation_complete",
            }
        except Exception as e:
            logger.error(f"Error in remediation_node: {e}", exc_info=True)
            errors = state.get("errors", []) + [f"Remediation error: {str(e)}"]
            return {"current_step": "remediation_failed", "errors": errors}

    # Construct the graph
    workflow = StateGraph(InvestigationWorkflowState)
    workflow.add_node("diagnose", diagnose_node)
    workflow.add_node("security", security_node)
    workflow.add_node("remediation", remediation_node)

    workflow.add_edge(START, "diagnose")
    workflow.add_edge("diagnose", "security")
    workflow.add_edge("security", "remediation")
    workflow.add_edge("remediation", END)

    compiled = workflow.compile()
    logger.info("Compiled LangGraph investigation workflow graph successfully")
    return compiled
