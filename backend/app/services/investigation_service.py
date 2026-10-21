"""
backend/app/services/investigation_service.py
=============================================
Application service orchestrating the multi-agent AI incident investigation:
- Fetches incident and anomaly records from SQLite
- Retrieves domain runbooks and knowledge from RAG
- Runs the LangGraph multi-agent workflow (Diagnosis -> Security -> Remediation)
- Updates SQLite with diagnoses, security risks, and proposed remediation actions
- Manages state machine lifecycle transitions (detected -> investigating -> awaiting_approval)
- Broadcasts real-time investigation updates via WebSocket
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from agents.graph import build_investigation_graph
from agents.schemas import InvestigationWorkflowState
from backend.app.api.ws import manager as ws_manager
from backend.app.services.rag_service import RAGService
from database.models import AnomalyRecord, Incident, RemediationActionRecord
from database.state_machine import IncidentStateMachine

logger = logging.getLogger("investigation.service")


class InvestigationService:
    """
    Coordinates multi-agent AI investigation for system incidents.
    """

    _instance: Optional[InvestigationService] = None

    def __init__(self, graph: Optional[Any] = None, rag_service: Optional[RAGService] = None) -> None:
        self.graph = graph or build_investigation_graph()
        self.rag_service = rag_service or RAGService.get_instance()

    @classmethod
    def get_instance(cls) -> InvestigationService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def investigate_incident(
        self,
        incident_id: str,
        db: AsyncSession,
        override_rag_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run end-to-end multi-agent investigation on an existing incident.
        """
        logger.info(f"Initiating multi-agent investigation for incident: {incident_id}")

        # 1. Fetch incident with associated anomaly records
        stmt = (
            select(Incident)
            .options(selectinload(Incident.anomalies))
            .where(Incident.id == incident_id)
        )
        result = await db.execute(stmt)
        incident = result.scalar_one_or_none()

        if not incident:
            raise ValueError(f"Incident with ID '{incident_id}' not found")

        # 2. Advance state machine to INVESTIGATING
        if incident.status == "detected":
            audit_entry = IncidentStateMachine.transition(
                incident=incident,
                target_status="investigating",
                actor="multi_agent_system",
                reason="Autonomous multi-agent investigation initiated",
            )
            db.add(audit_entry)
            await db.commit()
            await db.refresh(incident)

            await ws_manager.broadcast(
                "investigation_update",
                {
                    "incident_id": incident.id,
                    "status": "investigating",
                    "step": "investigation_started",
                    "message": "Diagnosis, Security, and Remediation agents dispatched",
                },
            )

        # 3. Gather top anomalous features from linked anomaly records
        top_features: List[str] = []
        telemetry_summary: Dict[str, Any] = {
            "severity": incident.severity,
            "anomaly_score": incident.anomaly_score,
            "source": incident.source,
        }

        if incident.anomalies:
            latest_anomaly = incident.anomalies[-1]
            if latest_anomaly.top_features:
                for item in latest_anomaly.top_features:
                    feature_name = item.get("feature") if isinstance(item, dict) else str(item)
                    if feature_name and feature_name not in top_features:
                        top_features.append(feature_name)
            if latest_anomaly.raw_features:
                telemetry_summary["sample_raw_features"] = {
                    k: round(v, 4) if isinstance(v, float) else v
                    for k, v in list(latest_anomaly.raw_features.items())[:10]
                }

        # 4. Retrieve RAG domain context
        if override_rag_context:
            rag_context = override_rag_context
        else:
            _, _, rag_context, _ = self.rag_service.get_incident_context(
                title=incident.title,
                description=incident.description,
                top_deviant_features=top_features,
                top_k=4,
            )

        # 5. Build initial state for LangGraph
        initial_state: InvestigationWorkflowState = {
            "incident_id": incident.id,
            "title": incident.title,
            "description": incident.description or "Automated incident anomaly detection",
            "severity": incident.severity,
            "anomaly_score": incident.anomaly_score,
            "top_deviant_features": top_features,
            "telemetry_summary": telemetry_summary,
            "rag_context": rag_context,
            "errors": [],
        }

        # 6. Execute LangGraph multi-agent pipeline
        logger.info("Executing LangGraph investigation graph...")
        final_state: Dict[str, Any] = await self.graph.ainvoke(initial_state)

        diagnosis_data = final_state.get("diagnosis")
        security_data = final_state.get("security_assessment")
        remediation_data = final_state.get("remediation")

        # 7. Persist findings to Incident
        if diagnosis_data:
            incident.diagnosis = diagnosis_data
            incident.root_cause = diagnosis_data.get("probable_root_cause")
            incident.confidence = diagnosis_data.get("confidence")

        if security_data:
            incident.security_assessment = security_data

        if remediation_data:
            proposed_actions_list = remediation_data.get("proposed_actions", [])
            incident.recommended_actions = [
                a.get("description", a.get("action_type", "Remediation Action"))
                for a in proposed_actions_list
            ]

            # Create individual RemediationActionRecord records
            for act in proposed_actions_list:
                action_record = RemediationActionRecord(
                    incident_id=incident.id,
                    action_type=act.get("action_type", "custom_action"),
                    description=act.get("description", "Remediation action proposed by agent"),
                    risk_level=act.get("risk_level", "low"),
                    status="proposed",
                    parameters=act.get("parameters", {}),
                    rollback_plan=act.get("rollback_plan", ""),
                    proposed_by="remediation_agent",
                )
                db.add(action_record)

        # 8. Advance state machine to AWAITING_APPROVAL
        if IncidentStateMachine.can_transition(incident.status, "awaiting_approval"):
            audit_entry = IncidentStateMachine.transition(
                incident=incident,
                target_status="awaiting_approval",
                actor="remediation_agent",
                reason="Remediation actions proposed; awaiting administrator approval",
            )
            db.add(audit_entry)

        await db.commit()
        await db.refresh(incident)

        # 9. Broadcast completion over WebSocket
        await ws_manager.broadcast(
            "investigation_update",
            {
                "incident_id": incident.id,
                "status": incident.status,
                "step": "investigation_completed",
                "root_cause": incident.root_cause,
                "confidence": incident.confidence,
                "actions_count": len(remediation_data.get("proposed_actions", [])) if remediation_data else 0,
            },
        )

        logger.info(
            f"Completed investigation for incident {incident.id}: "
            f"root_cause='{incident.root_cause}', status='{incident.status}'"
        )

        return {
            "incident_id": incident.id,
            "status": incident.status,
            "root_cause": incident.root_cause,
            "confidence": incident.confidence,
            "diagnosis": diagnosis_data,
            "security_assessment": security_data,
            "remediation": remediation_data,
            "errors": final_state.get("errors", []),
        }
