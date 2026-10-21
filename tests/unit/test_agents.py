"""
tests/unit/test_agents.py
=========================
Unit and integration tests for Phase 7: Local Llama & Multi-Agent AI:
- Agent schemas and validation rules
- Diagnosis Agent root cause analysis
- Security Agent threat classification and MITRE ATT&CK mapping
- Remediation Agent allowlisted action proposal and rollback plans
- LangGraph orchestration graph execution
- Investigation Service persistence and state machine transitions
- FastAPI /api/incidents/{id}/investigate REST endpoints
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agents.diagnosis_agent import DiagnosisAgent
from agents.graph import build_investigation_graph
from agents.remediation_agent import RemediationAgent
from agents.schemas import (
    DiagnosisAgentOutput,
    InvestigationWorkflowState,
    RemediationActionProposal,
    RemediationAgentOutput,
    SecurityAgentOutput,
)
from agents.security_agent import SecurityAgent
from backend.app.main import app
from backend.app.schemas.incident import IncidentCreate, Severity
from backend.app.services.incident_service import IncidentService
from backend.app.services.investigation_service import InvestigationService
from database.session import async_session_factory


# ── 1. Schemas & Data Contracts ───────────────────────────────────────────────

class TestAgentSchemas:

    def test_diagnosis_agent_output_schema(self):
        output = DiagnosisAgentOutput(
            probable_root_cause="Runaway worker process infinite loop in telemetry_sim.exe",
            confidence=0.92,
            affected_subsystems=["CPU", "Process Management"],
            supporting_evidence=["cpu_percent at 99.4%", "Process PID 8412 consuming 100% of Core 1"],
            technical_analysis="The application thread entered an unyielding loop without sleeping.",
            uncertainty_notes="No handle leaks detected.",
        )
        assert output.confidence == 0.92
        assert len(output.affected_subsystems) == 2
        assert len(output.supporting_evidence) == 2
        assert "Runaway" in output.probable_root_cause

    def test_security_agent_output_schema(self):
        output = SecurityAgentOutput(
            threat_classification="denial_of_service",
            risk_level="high",
            mitre_techniques=["T1499", "T1498"],
            threat_indicators=["Extreme CPU saturation", "Unresponsive application thread"],
            is_confirmed_threat=True,
            containment_required=False,
            summary="Endpoint resource exhaustion DoS pattern detected.",
        )
        assert output.threat_classification == "denial_of_service"
        assert output.risk_level == "high"
        assert "T1499" in output.mitre_techniques
        assert output.is_confirmed_threat is True

    def test_remediation_proposal_schema(self):
        proposal = RemediationActionProposal(
            action_type="throttle_process",
            target="8412",
            parameters={"pid": 8412, "priority": "Idle"},
            description="Lower the CPU scheduling priority of PID 8412 to Idle",
            risk_level="low",
            command_template="Set-Process -Id 8412 -Priority Idle",
            expected_impact="Host CPU utilization drops below 25%",
            verification_step="Confirm Get-Process -Id 8412 PriorityClass is Idle",
            rollback_plan="Set-Process -Id 8412 -Priority Normal",
            requires_human_approval=False,
        )
        assert proposal.action_type == "throttle_process"
        assert proposal.target == "8412"
        assert "Idle" in proposal.command_template
        assert proposal.risk_level == "low"

    def test_remediation_agent_output_schema(self):
        proposal = RemediationActionProposal(
            action_type="kill_process",
            target="8412",
            parameters={"pid": 8412},
            description="Terminate unresponsive rogue worker process",
            risk_level="medium",
            command_template="Stop-Process -Id 8412 -Force",
            expected_impact="Process 8412 terminated; CPU restored to baseline",
            verification_step="Get-Process -Id 8412 returns null",
            rollback_plan="Restart worker service from clean binary",
            requires_human_approval=True,
        )
        output = RemediationAgentOutput(
            executive_summary="Mitigate CPU overload by killing rogue process 8412",
            proposed_actions=[proposal],
            estimated_resolution_time_sec=15,
        )
        assert len(output.proposed_actions) == 1
        assert output.estimated_resolution_time_sec == 15


# ── 2. Individual Agents Live Inference ───────────────────────────────────────

class TestIndividualAgents:

    @pytest.mark.asyncio
    async def test_diagnosis_agent_live(self):
        agent = DiagnosisAgent()
        result = await agent.analyze(
            incident_title="Severe CPU Spike on Core 0",
            description="Host processor usage surged to 99% with runaway thread execution.",
            severity="critical",
            anomaly_score=0.884,
            top_deviant_features=["cpu_percent", "System_Processor_Queue_Length"],
            telemetry_summary={"cpu_percent": 99.2, "memory_percent": 45.1},
            rag_context="### Troubleshooting Guide: Runaway Worker Processes\nSustained CPU usage above 90% indicates infinite loops or unthrottled worker threads.",
        )
        assert isinstance(result, DiagnosisAgentOutput)
        assert len(result.probable_root_cause) > 5
        assert 0.0 <= result.confidence <= 1.0
        assert len(result.technical_analysis) > 10

    @pytest.mark.asyncio
    async def test_security_agent_live(self):
        agent = SecurityAgent()
        diag = DiagnosisAgentOutput(
            probable_root_cause="Abnormal outbound data burst and high socket connection rate",
            confidence=0.85,
            affected_subsystems=["Network"],
            supporting_evidence=["bytes_sent_per_sec > 100MB/s"],
            technical_analysis="Massive egress traffic burst to external unlisted IP address.",
        )
        result = await agent.assess(
            incident_title="Suspicious Outbound Network Surge",
            diagnosis=diag,
            top_deviant_features=["network_bytes_sent_per_sec", "active_connections"],
            telemetry_summary={"bytes_sent_per_sec": 125000000},
            rag_context="### MITRE ATT&CK: Technique T1071 Exfiltration & C2\nAdversaries transmit stolen data over application protocols.",
        )
        assert isinstance(result, SecurityAgentOutput)
        assert len(result.threat_classification) > 2
        assert result.risk_level in ("low", "medium", "high", "critical")
        assert len(result.summary) > 5

    @pytest.mark.asyncio
    async def test_remediation_agent_live(self):
        agent = RemediationAgent()
        diag = DiagnosisAgentOutput(
            probable_root_cause="Runaway worker process PID 4920 consuming 98% CPU",
            confidence=0.90,
            affected_subsystems=["CPU"],
            supporting_evidence=["cpu_percent at 98%"],
            technical_analysis="Thread looping infinitely.",
        )
        sec = SecurityAgentOutput(
            threat_classification="benign_performance_spike",
            risk_level="medium",
            mitre_techniques=[],
            threat_indicators=["High CPU"],
            is_confirmed_threat=False,
            containment_required=False,
            summary="Resource exhaustion without malicious cyber indicators.",
        )
        result = await agent.propose(
            incident_title="High CPU Overload",
            diagnosis=diag,
            security=sec,
            top_deviant_features=["cpu_percent"],
            rag_context="### Runbook RB-01: Process CPU Throttling\nUse Set-Process -Id <PID> -Priority Idle to throttle without killing.",
        )
        assert isinstance(result, RemediationAgentOutput)
        assert len(result.proposed_actions) >= 1
        first_act = result.proposed_actions[0]
        assert first_act.action_type in (
            "throttle_process", "kill_process", "restart_service",
            "flush_memory", "block_ip", "isolate_network"
        )
        assert len(first_act.command_template) > 5
        assert len(first_act.rollback_plan) > 5


# ── 3. LangGraph Orchestration Pipeline ───────────────────────────────────────

class TestInvestigationGraph:

    @pytest.mark.asyncio
    async def test_langgraph_pipeline_execution(self):
        graph = build_investigation_graph()
        initial_state: InvestigationWorkflowState = {
            "incident_id": "test-inc-123",
            "title": "Windows Update Service Hang",
            "description": "wuauserv service halted unexpectedly with Event ID 7034.",
            "severity": "medium",
            "anomaly_score": 0.65,
            "top_deviant_features": ["service_status_wuauserv"],
            "telemetry_summary": {"stopped_services": ["wuauserv"]},
            "rag_context": "### Troubleshooting Guide: Service Crashes\nUse Start-Service or Restart-Service to restore stopped services.",
            "errors": [],
        }

        final_state = await graph.ainvoke(initial_state)

        assert final_state.get("current_step") == "investigation_complete"
        assert final_state.get("diagnosis") is not None
        assert final_state.get("security_assessment") is not None
        assert final_state.get("remediation") is not None

        diag = final_state["diagnosis"]
        assert "probable_root_cause" in diag
        assert diag["confidence"] > 0.0

        sec = final_state["security_assessment"]
        assert "threat_classification" in sec

        rem = final_state["remediation"]
        assert len(rem.get("proposed_actions", [])) >= 1


# ── 4. Investigation Service & Database Integration ──────────────────────────

class TestInvestigationService:

    @pytest.mark.asyncio
    async def test_investigate_incident_persists_to_db(self):
        async with async_session_factory() as session:
            # 1. Create a test incident
            incident = await IncidentService.create_incident(
                session=session,
                data=IncidentCreate(
                    title="Sudden Memory Exhaustion",
                    description="Available physical RAM plummeted to 120 MB with active pagefile thrashing.",
                    severity=Severity.HIGH,
                    source="simulated",
                    anomaly_score=0.912,
                ),
            )
            incident_id = incident.id
            assert incident.status == "detected"

            # 2. Run investigation
            service = InvestigationService.get_instance()
            result = await service.investigate_incident(incident_id=incident_id, db=session)

            assert result["incident_id"] == incident_id
            assert result["status"] == "awaiting_approval"
            assert result["root_cause"] is not None
            assert result["confidence"] is not None
            assert result["diagnosis"] is not None
            assert result["remediation"] is not None

            # 3. Reload from database and verify persistence
            reloaded = await IncidentService.get_incident(session, incident_id)
            assert reloaded is not None
            assert reloaded.status == "awaiting_approval"
            assert reloaded.root_cause == result["root_cause"]
            assert reloaded.confidence == result["confidence"]
            assert reloaded.diagnosis is not None
            assert len(reloaded.actions) >= 1

            first_action = reloaded.actions[0]
            assert first_action.status == "proposed"
            assert first_action.proposed_by == "remediation_agent"

            # 4. Verify audit log records
            audit_logs = await IncidentService.get_incident_audit_logs(session, incident_id)
            actions_recorded = [log.details.get("to_status") for log in audit_logs if log.details]
            assert "investigating" in actions_recorded
            assert "awaiting_approval" in actions_recorded


# ── 5. FastAPI Investigation REST Endpoints ───────────────────────────────────

class TestInvestigationAPIEndpoints:

    def test_post_investigate_endpoint(self):
        with TestClient(app) as client:
            # 1. Create an incident
            create_resp = client.post(
                "/api/incidents",
                json={
                    "title": "Disk Thrashing and Queue Bottleneck",
                    "description": "Physical disk queue length exceeded 8.0 with 250 MB/s write throughput.",
                    "severity": "high",
                    "source": "simulated",
                    "anomaly_score": 0.87,
                },
            )
            assert create_resp.status_code == 201
            incident_id = create_resp.json()["id"]

            # 2. Trigger multi-agent investigation
            inv_resp = client.post(f"/api/incidents/{incident_id}/investigate")
            assert inv_resp.status_code == 200
            data = inv_resp.json()

            assert data["incident_id"] == incident_id
            assert data["status"] == "awaiting_approval"
            assert data["root_cause"] is not None
            assert data["confidence"] > 0.0
            assert "diagnosis" in data
            assert "security_assessment" in data
            assert "remediation" in data

            # 3. Retrieve investigation report via GET
            get_resp = client.get(f"/api/incidents/{incident_id}/investigation")
            assert get_resp.status_code == 200
            inv_report = get_resp.json()
            assert inv_report["incident_id"] == incident_id
            assert inv_report["root_cause"] == data["root_cause"]
            assert len(inv_report["recommended_actions"]) >= 1

    def test_investigate_nonexistent_incident(self):
        with TestClient(app) as client:
            resp = client.post("/api/incidents/00000000-0000-0000-0000-000000000000/investigate")
            assert resp.status_code == 404
