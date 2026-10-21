"""
tests/unit/test_incidents.py
============================
Unit tests for Phase 5: Database & Incident Management.

Tests:
1. SQLAlchemy Models & Relationships (Cascades, JSON columns, Timestamps)
2. State Machine Lifecycle (Allowed, Disallowed, Audit generation)
3. Incident Service & Correlation Engine (Deduplication, Severity Elevation, Sliding Window)
4. Incident REST API Endpoints (CRUD, Filtering, Pagination, Status Transitions)
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.app.schemas.incident import (
    IncidentCreate,
    IncidentStatus,
    RemediationActionCreate,
    RiskLevel,
    Severity,
)
from backend.app.services.incident_service import IncidentService
from database.models import (
    AnomalyRecord,
    AuditLogRecord,
    Base,
    Incident,
    RemediationActionRecord,
)
from database.state_machine import IncidentStateMachine, InvalidStateTransitionError


# ── Test Database Fixtures (In-Memory SQLite) ─────────────────────────────────

@pytest_asyncio.fixture()
async def test_engine():
    """Create a pristine in-memory SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture()
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an active AsyncSession backed by the in-memory test engine."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        yield session


# ===========================================================================
# 1. Database Models & Relationships
# ===========================================================================

class TestIncidentModels:
    """Tests for SQLAlchemy ORM models and relationships."""

    @pytest.mark.asyncio
    async def test_create_incident_with_children(self, test_session: AsyncSession) -> None:
        now = datetime.now(timezone.utc)
        incident = Incident(
            title="High CPU Incident",
            description="CPU load at 98%",
            severity="high",
            status="detected",
            source="live",
            anomaly_score=0.88,
        )
        test_session.add(incident)
        await test_session.flush()

        # Add child anomaly
        anomaly = AnomalyRecord(
            incident_id=incident.id,
            timestamp=now,
            score=0.88,
            threshold=0.05,
            severity="high",
            is_anomaly=True,
            top_features=[{"feature": "cpu_util", "squared_error": 0.45, "raw_value": 98.0}],
        )
        # Add child remediation action
        action = RemediationActionRecord(
            incident_id=incident.id,
            action_type="restart_service",
            description="Restart print spooler",
            risk_level="low",
            status="proposed",
        )
        # Add audit log
        audit = AuditLogRecord(
            incident_id=incident.id,
            timestamp=now,
            actor="system",
            action="incident_created",
            details={"score": 0.88},
        )
        test_session.add_all([anomaly, action, audit])
        await test_session.commit()

        # Reload and verify relationships
        fetched = await IncidentService.get_incident(test_session, incident.id, include_children=True)
        assert fetched is not None
        assert fetched.title == "High CPU Incident"
        assert len(fetched.anomalies) == 1
        assert fetched.anomalies[0].score == 0.88
        assert len(fetched.actions) == 1
        assert fetched.actions[0].action_type == "restart_service"
        assert len(fetched.audit_logs) == 1
        assert fetched.audit_logs[0].action == "incident_created"

    @pytest.mark.asyncio
    async def test_cascade_delete(self, test_session: AsyncSession) -> None:
        """Deleting an incident should cascade delete its anomalies and actions."""
        incident = Incident(title="Temporary Incident", severity="low")
        test_session.add(incident)
        await test_session.flush()

        anomaly = AnomalyRecord(
            incident_id=incident.id, score=0.5, threshold=0.1, severity="low", is_anomaly=True
        )
        test_session.add(anomaly)
        await test_session.commit()

        # Delete incident
        await test_session.delete(incident)
        await test_session.commit()

        # Verify child anomaly is deleted
        fetched_anom = await IncidentService.get_incident_anomalies(test_session, incident.id)
        assert len(fetched_anom) == 0


# ===========================================================================
# 2. State Machine Lifecycle
# ===========================================================================

class TestIncidentStateMachine:
    """Tests for IncidentStateMachine transition validation and audit logging."""

    def test_allowed_transitions(self) -> None:
        assert IncidentStateMachine.can_transition("detected", "investigating") is True
        assert IncidentStateMachine.can_transition("detected", "dismissed") is True
        assert IncidentStateMachine.can_transition("investigating", "awaiting_approval") is True
        assert IncidentStateMachine.can_transition("awaiting_approval", "remediating") is True
        assert IncidentStateMachine.can_transition("remediating", "mitigated") is True
        assert IncidentStateMachine.can_transition("mitigated", "resolved") is True
        assert IncidentStateMachine.can_transition("resolved", "investigating") is True

    def test_disallowed_transitions(self) -> None:
        assert IncidentStateMachine.can_transition("detected", "resolved") is False
        assert IncidentStateMachine.can_transition("detected", "remediating") is False
        assert IncidentStateMachine.can_transition("mitigated", "awaiting_approval") is False

        with pytest.raises(InvalidStateTransitionError) as exc_info:
            IncidentStateMachine.validate_transition("detected", "resolved")
        assert "Invalid incident state transition" in str(exc_info.value)

    def test_state_transition_updates_fields(self) -> None:
        incident = Incident(id="test-inc-01", title="Test", status="detected")
        audit = IncidentStateMachine.transition(
            incident=incident,
            target_status="investigating",
            actor="agent_rca",
            reason="High CPU pattern confirmed",
        )
        assert incident.status == "investigating"
        assert audit.action == "state_transition"
        assert audit.details["from_status"] == "detected"
        assert audit.details["to_status"] == "investigating"
        assert audit.actor == "agent_rca"

    def test_resolution_sets_resolved_at(self) -> None:
        incident = Incident(id="test-inc-02", title="Test", status="mitigated")
        assert incident.resolved_at is None

        IncidentStateMachine.transition(incident, "resolved", actor="human_admin")
        assert incident.status == "resolved"
        assert incident.resolved_at is not None

        # Reopen
        IncidentStateMachine.transition(incident, "investigating", actor="human_admin")
        assert incident.status == "investigating"
        assert incident.resolved_at is None


# ===========================================================================
# 3. Incident Service & Correlation Engine
# ===========================================================================

class TestIncidentService:
    """Tests for alert correlation, deduplication, and service operations."""

    @pytest.mark.asyncio
    async def test_first_anomaly_creates_new_incident(self, test_session: AsyncSession) -> None:
        inc, anom, is_new = await IncidentService.correlate_or_create_incident(
            session=test_session,
            score=0.85,
            threshold=0.01,
            severity="high",
            is_anomaly=True,
            top_features=[{"feature": "Memory Available MBytes", "squared_error": 0.4}],
            source="live",
        )
        await test_session.commit()

        assert is_new is True
        assert inc.severity == "high"
        assert inc.status == "detected"
        assert inc.anomaly_score == 0.85
        assert "Memory Available MBytes" in inc.title
        assert anom.incident_id == inc.id

    @pytest.mark.asyncio
    async def test_burst_anomalies_correlate_into_same_incident(self, test_session: AsyncSession) -> None:
        # First anomaly
        inc1, anom1, is_new1 = await IncidentService.correlate_or_create_incident(
            session=test_session,
            score=0.50,
            threshold=0.01,
            severity="medium",
            is_anomaly=True,
            source="live",
        )
        await test_session.commit()
        assert is_new1 is True

        # Second anomaly 5 seconds later with higher severity
        inc2, anom2, is_new2 = await IncidentService.correlate_or_create_incident(
            session=test_session,
            score=0.92,
            threshold=0.01,
            severity="critical",
            is_anomaly=True,
            source="live",
        )
        await test_session.commit()

        # Must correlate into the existing incident and elevate severity
        assert is_new2 is False
        assert inc2.id == inc1.id
        assert inc2.severity == "critical"
        assert inc2.anomaly_score == 0.92

        # Verify incident now has 2 anomaly child records
        anomalies = await IncidentService.get_incident_anomalies(test_session, inc1.id)
        assert len(anomalies) == 2

    @pytest.mark.asyncio
    async def test_incident_stats_summary(self, test_session: AsyncSession) -> None:
        # Create 1 detected, 1 investigating, 1 resolved
        inc1 = Incident(title="Inc 1", severity="high", status="detected")
        inc2 = Incident(title="Inc 2", severity="medium", status="investigating")
        inc3 = Incident(title="Inc 3", severity="low", status="resolved")
        test_session.add_all([inc1, inc2, inc3])
        await test_session.commit()

        stats = await IncidentService.get_stats_summary(test_session)
        assert stats.total == 3
        assert stats.active == 2  # detected + investigating
        assert stats.resolved == 1
        assert stats.by_severity["high"] == 1
        assert stats.by_severity["medium"] == 1
        assert stats.by_severity["low"] == 1


# ===========================================================================
# 4. Incident API Endpoints
# ===========================================================================

class TestIncidentAPIEndpoints:
    """Integration tests for FastAPI /api/incidents endpoints."""

    @pytest.fixture(autouse=True)
    def setup_client(self):
        from fastapi.testclient import TestClient
        from backend.app.main import app
        with TestClient(app) as client:
            self.client = client
            yield

    def test_list_incidents_returns_200(self) -> None:
        response = self.client.get("/api/incidents")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "incidents" in data

    def test_get_stats_summary_returns_200(self) -> None:
        response = self.client.get("/api/incidents/stats/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "active" in data
        assert "by_severity" in data

    def test_create_and_get_incident(self) -> None:
        create_payload = {
            "title": "API Test Incident",
            "description": "Simulated disk thrashing",
            "severity": "high",
            "source": "simulated",
            "anomaly_score": 0.82,
        }
        res_create = self.client.post("/api/incidents", json=create_payload)
        assert res_create.status_code == 201
        created = res_create.json()
        inc_id = created["id"]
        assert created["title"] == "API Test Incident"
        assert created["status"] == "detected"

        # Fetch detail
        res_get = self.client.get(f"/api/incidents/{inc_id}")
        assert res_get.status_code == 200
        detail = res_get.json()
        assert detail["id"] == inc_id
        assert "anomalies" in detail
        assert "actions" in detail

    def test_status_transition_valid_and_invalid(self) -> None:
        # Create incident
        res_create = self.client.post(
            "/api/incidents",
            json={"title": "Transition Test", "severity": "medium", "anomaly_score": 0.5},
        )
        inc_id = res_create.json()["id"]

        # Valid transition: detected -> investigating
        res_valid = self.client.patch(
            f"/api/incidents/{inc_id}/status",
            json={"status": "investigating", "actor": "test_agent", "reason": "triaged"},
        )
        assert res_valid.status_code == 200
        assert res_valid.json()["status"] == "investigating"

        # Invalid transition: investigating -> detected (not allowed)
        res_invalid = self.client.patch(
            f"/api/incidents/{inc_id}/status",
            json={"status": "detected", "actor": "test_agent"},
        )
        assert res_invalid.status_code == 409  # Conflict

    def test_add_remediation_action(self) -> None:
        # Create incident
        res_create = self.client.post(
            "/api/incidents",
            json={"title": "Action Test Incident", "severity": "critical"},
        )
        inc_id = res_create.json()["id"]

        # Add remediation action
        action_payload = {
            "action_type": "terminate_process",
            "description": "Kill rogue crypto miner process",
            "risk_level": "medium",
            "parameters": {"pid": 9999, "process_name": "miner.exe"},
            "rollback_plan": "Restart harmless worker if PID was legitimate",
        }
        res_act = self.client.post(f"/api/incidents/{inc_id}/actions", json=action_payload)
        assert res_act.status_code == 201
        action = res_act.json()
        assert action["action_type"] == "terminate_process"
        assert action["status"] == "proposed"

        # Fetch actions
        res_list = self.client.get(f"/api/incidents/{inc_id}/actions")
        assert res_list.status_code == 200
        assert len(res_list.json()) >= 1

    def test_get_audit_logs(self) -> None:
        res_create = self.client.post(
            "/api/incidents",
            json={"title": "Audit Log Test Incident", "severity": "low"},
        )
        inc_id = res_create.json()["id"]

        res_logs = self.client.get(f"/api/incidents/{inc_id}/audit-logs")
        assert res_logs.status_code == 200
        logs = res_logs.json()
        assert len(logs) >= 1
        assert logs[0]["action"] == "incident_created_manual"
