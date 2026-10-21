"""
Unit tests for the FastAPI backend foundation (Phase 2).

Tests:
- Health endpoint returns 200 and correct schema
- Root endpoint returns 200
- Telemetry status endpoint returns correct schema
- Incident list endpoint returns correct schema
- Actions pending endpoint returns correct schema
- Settings load without error
- Logging setup runs without error
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.main import app

client = TestClient(app)


class TestHealthEndpoints:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_ok_status(self):
        data = client.get("/health").json()
        assert data["status"] == "ok"

    def test_health_returns_version(self):
        data = client.get("/health").json()
        assert "version" in data

    def test_root_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_contains_docs_link(self):
        data = client.get("/").json()
        assert "docs" in data


class TestTelemetryEndpoints:
    def test_telemetry_status_returns_200(self):
        response = client.get("/api/telemetry/status")
        assert response.status_code == 200

    def test_telemetry_status_schema(self):
        data = client.get("/api/telemetry/status").json()
        assert "collector_running" in data
        assert "queue_size" in data
        assert "available_collectors" in data
        assert data["collector_running"] is False  # Not started yet in Phase 2

    def test_telemetry_latest_returns_200(self):
        response = client.get("/api/telemetry/latest")
        assert response.status_code == 200


class TestIncidentEndpoints:
    def test_incidents_list_returns_200(self):
        with TestClient(app) as c:
            response = c.get("/api/incidents")
            assert response.status_code == 200

    def test_incidents_list_schema(self):
        with TestClient(app) as c:
            data = c.get("/api/incidents").json()
            assert "total" in data
            assert "incidents" in data
            assert isinstance(data["incidents"], list)
            assert data["total"] >= 0

    def test_incident_get_by_id_returns_404_when_missing(self):
        with TestClient(app) as c:
            response = c.get("/api/incidents/test-id-123")
            assert response.status_code == 404



class TestActionsEndpoints:
    def test_actions_pending_returns_200(self):
        response = client.get("/api/actions/pending")
        assert response.status_code == 200

    def test_actions_pending_schema(self):
        data = client.get("/api/actions/pending").json()
        assert "pending" in data
        assert isinstance(data["pending"], list)

    def test_audit_log_returns_200(self):
        response = client.get("/api/actions/audit-log")
        assert response.status_code == 200


class TestSettings:
    def test_settings_load(self):
        from config.settings import settings
        assert settings.app_port == 8000
        assert settings.telemetry_interval_seconds > 0
        assert settings.anomaly_threshold > 0.0

    def test_settings_paths_are_relative_to_project(self):
        from config.settings import settings, PROJECT_ROOT
        assert settings.logs_dir.is_relative_to(PROJECT_ROOT)
        assert settings.models_dir.is_relative_to(PROJECT_ROOT)


class TestLogging:
    def test_logging_setup_runs(self):
        from config.logging_config import setup_logging
        # Should not raise
        setup_logging(log_level="INFO", logs_dir=None)
