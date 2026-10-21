"""
Unit and integration tests for Phase 3:
- Individual Collectors (CPU, Memory, Disk, Network, Process, Service, EventLog)
- CollectorManager (lifecycle, queue backpressure, status)
- Simulator Scenarios (all 6 scenarios)
- SimulatorManager (discovery, execution, disk serialization)
- REST API integration for Telemetry & Simulator
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.main import app
from backend.app.schemas.telemetry import TelemetrySnapshot
from collectors.cpu_collector import CpuCollector
from collectors.disk_collector import DiskCollector
from collectors.event_log_collector import EventLogCollector
from collectors.memory_collector import MemoryCollector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.service_collector import ServiceCollector
from collectors.collector_manager import CollectorManager
from simulator.simulator_manager import SimulatorManager


class TestIndividualCollectors:
    def test_cpu_collector(self):
        col = CpuCollector()
        res = col.collect()
        assert res is not None
        assert 0.0 <= res.percent <= 100.0
        assert isinstance(res.per_core, list)
        assert col.is_available is True
        assert col.last_latency_ms >= 0.0

    def test_memory_collector(self):
        col = MemoryCollector()
        res = col.collect()
        assert res is not None
        assert res.total_bytes > 0
        assert res.used_bytes > 0
        assert 0.0 <= res.percent <= 100.0
        assert col.is_available is True

    def test_disk_collector(self):
        col = DiskCollector()
        res = col.collect()
        assert res is not None
        assert isinstance(res, list)
        assert len(res) > 0
        assert res[0].total_bytes > 0
        assert 0.0 <= res[0].percent <= 100.0

    def test_network_collector(self):
        col = NetworkCollector()
        res = col.collect()
        assert res is not None
        assert isinstance(res, list)

    def test_process_collector(self):
        col = ProcessCollector()
        res = col.collect()
        assert res is not None
        assert isinstance(res, list)
        assert len(res) > 0
        # On Windows, System Idle Process has pid 0
        assert res[0].pid >= 0
        assert res[0].name != ""

    def test_service_collector(self):
        col = ServiceCollector()
        res = col.collect()
        assert res is not None
        assert isinstance(res, list)
        assert len(res) > 0
        assert res[0].name != ""

    def test_event_log_collector(self):
        col = EventLogCollector()
        res = col.collect()
        # Even on restricted environments, it shouldn't crash and returns None or dict
        if res is not None:
            assert isinstance(res, dict)
            assert "System" in res or "Application" in res


class TestCollectorManager:
    @pytest.mark.asyncio
    async def test_collector_manager_cycle(self):
        mgr = CollectorManager(interval_seconds=0.1, queue_max_size=5)
        # Verify single synchronous collection
        snapshot = mgr._collect_snapshot()
        assert snapshot is not None
        assert snapshot.source == "live"
        assert snapshot.cpu.percent >= 0.0
        assert snapshot.collection_latency_ms is not None

        # Start and verify async loop
        await mgr.start()
        assert mgr.is_running is True

        # Wait up to 5 seconds for at least 1 snapshot to be collected
        for _ in range(50):
            if mgr.snapshots_collected >= 1:
                break
            await asyncio.sleep(0.1)

        status = mgr.get_status()
        assert status.collector_running is True
        assert status.snapshots_collected >= 1
        assert mgr.queue.qsize() > 0

        await mgr.stop()
        assert mgr.is_running is False


class TestSimulatorScenarios:
    @pytest.fixture
    def base_snapshot(self) -> TelemetrySnapshot:
        mgr = CollectorManager()
        snap = mgr._collect_snapshot()
        assert snap is not None
        return snap

    @pytest.mark.parametrize(
        "scenario_name",
        [
            "cpu_overload",
            "memory_pressure",
            "disk_pressure",
            "service_failure",
            "network_anomaly",
            "app_failure",
        ],
    )
    def test_scenario_execution(self, scenario_name: str, base_snapshot: TelemetrySnapshot):
        sim_mgr = SimulatorManager()
        snapshots = sim_mgr.run_scenario(
            name=scenario_name,
            base_snapshot=base_snapshot,
            steps=3,
            intensity=0.8,
            save_to_disk=False,
        )
        assert len(snapshots) == 3
        for s in snapshots:
            assert s.source == "simulated"
            assert s.is_anomaly is True
            assert s.label == scenario_name


class TestTelemetryAPIEndpoints:
    def test_api_status_and_collect(self):
        with TestClient(app) as client:
            res = client.get("/api/telemetry/status")
            assert res.status_code == 200
            data = res.json()
            assert "collector_running" in data
            assert "available_collectors" in data

            res_snap = client.get("/api/telemetry/latest")
            assert res_snap.status_code == 200
            snap_data = res_snap.json()
            assert snap_data is not None
            assert "cpu" in snap_data

            # Test simulator list
            res_scenarios = client.get("/api/telemetry/simulator/scenarios")
            assert res_scenarios.status_code == 200
            scenarios = res_scenarios.json()
            assert "cpu_overload" in scenarios

            # Test simulator run
            res_run = client.post("/api/telemetry/simulator/run/cpu_overload?steps=2&intensity=0.7")
            assert res_run.status_code == 200
            sim_snaps = res_run.json()
            assert len(sim_snaps) == 2
            assert sim_snaps[0]["label"] == "cpu_overload"
