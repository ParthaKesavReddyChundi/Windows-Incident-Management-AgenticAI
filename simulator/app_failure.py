"""
Application Failure Scenario.

Simulates crashing/hung application processes (zombie/not responding status, rapid cycle).
"""
from __future__ import annotations

from typing import List

from backend.app.schemas.telemetry import (
    ProcessSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class AppFailureScenario(BaseScenario):
    name = "app_failure"
    description = "Simulates critical application crash or unhandled exception hanging in zombie state."

    def __init__(self, target_process_name: str = "critical_database_service.exe") -> None:
        super().__init__()
        self.target_process_name = target_process_name

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Mark process status as not responding / stopped / zombie
        hung_proc = ProcessSnapshot(
            pid=9995,
            name=self.target_process_name,
            cpu_percent=0.0,
            memory_mb=750.0,
            status="not_responding",
            username="SYSTEM",
        )

        existing = [p for p in snapshot.top_processes if p.name != self.target_process_name]
        snapshot.top_processes = [hung_proc] + existing[:19]

        return snapshot
