"""
Service Failure Scenario.

Simulates critical Windows service failures (e.g. Spooler, W32Time, EventLog, WinDefend).
"""
from __future__ import annotations

from typing import List

from backend.app.schemas.telemetry import (
    ServiceSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class ServiceFailureScenario(BaseScenario):
    name = "service_failure"
    description = "Simulates abrupt termination or stoppage of critical Windows services."

    def __init__(self, target_service: str = "wuauserv") -> None:
        super().__init__()
        self.target_service = target_service

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Mutate the target service to stopped/crashed state
        services: List[ServiceSnapshot] = []
        found = False
        for s in snapshot.services:
            if s.name.lower() == self.target_service.lower():
                services.append(
                    ServiceSnapshot(
                        name=s.name,
                        display_name=s.display_name,
                        status="stopped",
                        start_type=s.start_type,
                    )
                )
                found = True
            else:
                services.append(s)

        if not found:
            services.append(
                ServiceSnapshot(
                    name=self.target_service,
                    display_name="Windows Update Service (Simulated)",
                    status="stopped",
                    start_type="automatic",
                )
            )

        snapshot.services = services
        return snapshot
