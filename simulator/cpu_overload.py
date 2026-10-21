"""
CPU Overload Scenario.

Simulates a high CPU usage spike (e.g. 90-100% across multiple cores)
caused by a specific process consuming excessive compute resources.
"""
from __future__ import annotations

import random
from typing import List

from backend.app.schemas.telemetry import (
    CpuSnapshot,
    ProcessSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class CpuOverloadScenario(BaseScenario):
    name = "cpu_overload"
    description = "Simulates sustained high CPU load driven by a runaway process."

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Ramp up then sustained plateau
        progress = (step + 1) / total_steps
        ramp = min(1.0, progress * 2.0)
        target_pct = min(100.0, 75.0 + (25.0 * intensity * ramp) + random.uniform(-2.0, 2.0))

        # Core breakdown
        per_core = [
            round(min(100.0, target_pct + random.uniform(-5.0, 5.0)), 2)
            for _ in (base_snapshot.cpu.per_core or [target_pct] * 8)
        ]

        snapshot.cpu = CpuSnapshot(
            percent=round(target_pct, 2),
            per_core=per_core,
            freq_mhz=base_snapshot.cpu.freq_mhz,
            load_avg_1m=None,
        )

        # Inject / promote top process causing the load
        rogue_proc = ProcessSnapshot(
            pid=9991,
            name="crypto_worker_sim.exe",
            cpu_percent=round(target_pct * 0.85, 2),
            memory_mb=350.0,
            status="running",
            username="SYSTEM",
        )

        # Place rogue process at top of top_processes list
        existing = [p for p in snapshot.top_processes if p.pid != 9991]
        snapshot.top_processes = [rogue_proc] + existing[:19]

        return snapshot
