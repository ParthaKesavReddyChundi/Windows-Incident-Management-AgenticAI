"""
Memory Pressure Scenario.

Simulates progressive memory consumption (RAM exhaustion, high swap activity)
caused by a memory leak or rogue application.
"""
from __future__ import annotations

import random

from backend.app.schemas.telemetry import (
    MemorySnapshot,
    ProcessSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class MemoryPressureScenario(BaseScenario):
    name = "memory_pressure"
    description = "Simulates acute memory leak driving system RAM pressure above 90%."

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Progressive exhaustion
        progress = (step + 1) / total_steps
        target_pct = min(98.0, 80.0 + (18.0 * intensity * progress) + random.uniform(-1.0, 1.0))
        total_b = base_snapshot.memory.total_bytes
        used_b = int(total_b * (target_pct / 100.0))
        avail_b = max(0, total_b - used_b)

        swap_total = base_snapshot.memory.swap_total_bytes or (total_b // 2)
        swap_pct = min(95.0, 50.0 + (45.0 * intensity * progress))
        swap_used = int(swap_total * (swap_pct / 100.0))

        snapshot.memory = MemorySnapshot(
            total_bytes=total_b,
            available_bytes=avail_b,
            used_bytes=used_b,
            percent=round(target_pct, 2),
            swap_total_bytes=swap_total,
            swap_used_bytes=swap_used,
            swap_percent=round(swap_pct, 2),
        )

        # Rogue process leaking memory
        leaking_mb = (used_b - base_snapshot.memory.used_bytes) / (1024 * 1024)
        rogue_proc = ProcessSnapshot(
            pid=9992,
            name="memory_leak_sim.exe",
            cpu_percent=12.5,
            memory_mb=round(max(2048.0, leaking_mb), 2),
            status="running",
            username="SYSTEM",
        )

        existing = [p for p in snapshot.top_processes if p.pid != 9992]
        snapshot.top_processes = [rogue_proc] + existing[:19]

        return snapshot
