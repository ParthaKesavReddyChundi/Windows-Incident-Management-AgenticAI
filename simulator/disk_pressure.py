"""
Disk Pressure Scenario.

Simulates heavy disk I/O thrashing or disk space filling up.
"""
from __future__ import annotations

import random
from typing import List

from backend.app.schemas.telemetry import (
    DiskSnapshot,
    ProcessSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class DiskPressureScenario(BaseScenario):
    name = "disk_pressure"
    description = "Simulates extreme disk write I/O thrashing and partition saturation."

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Boost disk writes drastically on the primary partition
        disks: List[DiskSnapshot] = []
        for d in base_snapshot.disks:
            d_dict = d.model_dump()
            # Simulate massive read/write spike (e.g. 150-300 MB/s)
            d_dict["read_bytes_sec"] = round(random.uniform(50_000_000, 150_000_000) * intensity, 1)
            d_dict["write_bytes_sec"] = round(random.uniform(150_000_000, 350_000_000) * intensity, 1)
            # Increase disk usage percent slightly
            d_dict["percent"] = min(99.0, d_dict["percent"] + (intensity * 5.0))
            disks.append(DiskSnapshot(**d_dict))

        snapshot.disks = disks

        rogue_proc = ProcessSnapshot(
            pid=9993,
            name="disk_heavy_io_sim.exe",
            cpu_percent=25.0,
            memory_mb=512.0,
            status="running",
            username="SYSTEM",
        )
        existing = [p for p in snapshot.top_processes if p.pid != 9993]
        snapshot.top_processes = [rogue_proc] + existing[:19]

        return snapshot
