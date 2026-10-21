"""
CPU telemetry collector using psutil.

Collects:
  - Overall CPU utilisation %
  - Per-core utilisation %
  - Current clock frequency (MHz)

Note: Windows does not expose Unix-style load averages.
"""
from __future__ import annotations

from typing import List, Optional

import psutil

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import CpuSnapshot


class CpuCollector(BaseCollector):
    """Collects CPU utilisation metrics via psutil."""

    name = "cpu"

    def __init__(self) -> None:
        super().__init__()
        # Warm-up call — psutil requires a prior call to get accurate delta readings
        psutil.cpu_percent(interval=None)

    def _collect(self) -> CpuSnapshot:
        # interval=None uses the reading since the last call (non-blocking)
        overall: float = psutil.cpu_percent(interval=None)
        per_core: List[float] = psutil.cpu_percent(interval=None, percpu=True)  # type: ignore[assignment]

        freq = psutil.cpu_freq()
        freq_mhz: Optional[float] = round(freq.current, 1) if freq else None

        return CpuSnapshot(
            percent=round(overall, 2),
            per_core=[round(c, 2) for c in per_core],
            freq_mhz=freq_mhz,
            load_avg_1m=None,  # Not available on Windows
        )
