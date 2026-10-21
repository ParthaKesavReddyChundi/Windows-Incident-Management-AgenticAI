"""
Memory telemetry collector using psutil.

Collects:
  - Physical RAM: total, available, used, utilisation %
  - Swap: total, used, utilisation %
"""
from __future__ import annotations

import psutil

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import MemorySnapshot


class MemoryCollector(BaseCollector):
    """Collects physical RAM and swap metrics via psutil."""

    name = "memory"

    def _collect(self) -> MemorySnapshot:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()

        return MemorySnapshot(
            total_bytes=vm.total,
            available_bytes=vm.available,
            used_bytes=vm.used,
            percent=round(vm.percent, 2),
            swap_total_bytes=sw.total if sw.total > 0 else None,
            swap_used_bytes=sw.used if sw.total > 0 else None,
            swap_percent=round(sw.percent, 2) if sw.total > 0 else None,
        )
