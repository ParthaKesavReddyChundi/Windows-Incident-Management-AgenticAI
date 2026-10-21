"""
Process telemetry collector using psutil.

Collects the top N processes by CPU utilisation.

Note: psutil requires a warm-up call before accurate CPU %
      readings are available per-process. We maintain a process
      cache across calls to get accurate delta readings.
"""
from __future__ import annotations

import logging
from typing import List, Optional

import psutil

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import ProcessSnapshot

logger = logging.getLogger(__name__)

TOP_N = 20  # Number of top processes to include


class ProcessCollector(BaseCollector):
    """Collects top processes by CPU utilisation via psutil."""

    name = "processes"

    def __init__(self) -> None:
        super().__init__()
        # Pre-warm all processes for accurate CPU readings on first real call
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                pass

    def _collect(self) -> List[ProcessSnapshot]:
        processes: List[ProcessSnapshot] = []

        # Only fetch lightweight attributes during high-frequency telemetry cycle
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
            try:
                info = proc.info  # type: ignore[attr-defined]
                cpu = info.get("cpu_percent") or 0.0
                mem = info.get("memory_info")
                mem_mb = round(mem.rss / 1024 / 1024, 2) if mem else 0.0
                processes.append(
                    ProcessSnapshot(
                        pid=info["pid"],
                        name=info.get("name") or "unknown",
                        cpu_percent=round(cpu, 2),
                        memory_mb=mem_mb,
                        status="running",
                        username=None,
                        create_time=None,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug("Skipping process: %s", exc)
                continue

        # Sort by CPU descending, take top N
        processes.sort(key=lambda p: p.cpu_percent, reverse=True)
        return processes[:TOP_N]
