"""
Disk telemetry collector using psutil.

Collects per partition:
  - Total, used, free bytes and utilisation %
  - Read/write throughput (bytes/sec) via I/O counters delta

The I/O delta is computed between consecutive calls.
The first call will not have throughput data (returns 0.0 as baseline).
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

import psutil

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import DiskSnapshot


class DiskCollector(BaseCollector):
    """Collects disk partition usage and I/O throughput via psutil."""

    name = "disk"

    def __init__(self) -> None:
        super().__init__()
        self._prev_io: Optional[Dict[str, Tuple[int, int, float]]] = None  # {device: (r, w, t)}

    def _collect(self) -> List[DiskSnapshot]:
        snapshots: List[DiskSnapshot] = []

        # Get current disk I/O counters (per-disk)
        try:
            io_now = psutil.disk_io_counters(perdisk=True) or {}
        except Exception:
            io_now = {}

        now_time = time.monotonic()

        for part in psutil.disk_partitions(all=False):
            # Skip non-physical or unmounted partitions
            if not part.mountpoint:
                continue
            # Skip optical drives and network mounts
            if part.fstype in ("", "cdfs", "udf"):
                continue

            try:
                usage = psutil.disk_usage(part.mountpoint)
            except PermissionError:
                continue
            except Exception:
                continue

            # Compute I/O throughput if we have a previous reading
            read_bps: Optional[float] = None
            write_bps: Optional[float] = None

            dev_key = part.device.replace("\\", "").replace(":", "")
            if dev_key in io_now and self._prev_io and dev_key in self._prev_io:
                prev_r, prev_w, prev_t = self._prev_io[dev_key]
                curr_r = io_now[dev_key].read_bytes
                curr_w = io_now[dev_key].write_bytes
                elapsed = now_time - prev_t
                if elapsed > 0:
                    read_bps = max(0.0, (curr_r - prev_r) / elapsed)
                    write_bps = max(0.0, (curr_w - prev_w) / elapsed)

            snapshots.append(DiskSnapshot(
                device=part.device,
                mountpoint=part.mountpoint,
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                percent=round(usage.percent, 2),
                read_bytes_sec=round(read_bps, 1) if read_bps is not None else None,
                write_bytes_sec=round(write_bps, 1) if write_bps is not None else None,
            ))

        # Update previous I/O snapshot
        self._prev_io = {
            dev: (c.read_bytes, c.write_bytes, now_time)
            for dev, c in io_now.items()
        }

        return snapshots
