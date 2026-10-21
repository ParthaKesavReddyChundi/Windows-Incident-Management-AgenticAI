"""
Network telemetry collector using psutil.

Collects per-interface:
  - Bytes sent/received per second (computed delta)
  - Packets sent/received per second
  - In/out error counts
  - Active connection count (total across all interfaces)

Note: First call has no throughput data — bytes/sec fields will be 0.0.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple

import psutil

from collectors.base import BaseCollector
from backend.app.schemas.telemetry import NetworkSnapshot

# Interfaces to skip (loopback and virtual adapters)
_SKIP_PREFIXES = ("Loopback", "isatap", "Teredo")


class NetworkCollector(BaseCollector):
    """Collects per-interface network throughput via psutil delta."""

    name = "network"

    def __init__(self) -> None:
        super().__init__()
        # {iface: (bytes_sent, bytes_recv, pkts_sent, pkts_recv, timestamp)}
        self._prev: Optional[Dict[str, Tuple[int, int, int, int, float]]] = None

    def _collect(self) -> List[NetworkSnapshot]:
        now_time = time.monotonic()

        try:
            counters = psutil.net_io_counters(pernic=True) or {}
        except Exception as exc:
            raise RuntimeError(f"net_io_counters failed: {exc}") from exc

        # Count all active connections once (global, not per-interface)
        try:
            total_connections = len(psutil.net_connections(kind="inet"))
        except PermissionError:
            total_connections = None
        except Exception:
            total_connections = None

        snapshots: List[NetworkSnapshot] = []

        for iface, stats in counters.items():
            if any(iface.startswith(p) for p in _SKIP_PREFIXES):
                continue
            # Skip interfaces with zero traffic and no previous data
            if stats.bytes_sent == 0 and stats.bytes_recv == 0:
                continue

            bytes_sent_sec = 0.0
            bytes_recv_sec = 0.0
            pkts_sent_sec = 0.0
            pkts_recv_sec = 0.0

            if self._prev and iface in self._prev:
                prev_bs, prev_br, prev_ps, prev_pr, prev_t = self._prev[iface]
                elapsed = now_time - prev_t
                if elapsed > 0:
                    bytes_sent_sec = max(0.0, (stats.bytes_sent - prev_bs) / elapsed)
                    bytes_recv_sec = max(0.0, (stats.bytes_recv - prev_br) / elapsed)
                    pkts_sent_sec = max(0.0, (stats.packets_sent - prev_ps) / elapsed)
                    pkts_recv_sec = max(0.0, (stats.packets_recv - prev_pr) / elapsed)

            snapshots.append(NetworkSnapshot(
                interface=iface,
                bytes_sent_sec=round(bytes_sent_sec, 1),
                bytes_recv_sec=round(bytes_recv_sec, 1),
                packets_sent_sec=round(pkts_sent_sec, 2),
                packets_recv_sec=round(pkts_recv_sec, 2),
                errors_in=stats.errin,
                errors_out=stats.errout,
                connections_count=total_connections if len(counters) == 1 else None,
            ))

        # Update previous snapshot
        self._prev = {
            iface: (s.bytes_sent, s.bytes_recv, s.packets_sent, s.packets_recv, now_time)
            for iface, s in counters.items()
        }

        return snapshots
