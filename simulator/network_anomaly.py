"""
Network Anomaly Scenario.

Simulates anomalous outbound or inbound network traffic (e.g. data exfiltration, C2 beaconing, port scanning).
"""
from __future__ import annotations

import random
from typing import List

from backend.app.schemas.telemetry import (
    NetworkSnapshot,
    ProcessSnapshot,
    TelemetrySnapshot,
)
from simulator.base import BaseScenario


class NetworkAnomalyScenario(BaseScenario):
    name = "network_anomaly"
    description = "Simulates massive outbound traffic burst indicative of data exfiltration or DDoS."

    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        snapshot = self._labelled_copy(base_snapshot)

        # Spike network outbound bytes significantly (e.g. 50MB/s - 120MB/s)
        networks: List[NetworkSnapshot] = []
        for net in base_snapshot.networks:
            n_dict = net.model_dump()
            n_dict["bytes_sent_sec"] = round(random.uniform(40_000_000, 100_000_000) * intensity, 1)
            n_dict["packets_sent_sec"] = round(random.uniform(5000, 15000) * intensity, 1)
            n_dict["connections_count"] = int(random.uniform(250, 800) * intensity)
            networks.append(NetworkSnapshot(**n_dict))

        if not networks:
            networks.append(
                NetworkSnapshot(
                    interface="Ethernet0",
                    bytes_sent_sec=round(75_000_000.0 * intensity, 1),
                    bytes_recv_sec=12000.0,
                    packets_sent_sec=8500.0,
                    packets_recv_sec=120.0,
                    errors_in=0,
                    errors_out=0,
                    connections_count=450,
                )
            )

        snapshot.networks = networks

        rogue_proc = ProcessSnapshot(
            pid=9994,
            name="exfil_beacon_sim.exe",
            cpu_percent=18.0,
            memory_mb=180.0,
            status="running",
            username="SYSTEM",
        )
        existing = [p for p in snapshot.top_processes if p.pid != 9994]
        snapshot.top_processes = [rogue_proc] + existing[:19]

        return snapshot
