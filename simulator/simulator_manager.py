"""
SimulatorManager — orchestrates and runs incident simulation scenarios.

Provides a unified interface to:
- List available scenarios
- Run a specific scenario against a real or generated baseline snapshot
- Save simulated incident sequences to disk (data/simulated/)
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type

from backend.app.schemas.telemetry import TelemetrySnapshot
from simulator.app_failure import AppFailureScenario
from simulator.base import BaseScenario
from simulator.cpu_overload import CpuOverloadScenario
from simulator.disk_pressure import DiskPressureScenario
from simulator.memory_pressure import MemoryPressureScenario
from simulator.network_anomaly import NetworkAnomalyScenario
from simulator.service_failure import ServiceFailureScenario

logger = logging.getLogger(__name__)


class SimulatorManager:
    """Manages scenario discovery, execution, and artifact saving."""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = output_dir or (Path(__file__).resolve().parent.parent / "data" / "simulated")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._scenarios: Dict[str, BaseScenario] = {
            "cpu_overload": CpuOverloadScenario(),
            "memory_pressure": MemoryPressureScenario(),
            "disk_pressure": DiskPressureScenario(),
            "service_failure": ServiceFailureScenario(),
            "network_anomaly": NetworkAnomalyScenario(),
            "app_failure": AppFailureScenario(),
        }

    def list_scenarios(self) -> Dict[str, str]:
        """Return a mapping of scenario_name -> description."""
        return {name: sc.description for name, sc in self._scenarios.items()}

    def get_scenario(self, name: str) -> Optional[BaseScenario]:
        return self._scenarios.get(name)

    def run_scenario(
        self,
        name: str,
        base_snapshot: TelemetrySnapshot,
        steps: int = 10,
        intensity: float = 0.8,
        save_to_disk: bool = True,
    ) -> List[TelemetrySnapshot]:
        """Run the named scenario and return the list of generated snapshots."""
        scenario = self.get_scenario(name)
        if not scenario:
            raise ValueError(f"Unknown scenario: {name}. Available: {list(self._scenarios.keys())}")

        snapshots = scenario.run(base_snapshot=base_snapshot, steps=steps, intensity=intensity)

        if save_to_disk:
            self._save_snapshots(name, snapshots)

        return snapshots

    def _save_snapshots(self, scenario_name: str, snapshots: List[TelemetrySnapshot]) -> Path:
        """Save snapshots as both JSON and tabular CSV summary."""
        file_prefix = f"sim_{scenario_name}_{snapshots[0].snapshot_id[:8]}"
        json_path = self.output_dir / f"{file_prefix}.json"
        csv_path = self.output_dir / f"{file_prefix}.csv"

        # 1. Save complete JSON representation
        raw_data = [s.model_dump(mode="json") for s in snapshots]
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(raw_data, f, indent=2)

        # 2. Save flattened feature summary CSV
        rows = []
        for s in snapshots:
            top_proc = s.top_processes[0].name if s.top_processes else "none"
            top_proc_cpu = s.top_processes[0].cpu_percent if s.top_processes else 0.0
            net_sent = sum(n.bytes_sent_sec for n in s.networks)
            disk_write = sum((d.write_bytes_sec or 0.0) for d in s.disks)

            rows.append({
                "snapshot_id": s.snapshot_id,
                "timestamp": s.timestamp.isoformat(),
                "source": s.source,
                "label": s.label,
                "is_anomaly": s.is_anomaly,
                "cpu_percent": s.cpu.percent,
                "memory_percent": s.memory.percent,
                "network_bytes_sent_sec": net_sent,
                "disk_write_bytes_sec": disk_write,
                "top_process": top_proc,
                "top_process_cpu": top_proc_cpu,
            })

        if rows:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

        logger.info("Saved %d simulated snapshots to %s and %s", len(snapshots), json_path, csv_path)
        return json_path
