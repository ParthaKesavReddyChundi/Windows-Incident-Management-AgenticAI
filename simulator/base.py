"""
BaseScenario — abstract base for all incident simulation scenarios.

SAFETY DESIGN:
  All scenarios generate SYNTHETIC telemetry data only.
  They do NOT:
    - Allocate real memory
    - Spin real CPU threads
    - Modify real Windows services
    - Make real network connections
    - Create or delete real files

  The simulated snapshots are labelled so the anomaly detector, agents,
  and evaluation pipeline can clearly distinguish them from live data.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Iterator, List, Optional

from backend.app.schemas.telemetry import TelemetrySnapshot


class BaseScenario(ABC):
    """Abstract base for simulation scenarios."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scenario identifier used as the ground-truth label."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scenario simulates."""

    @abstractmethod
    def generate(
        self,
        base_snapshot: TelemetrySnapshot,
        step: int,
        total_steps: int,
        intensity: float = 0.8,
    ) -> TelemetrySnapshot:
        """
        Produce one anomalous snapshot for the given step.

        Args:
            base_snapshot: A real (or synthetic) baseline snapshot to modify.
            step: Current step number (0-indexed).
            total_steps: Total number of steps in this scenario run.
            intensity: 0.0–1.0 scaling factor for anomaly severity.

        Returns:
            A new TelemetrySnapshot with anomalous values and correct labels.
        """

    def run(
        self,
        base_snapshot: TelemetrySnapshot,
        steps: int = 12,
        intensity: float = 0.8,
    ) -> List[TelemetrySnapshot]:
        """
        Generate a complete scenario as a list of snapshots.

        Args:
            base_snapshot: Baseline snapshot to build the scenario from.
            steps: Number of snapshots to generate.
            intensity: Anomaly intensity (0–1).

        Returns:
            List of labelled TelemetrySnapshot objects.
        """
        return [
            self.generate(base_snapshot, step=i, total_steps=steps, intensity=intensity)
            for i in range(steps)
        ]

    def _labelled_copy(
        self,
        snapshot: TelemetrySnapshot,
        label: Optional[str] = None,
    ) -> TelemetrySnapshot:
        """Return a deep copy with updated snapshot_id, timestamp, and labels."""
        data = snapshot.model_dump()
        data["snapshot_id"] = str(uuid.uuid4())
        data["timestamp"] = datetime.now(tz=timezone.utc)
        data["source"] = "simulated"
        data["label"] = label or self.name
        data["is_anomaly"] = True
        return TelemetrySnapshot(**data)
