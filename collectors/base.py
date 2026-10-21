"""
BaseCollector — abstract base class for all Windows telemetry collectors.

Design principles:
  - Each collector is independent: a failure in one does NOT affect others.
  - collect() always returns Optional[T]; None signals unavailability.
  - Latency of each collection is measured and stored.
  - Collectors expose is_available so the manager can report status clearly.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for all telemetry collectors."""

    def __init__(self) -> None:
        self._available: bool = True
        self._last_latency_ms: float = 0.0
        self._last_error: Optional[str] = None
        self._collect_count: int = 0

    # ── Subclasses implement this ──────────────────────────────────────────────
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique collector identifier (e.g. 'cpu', 'memory')."""

    @abstractmethod
    def _collect(self) -> Any:
        """Perform the actual data collection. Raise on failure."""

    # ── Public interface ───────────────────────────────────────────────────────
    def collect(self) -> Optional[Any]:
        """
        Safe collection wrapper.
        Measures latency, catches all exceptions, updates availability flag.
        Returns None if collection fails.
        """
        t0 = time.perf_counter()
        try:
            result = self._collect()
            self._last_latency_ms = (time.perf_counter() - t0) * 1000
            self._available = True
            self._last_error = None
            self._collect_count += 1
            return result
        except PermissionError as exc:
            self._available = False
            self._last_error = f"PermissionError: {exc}"
            logger.warning("[%s] Permission denied — skipping: %s", self.name, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            self._available = False
            self._last_error = str(exc)
            logger.warning("[%s] Collection failed: %s", self.name, exc)
            return None
        finally:
            self._last_latency_ms = (time.perf_counter() - t0) * 1000

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def last_latency_ms(self) -> float:
        return self._last_latency_ms

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def collect_count(self) -> int:
        return self._collect_count

    def __repr__(self) -> str:
        status = "available" if self._available else f"unavailable ({self._last_error})"
        return f"<{self.__class__.__name__} name={self.name!r} status={status}>"
