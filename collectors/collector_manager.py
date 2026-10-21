"""
CollectorManager — orchestrates all Windows telemetry collectors.

Responsibilities:
  - Maintains a list of all available collectors.
  - Runs a background asyncio loop collecting snapshots every N seconds.
  - Puts complete TelemetrySnapshot objects into a bounded asyncio.Queue.
  - Tracks which collectors succeeded/failed and their latencies.
  - Exposes status for the API and dashboard.

Thread safety: all state mutations happen in the single asyncio event loop.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from backend.app.schemas.telemetry import (
    TelemetrySnapshot,
    TelemetryStatusResponse,
    CpuSnapshot,
    MemorySnapshot,
    DiskSnapshot,
    NetworkSnapshot,
    ProcessSnapshot,
    ServiceSnapshot,
)
from collectors.cpu_collector import CpuCollector
from collectors.memory_collector import MemoryCollector
from collectors.disk_collector import DiskCollector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.service_collector import ServiceCollector
from collectors.event_log_collector import EventLogCollector

logger = logging.getLogger(__name__)


class CollectorManager:
    """
    Background collector that aggregates all Windows telemetry metrics
    into TelemetrySnapshot objects and places them in a bounded queue.
    """

    def __init__(
        self,
        interval_seconds: float = 5.0,
        queue_max_size: int = 200,
    ) -> None:
        self._interval = interval_seconds
        self._queue: asyncio.Queue[TelemetrySnapshot] = asyncio.Queue(maxsize=queue_max_size)
        self._running = False
        self._task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
        self._snapshots_collected = 0
        self._last_snapshot_at: Optional[datetime] = None
        self._failed_collectors: List[str] = []
        self._latest_snapshot: Optional[TelemetrySnapshot] = None
        self._on_snapshot: Optional[Any] = None

        # Instantiate all collectors
        self._cpu = CpuCollector()
        self._mem = MemoryCollector()
        self._disk = DiskCollector()
        self._net = NetworkCollector()
        self._proc = ProcessCollector()
        self._svc = ServiceCollector()
        self._evtlog = EventLogCollector()

        logger.info(
            "CollectorManager initialised — interval=%.1fs queue_max=%d",
            interval_seconds,
            queue_max_size,
        )

    def set_on_snapshot(self, callback: Any) -> None:
        """Register a callback invoked whenever a new telemetry snapshot is collected."""
        self._on_snapshot = callback

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Start the background collection loop."""
        if self._running:
            logger.warning("CollectorManager already running")
            return
        self._running = True
        self._task = asyncio.create_task(self._collection_loop(), name="telemetry-collector")
        logger.info("CollectorManager started")

    async def stop(self) -> None:
        """Stop the background collection loop gracefully."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        logger.info("CollectorManager stopped")

    # ── Background loop ────────────────────────────────────────────────────────
    async def _collection_loop(self) -> None:
        logger.info("Collection loop starting")
        while self._running:
            t_start = time.monotonic()
            try:
                snapshot = await asyncio.to_thread(self._collect_snapshot)
                if snapshot:
                    self._latest_snapshot = snapshot
                    # Evict oldest entry if queue is full (bounded backpressure)
                    if self._queue.full():
                        try:
                            self._queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    await self._queue.put(snapshot)
                    self._snapshots_collected += 1
                    self._last_snapshot_at = snapshot.timestamp
                    if self._on_snapshot:
                        try:
                            cb_res = self._on_snapshot(snapshot)
                            if asyncio.iscoroutine(cb_res):
                                await cb_res
                        except Exception as cb_err:
                            logger.debug("on_snapshot callback error: %s", cb_err)
            except Exception as exc:
                logger.error("Unexpected error in collection loop: %s", exc, exc_info=True)

            elapsed = time.monotonic() - t_start
            sleep_time = max(0.0, self._interval - elapsed)
            await asyncio.sleep(sleep_time)

    def _collect_snapshot(self) -> Optional[TelemetrySnapshot]:
        """
        Synchronous collection of all metrics.
        Runs in a thread executor to avoid blocking the event loop.
        """
        t0 = time.perf_counter()
        failed: List[str] = []

        # ── CPU ───────────────────────────────────────────────────────────────
        cpu_data = self._cpu.collect()
        if cpu_data is None:
            failed.append("cpu")
            cpu_data = CpuSnapshot(percent=0.0, per_core=[], freq_mhz=None, load_avg_1m=None)

        # ── Memory ────────────────────────────────────────────────────────────
        mem_data = self._mem.collect()
        if mem_data is None:
            failed.append("memory")
            import psutil
            vm = psutil.virtual_memory()
            mem_data = MemorySnapshot(
                total_bytes=vm.total, available_bytes=vm.available,
                used_bytes=vm.used, percent=0.0,
            )

        # ── Disk ──────────────────────────────────────────────────────────────
        disk_data: List[DiskSnapshot] = self._disk.collect() or []
        if not disk_data:
            failed.append("disk")

        # ── Network ───────────────────────────────────────────────────────────
        net_data: List[NetworkSnapshot] = self._net.collect() or []
        if not net_data:
            failed.append("network")

        # ── Processes ─────────────────────────────────────────────────────────
        proc_data: List[ProcessSnapshot] = self._proc.collect() or []
        if not proc_data:
            failed.append("processes")

        # ── Services ──────────────────────────────────────────────────────────
        svc_data: List[ServiceSnapshot] = self._svc.collect() or []
        if not svc_data:
            failed.append("services")

        # ── Event Logs (best-effort, stored for future phases) ─────────────────
        self._evtlog.collect()  # Data available via evtlog collector directly in Phase 7

        total_latency_ms = (time.perf_counter() - t0) * 1000
        self._failed_collectors = failed

        if failed:
            logger.debug("Collectors unavailable this cycle: %s", failed)

        return TelemetrySnapshot(
            snapshot_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=timezone.utc),
            source="live",
            collection_latency_ms=round(total_latency_ms, 2),
            cpu=cpu_data,
            memory=mem_data,
            disks=disk_data,
            networks=net_data,
            top_processes=proc_data,
            services=svc_data,
        )

    # ── Public accessors ───────────────────────────────────────────────────────
    def get_latest_sync(self) -> Optional[TelemetrySnapshot]:
        """Return the most recent snapshot (non-async, safe from any context)."""
        return self._latest_snapshot

    def get_status(self) -> TelemetryStatusResponse:
        all_collectors = ["cpu", "memory", "disk", "network", "processes", "services", "event_log"]
        available = [c for c in all_collectors if c not in self._failed_collectors]
        return TelemetryStatusResponse(
            collector_running=self._running,
            last_snapshot_at=self._last_snapshot_at,
            snapshots_collected=self._snapshots_collected,
            queue_size=self._queue.qsize(),
            queue_max=self._queue.maxsize,
            available_collectors=available,
            failed_collectors=self._failed_collectors,
        )

    @property
    def queue(self) -> asyncio.Queue:  # type: ignore[type-arg]
        return self._queue

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def snapshots_collected(self) -> int:
        return self._snapshots_collected
