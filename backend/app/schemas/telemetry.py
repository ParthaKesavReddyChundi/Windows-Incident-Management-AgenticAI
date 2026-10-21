"""
Pydantic schemas for telemetry snapshots.

These define the validated data contracts for telemetry flowing from
collectors → backend → database → dashboard.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CpuSnapshot(BaseModel):
    percent: float = Field(..., ge=0.0, le=100.0, description="Overall CPU utilisation %")
    per_core: List[float] = Field(default_factory=list, description="Per-core utilisation %")
    freq_mhz: Optional[float] = Field(None, description="Current clock frequency (MHz)")
    load_avg_1m: Optional[float] = Field(None, description="1-minute load average (Unix-style)")


class MemorySnapshot(BaseModel):
    total_bytes: int = Field(..., description="Total physical RAM in bytes")
    available_bytes: int = Field(..., description="Available RAM in bytes")
    used_bytes: int = Field(..., description="Used RAM in bytes")
    percent: float = Field(..., ge=0.0, le=100.0, description="RAM utilisation %")
    swap_total_bytes: Optional[int] = None
    swap_used_bytes: Optional[int] = None
    swap_percent: Optional[float] = None


class DiskSnapshot(BaseModel):
    device: str
    mountpoint: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent: float = Field(..., ge=0.0, le=100.0)
    read_bytes_sec: Optional[float] = None
    write_bytes_sec: Optional[float] = None


class NetworkSnapshot(BaseModel):
    interface: str
    bytes_sent_sec: float = Field(..., ge=0.0)
    bytes_recv_sec: float = Field(..., ge=0.0)
    packets_sent_sec: float = Field(..., ge=0.0)
    packets_recv_sec: float = Field(..., ge=0.0)
    errors_in: int = Field(default=0)
    errors_out: int = Field(default=0)
    connections_count: Optional[int] = None


class ProcessSnapshot(BaseModel):
    pid: int
    name: str
    cpu_percent: float = Field(..., ge=0.0)
    memory_mb: float = Field(..., ge=0.0)
    status: str
    username: Optional[str] = None
    create_time: Optional[datetime] = None


class ServiceSnapshot(BaseModel):
    name: str
    display_name: str
    status: str          # running, stopped, paused, etc.
    start_type: str      # automatic, manual, disabled


class TelemetrySnapshot(BaseModel):
    """A complete point-in-time snapshot of Windows system telemetry."""
    snapshot_id: str = Field(..., description="Unique identifier (UUID)")
    timestamp: datetime = Field(..., description="UTC timestamp of collection")
    source: str = Field(default="live", description="'live' | 'simulated' | 'benchmark'")
    collection_latency_ms: Optional[float] = Field(None, description="Time to collect this snapshot (ms)")

    cpu: CpuSnapshot
    memory: MemorySnapshot
    disks: List[DiskSnapshot] = Field(default_factory=list)
    networks: List[NetworkSnapshot] = Field(default_factory=list)
    top_processes: List[ProcessSnapshot] = Field(default_factory=list)
    services: List[ServiceSnapshot] = Field(default_factory=list)

    # Labels (populated by simulator or benchmark loader)
    label: Optional[str] = Field(None, description="Ground-truth label if known")
    is_anomaly: Optional[bool] = Field(None, description="Ground-truth anomaly flag if known")


class TelemetryStatusResponse(BaseModel):
    """Status of the telemetry collection subsystem."""
    collector_running: bool
    last_snapshot_at: Optional[datetime]
    snapshots_collected: int
    queue_size: int
    queue_max: int
    available_collectors: List[str]
    failed_collectors: List[str]


class TopDeviantFeature(BaseModel):
    feature: str
    squared_error: float
    raw_value: float


class AnomalyDetectionResponse(BaseModel):
    """Response returned by the deep learning anomaly detector."""
    score: float
    threshold: float
    is_anomaly: bool
    severity: str
    top_deviant_features: List[TopDeviantFeature] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ModelInfoResponse(BaseModel):
    """Metadata regarding the loaded autoencoder model and threshold."""
    loaded: bool
    model_type: str = "Deep Autoencoder"
    input_dim: int
    threshold: float
    device: str
    feature_count: int

