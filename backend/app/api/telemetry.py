"""
Telemetry REST API and Simulator endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.schemas.telemetry import (
    AnomalyDetectionResponse,
    ModelInfoResponse,
    TelemetrySnapshot,
    TelemetryStatusResponse,
)
from collectors.collector_manager import CollectorManager
from database.session import get_db
from detection.anomaly_detector import AnomalyDetector
from simulator.simulator_manager import SimulatorManager

router = APIRouter()

# Global instances managed in app lifespan
collector_manager: Optional[CollectorManager] = None
simulator_manager = SimulatorManager()
anomaly_detector: Optional[AnomalyDetector] = None


def get_collector_manager() -> CollectorManager:
    global collector_manager
    if collector_manager is None:
        collector_manager = CollectorManager()
    return collector_manager


def get_anomaly_detector() -> Optional[AnomalyDetector]:
    global anomaly_detector
    if anomaly_detector is None:
        try:
            anomaly_detector = AnomalyDetector.load()
        except FileNotFoundError:
            anomaly_detector = None
    return anomaly_detector



@router.get("/status", response_model=TelemetryStatusResponse)
async def get_telemetry_status() -> TelemetryStatusResponse:
    """Return the current status of all telemetry collectors."""
    mgr = get_collector_manager()
    return mgr.get_status()


@router.get("/latest", response_model=Optional[TelemetrySnapshot])
async def get_latest_snapshot() -> Optional[TelemetrySnapshot]:
    """Return the most recent telemetry snapshot."""
    mgr = get_collector_manager()
    snapshot = mgr.get_latest_sync()
    if snapshot is None:
        # Collect synchronously once on demand if loop hasn't completed first cycle yet
        snapshot = mgr._collect_snapshot()
    return snapshot


@router.post("/collect-now", response_model=TelemetrySnapshot)
async def collect_now() -> TelemetrySnapshot:
    """Manually trigger an on-demand telemetry collection."""
    mgr = get_collector_manager()
    snapshot = mgr._collect_snapshot()
    if snapshot is None:
        raise HTTPException(status_code=500, detail="Failed to collect telemetry snapshot")
    return snapshot


# ── Simulator endpoints ────────────────────────────────────────────────────────


@router.get("/simulator/scenarios")
async def list_scenarios() -> Dict[str, str]:
    """List all available incident simulation scenarios."""
    return simulator_manager.list_scenarios()


@router.post("/simulator/run/{scenario_name}", response_model=List[TelemetrySnapshot])
async def run_scenario(
    scenario_name: str,
    steps: int = Query(default=10, ge=1, le=100),
    intensity: float = Query(default=0.8, ge=0.1, le=1.0),
    save_to_disk: bool = Query(default=True),
    auto_correlate: bool = Query(default=True),
    session: AsyncSession = Depends(get_db),
) -> List[TelemetrySnapshot]:
    """
    Run an incident simulation scenario safely generating synthetic snapshots.
    If auto_correlate=True, passes the anomalous snapshot through the Autoencoder,
    creates/correlates an incident in SQLite, and broadcasts real-time alerts.
    """
    mgr = get_collector_manager()
    base_snapshot = mgr.get_latest_sync() or mgr._collect_snapshot()
    if not base_snapshot:
        raise HTTPException(status_code=500, detail="Could not capture baseline telemetry snapshot")

    try:
        snapshots = simulator_manager.run_scenario(
            name=scenario_name,
            base_snapshot=base_snapshot,
            steps=steps,
            intensity=intensity,
            save_to_disk=save_to_disk,
        )

        if snapshots:
            peak_snap = snapshots[0]
            mgr._latest_snapshot = peak_snap

            det = get_anomaly_detector()
            if det and auto_correlate:
                pred = det.predict_snapshot(peak_snap)
                if pred.is_anomaly:
                    from backend.app.services.incident_service import IncidentService
                    from backend.app.api.ws import manager

                    incident, anom_record, is_new = await IncidentService.correlate_or_create_incident(
                        session=session,
                        score=pred.score,
                        threshold=pred.threshold,
                        severity=pred.severity.value,
                        is_anomaly=True,
                        top_features=pred.top_deviant_features,
                        snapshot_id=getattr(peak_snap, "snapshot_id", None),
                        source="simulated",
                    )

                    snap_dict = peak_snap.model_dump(mode="json")
                    snap_dict["is_anomaly"] = True
                    snap_dict["anomaly_score"] = pred.score

                    await manager.broadcast("telemetry_snapshot", snap_dict)
                    await manager.broadcast("incident_created", {
                        "id": incident.id,
                        "incident_id": incident.id,
                        "title": incident.title,
                        "severity": incident.severity,
                        "status": incident.status,
                        "anomaly_score": pred.score,
                    })

        return snapshots
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Anomaly Detection endpoints ───────────────────────────────────────────────


@router.get("/model-info", response_model=ModelInfoResponse)
async def get_model_info() -> ModelInfoResponse:
    """Return status and metadata for the loaded Autoencoder anomaly detector."""
    det = get_anomaly_detector()
    if det is None:
        raise HTTPException(
            status_code=503,
            detail="Anomaly detector model artifacts not loaded. Run train_model.py first."
        )
    return ModelInfoResponse(
        loaded=True,
        model_type="Deep Autoencoder (PyTorch)",
        input_dim=det.input_dim,
        threshold=det.threshold,
        device=str(det._device),
        feature_count=len(det.feature_columns),
    )


@router.post("/detect", response_model=AnomalyDetectionResponse)
async def detect_anomaly(
    snapshot: Optional[TelemetrySnapshot] = None,
    top_n: int = Query(default=5, ge=1, le=20),
    auto_correlate: bool = Query(default=True, description="Automatically correlate anomalies into database incidents"),
    session: AsyncSession = Depends(get_db),
) -> AnomalyDetectionResponse:
    """
    Score a telemetry snapshot using the trained Autoencoder.
    If no snapshot is provided in the body, scores the latest collected snapshot.
    If an anomaly is detected and auto_correlate=True, automatically persists and
    correlates the event into an Incident in SQLite.
    """
    det = get_anomaly_detector()
    if det is None:
        raise HTTPException(
            status_code=503,
            detail="Anomaly detector model artifacts not loaded. Run train_model.py first."
        )

    if snapshot is None:
        mgr = get_collector_manager()
        snapshot = mgr.get_latest_sync() or mgr._collect_snapshot()
        if snapshot is None:
            raise HTTPException(
                status_code=500,
                detail="Could not acquire a telemetry snapshot for anomaly detection."
            )

    pred = det.predict_snapshot(snapshot, top_n=top_n)
    metadata = dict(pred.metadata)

    if pred.is_anomaly and auto_correlate:
        from backend.app.services.incident_service import IncidentService
        incident, anom_record, is_new = await IncidentService.correlate_or_create_incident(
            session=session,
            score=pred.score,
            threshold=pred.threshold,
            severity=pred.severity.value,
            is_anomaly=pred.is_anomaly,
            top_features=pred.top_deviant_features,
            snapshot_id=getattr(snapshot, "snapshot_id", None),
            source=getattr(snapshot, "source", "live"),
        )
        metadata["incident_id"] = incident.id
        metadata["is_new_incident"] = is_new

    return AnomalyDetectionResponse(
        score=pred.score,
        threshold=pred.threshold,
        is_anomaly=pred.is_anomaly,
        severity=pred.severity.value,
        top_deviant_features=[
            {
                "feature": f["feature"],
                "squared_error": f["squared_error"],
                "raw_value": f["raw_value"],
            }
            for f in pred.top_deviant_features
        ],
        metadata=metadata,
    )

