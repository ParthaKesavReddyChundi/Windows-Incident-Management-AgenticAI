"""
detection/anomaly_detector.py
==============================
Inference wrapper for the trained TelemetryAutoencoder.

At startup, loads:
  - models/autoencoder.pt           (model weights + input_dim)
  - models/preprocessor_scaler.joblib  (MinMaxScaler fitted on normal train data)
  - models/feature_columns.json        (ordered list of feature names)
  - models/anomaly_threshold.json      (calibrated threshold + stats)

Public API
----------
AnomalyDetector.score(feature_dict)  -> float
    Returns reconstruction error for a feature dict.

AnomalyDetector.is_anomaly(feature_dict) -> bool
    Returns True if score > threshold.

AnomalyDetector.predict(feature_dict) -> AnomalyPrediction
    Full prediction with score, label, severity, and feature details.

AnomalyDetector.predict_batch(X_df) -> pd.DataFrame
    Batch inference on a DataFrame.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import numpy as np
import pandas as pd
import torch

from config.settings import settings
from detection.autoencoder import TelemetryAutoencoder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class AnomalySeverity(str, Enum):
    NORMAL = "normal"
    LOW = "low"         # score slightly above threshold
    MEDIUM = "medium"   # score 2× threshold
    HIGH = "high"       # score 5× threshold
    CRITICAL = "critical"  # score 10× threshold


@dataclass
class AnomalyPrediction:
    """Full prediction result for one telemetry snapshot."""
    score: float
    threshold: float
    is_anomaly: bool
    severity: AnomalySeverity
    # Reconstruction error per feature (top-N most deviant)
    top_deviant_features: list[dict[str, Any]] = field(default_factory=list)
    # Raw metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "threshold": self.threshold,
            "is_anomaly": self.is_anomaly,
            "severity": self.severity.value,
            "top_deviant_features": self.top_deviant_features,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------

def _classify_severity(score: float, threshold: float) -> AnomalySeverity:
    if score <= threshold:
        return AnomalySeverity.NORMAL
    ratio = score / (threshold + 1e-12)
    if ratio < 2.0:
        return AnomalySeverity.LOW
    if ratio < 5.0:
        return AnomalySeverity.MEDIUM
    if ratio < 10.0:
        return AnomalySeverity.HIGH
    return AnomalySeverity.CRITICAL


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Production inference wrapper around TelemetryAutoencoder.

    Usage
    -----
    detector = AnomalyDetector.load()
    result = detector.predict({"processor_time": 0.92, ...})
    if result.is_anomaly:
        print(f"Anomaly detected! severity={result.severity}, score={result.score:.4f}")
    """

    def __init__(
        self,
        model: TelemetryAutoencoder,
        scaler,  # sklearn MinMaxScaler
        feature_columns: list[str],
        threshold: float,
        threshold_stats: dict,
        device: torch.device,
    ) -> None:
        self._model = model
        self._scaler = scaler
        self._feature_columns = feature_columns
        self._threshold = threshold
        self._threshold_stats = threshold_stats
        self._device = device
        logger.info(
            "AnomalyDetector ready — input_dim=%d  threshold=%.6f  device=%s",
            len(feature_columns),
            threshold,
            device,
        )

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(
        cls,
        model_path: Optional[Path] = None,
        scaler_path: Optional[Path] = None,
        features_path: Optional[Path] = None,
        threshold_path: Optional[Path] = None,
    ) -> "AnomalyDetector":
        """
        Load all artifacts from disk and return a ready detector.

        Raises FileNotFoundError if any required artifact is missing.
        """
        import joblib

        model_path = model_path or settings.model_path
        scaler_path = scaler_path or (settings.model_path.parent / "preprocessor_scaler.joblib")
        features_path = features_path or (settings.model_path.parent / "feature_columns.json")
        threshold_path = threshold_path or (settings.model_path.parent / "anomaly_threshold.json")

        for p in [model_path, scaler_path, features_path, threshold_path]:
            if not p.exists():
                raise FileNotFoundError(
                    f"Required artifact not found: {p}\n"
                    "Run `python scripts/train_model.py` first."
                )

        # Device
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Model
        ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
        input_dim = ckpt["input_dim"]
        model = TelemetryAutoencoder(input_dim=input_dim)
        model.load_state_dict(ckpt["model_state_dict"])
        model = model.to(device)
        model.eval()

        # Scaler
        scaler = joblib.load(scaler_path)

        # Feature columns
        with open(features_path, "r", encoding="utf-8") as f:
            feature_columns: list[str] = json.load(f)

        # Threshold
        with open(threshold_path, "r", encoding="utf-8") as f:
            threshold_stats = json.load(f)
        threshold = threshold_stats["threshold"]

        return cls(
            model=model,
            scaler=scaler,
            feature_columns=feature_columns,
            threshold=threshold,
            threshold_stats=threshold_stats,
            device=device,
        )

    # ------------------------------------------------------------------
    # Core inference
    # ------------------------------------------------------------------

    def _prepare_input(self, feature_dict: dict[str, Any]) -> np.ndarray:
        """
        Convert a feature dict to a scaled numpy array matching model input.

        Missing features are filled with 0.0 (safe default after MinMax scaling).
        """
        row = np.array(
            [float(feature_dict.get(col, 0.0)) for col in self._feature_columns],
            dtype=np.float32,
        ).reshape(1, -1)
        return self._scaler.transform(row).astype(np.float32)

    def _reconstruction_error(self, X_scaled: np.ndarray) -> tuple[float, np.ndarray]:
        """
        Run forward pass and return (mean_mse, per_feature_squared_error).
        """
        tensor = torch.tensor(X_scaled, dtype=torch.float32).to(self._device)
        with torch.no_grad():
            recon = self._model(tensor)
        diff = (recon - tensor).cpu().numpy()
        per_feature_se = (diff ** 2)[0]  # shape [input_dim]
        mean_mse = float(per_feature_se.mean())
        return mean_mse, per_feature_se

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, feature_dict: dict[str, Any]) -> float:
        """Return the reconstruction error (anomaly score) for a feature dict."""
        X = self._prepare_input(feature_dict)
        mse, _ = self._reconstruction_error(X)
        return mse

    def is_anomaly(self, feature_dict: dict[str, Any]) -> bool:
        """Return True if the anomaly score exceeds the calibrated threshold."""
        return self.score(feature_dict) > self._threshold

    def predict(self, feature_dict: dict[str, Any], top_n: int = 10) -> AnomalyPrediction:
        """
        Full prediction with severity and top deviant features.

        Parameters
        ----------
        feature_dict : dict
            Raw (unscaled) telemetry values keyed by feature name.
        top_n : int
            Number of most-deviant features to include in result.

        Returns
        -------
        AnomalyPrediction
        """
        X = self._prepare_input(feature_dict)
        mse, per_feature_se = self._reconstruction_error(X)
        is_anom = mse > self._threshold
        severity = _classify_severity(mse, self._threshold)

        # Top deviant features
        top_idx = np.argsort(per_feature_se)[::-1][:top_n]
        top_features = [
            {
                "feature": self._feature_columns[i],
                "squared_error": float(per_feature_se[i]),
                "raw_value": float(feature_dict.get(self._feature_columns[i], 0.0)),
            }
            for i in top_idx
        ]

        return AnomalyPrediction(
            score=mse,
            threshold=self._threshold,
            is_anomaly=is_anom,
            severity=severity,
            top_deviant_features=top_features,
            metadata={
                "threshold_percentile": self._threshold_stats.get("percentile_used"),
                "device": str(self._device),
            },
        )

    def predict_batch(
        self, df: pd.DataFrame, batch_size: int = 512
    ) -> pd.DataFrame:
        """
        Run inference on a DataFrame with the same columns as the training set.

        Returns the original DataFrame with added columns:
          - anomaly_score  : float (reconstruction MSE)
          - is_anomaly     : bool
          - severity       : str
        """
        # Align and fill missing columns
        X_raw = df.reindex(columns=self._feature_columns, fill_value=0.0).values.astype(np.float32)
        X_scaled = self._scaler.transform(X_raw).astype(np.float32)

        all_scores: list[float] = []
        with torch.no_grad():
            for start in range(0, len(X_scaled), batch_size):
                batch = torch.tensor(X_scaled[start : start + batch_size]).to(self._device)
                recon = self._model(batch)
                mse = ((recon - batch) ** 2).mean(dim=1).cpu().numpy()
                all_scores.extend(mse.tolist())

        scores = np.array(all_scores)
        result_df = df.copy()
        result_df["anomaly_score"] = scores
        result_df["is_anomaly"] = scores > self._threshold
        result_df["severity"] = [
            _classify_severity(s, self._threshold).value for s in scores
        ]
        return result_df

    def predict_snapshot(
        self, snapshot: Any, top_n: int = 10
    ) -> AnomalyPrediction:
        """
        Inference on a live TelemetrySnapshot object.
        """
        feature_dict = extract_snapshot_features(snapshot)
        return self.predict(feature_dict, top_n=top_n)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def feature_columns(self) -> list[str]:
        return self._feature_columns

    @property
    def input_dim(self) -> int:
        return len(self._feature_columns)

    def __repr__(self) -> str:
        return (
            f"AnomalyDetector(input_dim={self.input_dim}, "
            f"threshold={self._threshold:.6f}, device={self._device})"
        )


# ---------------------------------------------------------------------------
# TelemetrySnapshot Feature Extractor
# ---------------------------------------------------------------------------

def extract_snapshot_features(snapshot: Any) -> dict[str, float]:
    """
    Extracts tabular numerical features from a TelemetrySnapshot matching
    the ToN_IoT Performance Monitor feature schema.
    """
    features: dict[str, float] = {}

    # CPU
    if hasattr(snapshot, "cpu") and snapshot.cpu:
        features["Processor_DPC_Rate"] = float(getattr(snapshot.cpu, "percent", 0.0) * 10.0)

    # Memory
    if hasattr(snapshot, "memory") and snapshot.memory:
        mem = snapshot.memory
        avail = float(getattr(mem, "available_bytes", 0.0))
        used = float(getattr(mem, "used_bytes", 0.0))
        total = float(getattr(mem, "total_bytes", avail + used or 1.0))
        pct = float(getattr(mem, "percent", 0.0))

        features["Memory Available Bytes"] = avail
        features["Memory Available KBytes"] = avail / 1024.0
        features["Memory Available MBytes"] = avail / (1024.0 * 1024.0)
        features["Memory Committed Bytes"] = used
        features["Memory pct_ Committed Bytes In Use"] = pct
        features["Memory Commit Limit"] = total
        features["Memory Cache Bytes"] = avail * 0.15
        features["Memory Cache Bytes Peak"] = avail * 0.20
        features["Memory System Cache Resident Bytes"] = avail * 0.10

    # Disks
    if hasattr(snapshot, "disks") and snapshot.disks:
        primary_disk = snapshot.disks[0]
        free_bytes = float(getattr(primary_disk, "free_bytes", 0.0))
        pct_used = float(getattr(primary_disk, "percent", 0.0))
        features["LogicalDisk(_Total) pct_ Free Space"] = max(0.0, 100.0 - pct_used)
        features["LogicalDisk(_Total) Free Megabytes"] = free_bytes / (1024.0 * 1024.0)

        r_sec = float(getattr(primary_disk, "read_bytes_sec", 0.0) or 0.0)
        w_sec = float(getattr(primary_disk, "write_bytes_sec", 0.0) or 0.0)
        features["LogicalDisk(_Total) Current Disk Queue Length"] = (r_sec + w_sec) / (1024.0 * 1024.0)

    # Processes
    if hasattr(snapshot, "top_processes") and snapshot.top_processes:
        procs = snapshot.top_processes
        total_p_mem_mb = sum(float(getattr(p, "memory_mb", 0.0)) for p in procs)
        total_p_bytes = total_p_mem_mb * 1024.0 * 1024.0
        features["Process_Working Set"] = total_p_bytes
        features["Process_Working_Set_Peak"] = total_p_bytes * 1.1
        features["Process_Private_Bytes"] = total_p_bytes * 0.9
        features["Process_Virtual_Bytes"] = total_p_bytes * 1.5
        features["Process_Thread Count"] = float(len(procs) * 8.0)
        features["Process_Handle Count"] = float(len(procs) * 120.0)

    # Networks
    if hasattr(snapshot, "networks") and snapshot.networks:
        nets = snapshot.networks
        total_bw = sum(
            float(getattr(n, "bytes_sent_sec", 0.0)) + float(getattr(n, "bytes_recv_sec", 0.0))
            for n in nets
        )
        total_pkt = sum(
            float(getattr(n, "packets_sent_sec", 0.0)) + float(getattr(n, "packets_recv_sec", 0.0))
            for n in nets
        )
        features["Network_I(Intel R _82574L_GNC) Current Bandwidth"] = total_bw
        features["Network_I(Intel R _82574L_GNC)TCP_APS"] = total_pkt

    return features

