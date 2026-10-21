"""
detection/threshold_calibrator.py
==================================
Calibrates the anomaly detection threshold from reconstruction errors.

Strategy
--------
1. Run the trained autoencoder on a held-out *normal* validation set.
2. Compute per-sample reconstruction error (mean MSE over all features).
3. Set threshold = percentile(errors, q) where q is configurable (default 95).
4. Persist threshold + calibration statistics to models/anomaly_threshold.json.

At inference time, any sample whose reconstruction error exceeds the threshold
is classified as anomalous.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

from config.settings import settings
from detection.autoencoder import TelemetryAutoencoder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------

class ThresholdCalibrator:
    """
    Calibrates the reconstruction-error threshold for anomaly detection.

    Parameters
    ----------
    percentile : float
        Percentile of normal reconstruction errors used as threshold (default 95).
    threshold_path : Path | None
        Where to save the threshold JSON. Defaults to models/anomaly_threshold.json.
    """

    DEFAULT_THRESHOLD_PATH = settings.model_path.parent / "anomaly_threshold.json"

    def __init__(
        self,
        percentile: float = 95.0,
        threshold_path: Optional[Path] = None,
    ) -> None:
        if not (50.0 <= percentile <= 100.0):
            raise ValueError("percentile must be in [50, 100].")
        self.percentile = percentile
        self.threshold_path: Path = threshold_path or self.DEFAULT_THRESHOLD_PATH
        self.threshold: Optional[float] = None
        self.calibration_stats: dict = {}

    # ------------------------------------------------------------------
    def calibrate(
        self,
        model: TelemetryAutoencoder,
        X_normal_val: np.ndarray,
        device: Optional[torch.device] = None,
        batch_size: int = 512,
    ) -> float:
        """
        Compute reconstruction errors on X_normal_val and set threshold.

        Parameters
        ----------
        model : TelemetryAutoencoder
            Trained autoencoder in eval mode.
        X_normal_val : np.ndarray
            Scaled normal-only validation data, shape [N, input_dim].
        device : torch.device | None
            Device to run inference on; auto-detected if None.
        batch_size : int
            Inference batch size.

        Returns
        -------
        float
            Calibrated threshold value.
        """
        if device is None:
            device = next(model.parameters()).device
        model.eval()
        model = model.to(device)

        errors = self._compute_reconstruction_errors(model, X_normal_val, device, batch_size)

        self.threshold = float(np.percentile(errors, self.percentile))
        self.calibration_stats = {
            "percentile_used": self.percentile,
            "threshold": self.threshold,
            "n_samples": len(errors),
            "error_mean": float(np.mean(errors)),
            "error_std": float(np.std(errors)),
            "error_min": float(np.min(errors)),
            "error_p50": float(np.percentile(errors, 50)),
            "error_p75": float(np.percentile(errors, 75)),
            "error_p90": float(np.percentile(errors, 90)),
            "error_p95": float(np.percentile(errors, 95)),
            "error_p99": float(np.percentile(errors, 99)),
            "error_max": float(np.max(errors)),
        }

        logger.info(
            "Threshold calibrated: %.6f (p%.0f of %d normal val samples)",
            self.threshold,
            self.percentile,
            len(errors),
        )
        logger.info(
            "Error distribution — mean=%.6f  std=%.6f  p95=%.6f  p99=%.6f",
            self.calibration_stats["error_mean"],
            self.calibration_stats["error_std"],
            self.calibration_stats["error_p95"],
            self.calibration_stats["error_p99"],
        )

        self._save()
        return self.threshold

    # ------------------------------------------------------------------
    def _compute_reconstruction_errors(
        self,
        model: TelemetryAutoencoder,
        X: np.ndarray,
        device: torch.device,
        batch_size: int,
    ) -> np.ndarray:
        """Return per-sample MSE reconstruction error array."""
        criterion = nn.MSELoss(reduction="none")
        errors: list[np.ndarray] = []

        with torch.no_grad():
            for start in range(0, len(X), batch_size):
                batch = torch.tensor(
                    X[start : start + batch_size], dtype=torch.float32
                ).to(device)
                recon = model(batch)
                # Per-sample MSE = mean over feature dimension
                sample_errors = criterion(recon, batch).mean(dim=1).cpu().numpy()
                errors.append(sample_errors)

        return np.concatenate(errors)

    # ------------------------------------------------------------------
    def _save(self) -> None:
        """Persist calibration stats to threshold_path."""
        self.threshold_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.threshold_path, "w", encoding="utf-8") as f:
            json.dump(self.calibration_stats, f, indent=2)
        logger.info("Threshold saved → %s", self.threshold_path)

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, threshold_path: Optional[Path] = None) -> "ThresholdCalibrator":
        """
        Load a previously saved threshold from JSON.

        Returns
        -------
        ThresholdCalibrator
            Instance with .threshold and .calibration_stats populated.
        """
        path = threshold_path or cls.DEFAULT_THRESHOLD_PATH
        if not path.exists():
            raise FileNotFoundError(f"No threshold file found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            stats = json.load(f)

        calibrator = cls(percentile=stats["percentile_used"], threshold_path=path)
        calibrator.threshold = stats["threshold"]
        calibrator.calibration_stats = stats
        logger.info("Threshold loaded from %s: %.6f", path, calibrator.threshold)
        return calibrator
