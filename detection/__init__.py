"""
detection package — autoencoder-based anomaly detection for Windows telemetry.

Modules:
    autoencoder   : TelemetryAutoencoder (PyTorch nn.Module)
    trainer       : Training loop with early stopping
    threshold_calibrator : Calibrates detection threshold on normal holdout
    anomaly_detector     : Inference wrapper (load artifacts, score live data)
    evaluator     : Evaluation metrics (Accuracy, Precision, Recall, F1, AUC)
    baseline      : IsolationForest baseline for comparison
"""

from detection.autoencoder import TelemetryAutoencoder
from detection.baseline import BaselineAnomalyDetector

__all__ = ["TelemetryAutoencoder", "BaselineAnomalyDetector"]
