"""
Baseline Anomaly Detection Models for Comparative Evaluation.

Implements standard benchmark models (Isolation Forest & One-Class SVM)
to compare against the PyTorch Autoencoder.
"""
from __future__ import annotations

import logging
from typing import Dict, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

logger = logging.getLogger(__name__)


class BaselineAnomalyDetector:
    """Isolation Forest anomaly detection baseline."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42) -> None:
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit(self, X_train: np.ndarray) -> None:
        self.model.fit(X_train)
        self.is_fitted = True

    def predict_score(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            scores: normalized anomaly score in [0, 1] (higher = more anomalous)
            preds: binary flags (1 for anomaly, 0 for normal)
        """
        # score_samples returns opposite of anomaly score (lower is more abnormal)
        raw_scores = -self.model.score_samples(X)
        min_s, max_s = raw_scores.min(), raw_scores.max()
        norm_scores = (raw_scores - min_s) / (max_s - min_s + 1e-8)

        # In sklearn, -1 is anomaly, 1 is inlier/normal
        raw_preds = self.model.predict(X)
        preds = np.where(raw_preds == -1, 1, 0)
        return norm_scores, preds

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """Calculates standard classification metrics."""
        scores, preds = self.predict_score(X_test)
        metrics = {
            "accuracy": float(accuracy_score(y_test, preds)),
            "precision": float(precision_score(y_test, preds, zero_division=0)),
            "recall": float(recall_score(y_test, preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, preds, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, scores)) if len(np.unique(y_test)) > 1 else 0.0,
        }
        return metrics

    def decision_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Return raw IsolationForest decision_function output.
        Negative values indicate anomalies (more negative = more anomalous).
        Used by AnomalyEvaluator.evaluate_baseline().
        """
        if not self.is_fitted:
            raise RuntimeError("BaselineAnomalyDetector must be fitted before scoring.")
        return self.model.decision_function(X)
