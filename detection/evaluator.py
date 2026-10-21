"""
detection/evaluator.py
======================
Evaluation metrics for the autoencoder anomaly detector vs. ground truth labels.

Computes:
- Accuracy, Precision, Recall, F1-Score
- ROC-AUC (area under ROC curve)
- PR-AUC  (area under Precision-Recall curve)
- Confusion matrix
- Attack-type breakdown (precision/recall per attack category)

Also compares AE performance against the IsolationForest baseline.
Results are saved to models/evaluation_report.json.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

from config.settings import settings

logger = logging.getLogger(__name__)

EVAL_REPORT_PATH = settings.model_path.parent / "evaluation_report.json"


# ---------------------------------------------------------------------------

def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray) -> dict:
    """Compute standard binary classification metrics."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, cm[0, 0])

    try:
        roc_auc = float(roc_auc_score(y_true, y_score))
    except ValueError:
        roc_auc = 0.0

    try:
        pr_auc = float(average_precision_score(y_true, y_score))
    except ValueError:
        pr_auc = 0.0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
        "total_samples": int(len(y_true)),
        "true_anomalies": int(y_true.sum()),
        "predicted_anomalies": int(y_pred.sum()),
    }


# ---------------------------------------------------------------------------

class AnomalyEvaluator:
    """
    Evaluates anomaly detection performance against ground-truth labels.

    Parameters
    ----------
    report_path : Path | None
        Where to save the JSON report. Defaults to models/evaluation_report.json.
    """

    def __init__(self, report_path: Optional[Path] = None) -> None:
        self.report_path = report_path or EVAL_REPORT_PATH
        self.report: dict = {}

    # ------------------------------------------------------------------
    def evaluate_autoencoder(
        self,
        scores: np.ndarray,
        y_true: np.ndarray,
        threshold: float,
        attack_types: Optional[np.ndarray] = None,
    ) -> dict:
        """
        Evaluate autoencoder predictions.

        Parameters
        ----------
        scores : np.ndarray
            Reconstruction error per sample (float).
        y_true : np.ndarray
            Ground-truth binary labels (0=normal, 1=attack).
        threshold : float
            Decision boundary; score > threshold → anomaly.
        attack_types : np.ndarray | None
            String array of attack category per sample (for breakdown table).

        Returns
        -------
        dict
            Evaluation report section for the autoencoder.
        """
        y_pred = (scores > threshold).astype(int)
        metrics = _binary_metrics(y_true, y_pred, scores)
        metrics["threshold"] = threshold

        # Per-attack-type breakdown
        if attack_types is not None:
            breakdown = self._attack_type_breakdown(y_true, y_pred, scores, attack_types)
            metrics["attack_type_breakdown"] = breakdown

        self.report["autoencoder"] = metrics
        logger.info(
            "AE Evaluation — Acc=%.3f  P=%.3f  R=%.3f  F1=%.3f  ROC-AUC=%.3f  PR-AUC=%.3f",
            metrics["accuracy"],
            metrics["precision"],
            metrics["recall"],
            metrics["f1_score"],
            metrics["roc_auc"],
            metrics["pr_auc"],
        )
        return metrics

    # ------------------------------------------------------------------
    def evaluate_baseline(
        self,
        baseline_scores: np.ndarray,
        y_true: np.ndarray,
    ) -> dict:
        """
        Evaluate IsolationForest baseline.
        IsolationForest returns -1 for anomaly, 1 for normal.
        We convert: anomaly = (raw_pred == -1) → binary 1.
        Negative scores (more anomalous) are used as the ranking score.

        Parameters
        ----------
        baseline_scores : np.ndarray
            Raw IsolationForest decision_function output.
        y_true : np.ndarray
            Ground-truth binary labels.
        """
        y_pred = (baseline_scores < 0).astype(int)
        # Invert sign so higher value → more anomalous (matches convention)
        ranking_score = -baseline_scores
        metrics = _binary_metrics(y_true, y_pred, ranking_score)

        self.report["isolation_forest_baseline"] = metrics
        logger.info(
            "IF  Evaluation — Acc=%.3f  P=%.3f  R=%.3f  F1=%.3f  ROC-AUC=%.3f",
            metrics["accuracy"],
            metrics["precision"],
            metrics["recall"],
            metrics["f1_score"],
            metrics["roc_auc"],
        )
        return metrics

    # ------------------------------------------------------------------
    def compare(self) -> dict:
        """
        Compare autoencoder vs baseline and flag which is better on each metric.

        Returns
        -------
        dict
            Comparison table keyed by metric name.
        """
        if "autoencoder" not in self.report or "isolation_forest_baseline" not in self.report:
            raise RuntimeError("Run evaluate_autoencoder and evaluate_baseline first.")

        ae = self.report["autoencoder"]
        bl = self.report["isolation_forest_baseline"]
        metrics_to_compare = ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc"]

        comparison = {}
        for m in metrics_to_compare:
            ae_val = ae.get(m, 0.0)
            bl_val = bl.get(m, 0.0)
            comparison[m] = {
                "autoencoder": round(ae_val, 4),
                "isolation_forest": round(bl_val, 4),
                "winner": "autoencoder" if ae_val >= bl_val else "isolation_forest",
                "delta": round(ae_val - bl_val, 4),
            }

        self.report["comparison"] = comparison

        ae_wins = sum(1 for v in comparison.values() if v["winner"] == "autoencoder")
        logger.info(
            "Comparison: AE wins %d/%d metrics vs IsolationForest baseline.",
            ae_wins,
            len(metrics_to_compare),
        )
        return comparison

    # ------------------------------------------------------------------
    def save_report(self) -> Path:
        """Persist evaluation report to JSON."""
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2)
        logger.info("Evaluation report saved → %s", self.report_path)
        return self.report_path

    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        """Print a human-readable summary table to stdout."""
        print("\n" + "=" * 65)
        print("  ANOMALY DETECTION EVALUATION SUMMARY")
        print("=" * 65)

        for model_name, section_key in [
            ("Autoencoder (AE)", "autoencoder"),
            ("IsolationForest  ", "isolation_forest_baseline"),
        ]:
            if section_key not in self.report:
                continue
            m = self.report[section_key]
            print(f"\n  {model_name}")
            print(f"    Accuracy  : {m.get('accuracy', 0):.4f}")
            print(f"    Precision : {m.get('precision', 0):.4f}")
            print(f"    Recall    : {m.get('recall', 0):.4f}")
            print(f"    F1-Score  : {m.get('f1_score', 0):.4f}")
            print(f"    ROC-AUC   : {m.get('roc_auc', 0):.4f}")
            print(f"    PR-AUC    : {m.get('pr_auc', 0):.4f}")
            cm = m.get("confusion_matrix", {})
            print(f"    Confusion : TN={cm.get('tn',0)}  FP={cm.get('fp',0)}  "
                  f"FN={cm.get('fn',0)}  TP={cm.get('tp',0)}")

        if "comparison" in self.report:
            print("\n  Comparison (AE vs IsolationForest):")
            for metric, vals in self.report["comparison"].items():
                delta_str = f"{vals['delta']:+.4f}"
                winner_tag = "[AE]" if vals["winner"] == "autoencoder" else "[IF]"
                print(
                    f"    {metric:12s}  AE={vals['autoencoder']:.4f}  "
                    f"IF={vals['isolation_forest']:.4f}  "
                    f"Diff={delta_str}  {winner_tag}"
                )

        print("=" * 65 + "\n")

    # ------------------------------------------------------------------
    @staticmethod
    def _attack_type_breakdown(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        scores: np.ndarray,
        attack_types: np.ndarray,
    ) -> list[dict]:
        """Compute per-attack-type precision, recall, F1, and sample count."""
        unique_types = np.unique(attack_types)
        rows = []
        for atype in unique_types:
            mask = attack_types == atype
            yt = y_true[mask]
            yp = y_pred[mask]
            rows.append(
                {
                    "attack_type": str(atype),
                    "n_samples": int(mask.sum()),
                    "n_attacks": int(yt.sum()),
                    "precision": float(precision_score(yt, yp, zero_division=0)),
                    "recall": float(recall_score(yt, yp, zero_division=0)),
                    "f1_score": float(f1_score(yt, yp, zero_division=0)),
                }
            )
        rows.sort(key=lambda r: r["n_samples"], reverse=True)
        return rows
