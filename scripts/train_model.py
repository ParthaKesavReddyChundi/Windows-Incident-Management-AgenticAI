#!/usr/bin/env python3
"""
scripts/train_model.py
======================
CLI entry point for end-to-end autoencoder training pipeline.

Steps
-----
1.  Validate the raw dataset (schema + label distribution).
2.  Load and preprocess: fit MinMaxScaler on normal-only train split.
3.  Train TelemetryAutoencoder on GPU (or CPU fallback).
4.  Calibrate anomaly threshold on held-out normal validation data.
5.  Evaluate on full test set (autoencoder + IsolationForest baseline).
6.  Save all artifacts:
        models/autoencoder.pt
        models/preprocessor_scaler.joblib
        models/feature_columns.json
        models/anomaly_threshold.json
        models/training_history.json
        models/evaluation_report.json
7.  Print a human-readable summary.

Usage
-----
    python scripts/train_model.py
    python scripts/train_model.py --dataset windows10
    python scripts/train_model.py --epochs 100 --lr 5e-4 --percentile 99

Arguments
---------
    --dataset    : windows10 | windows7 | both  (default: windows10)
    --epochs     : Maximum training epochs      (default: 80)
    --batch      : Batch size                   (default: 256)
    --lr         : Initial learning rate        (default: 0.001)
    --patience   : Early stopping patience      (default: 12)
    --percentile : Threshold percentile [50-100] (default: 95)
    --test-frac  : Fraction used for test set   (default: 0.2)
    --val-frac   : Fraction of normal for val   (default: 0.1)
    --seed       : Random seed                  (default: 42)
    --skip-baseline : Skip IsolationForest baseline evaluation
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import settings
from data_pipeline.validator import DatasetValidator
from data_pipeline.preprocessor import TelemetryPreprocessor
from detection.autoencoder import TelemetryAutoencoder
from detection.trainer import AutoencoderTrainer
from detection.threshold_calibrator import ThresholdCalibrator
from detection.evaluator import AnomalyEvaluator
from detection.baseline import BaselineAnomalyDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_model")


# ---------------------------------------------------------------------------
# Dataset paths
# ---------------------------------------------------------------------------

DATASET_PATHS = {
    "windows10": settings.data_raw_dir / "train_test" / "Train_Test_Windows_10.csv",
    "windows7":  settings.data_raw_dir / "train_test" / "Train_Test_Windows_7.csv",
}

LABEL_COL = "label"
TYPE_COL = "type"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_dataset(dataset_name: str) -> pd.DataFrame:
    path = DATASET_PATHS[dataset_name]
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    logger.info("Loading dataset: %s  (%s)", dataset_name, path)
    df = pd.read_csv(path, low_memory=False)
    logger.info("Loaded %d rows × %d columns", len(df), len(df.columns))
    return df


def _validate(path: Path) -> None:
    validator = DatasetValidator(file_path=path)
    report = validator.inspect()
    logger.info(
        "Validation — file=%s  rows=%d  cols=%d  label_col=%s  missing_with_values=%d",
        report.get("file"),
        report.get("total_rows"),
        report.get("total_columns"),
        report.get("label_column"),
        report.get("missing_values_count", 0),
    )
    label_dist = report.get("label_distribution", {})
    logger.info("Label distribution: %s", label_dist)


def _split_data(
    df: pd.DataFrame,
    test_frac: float,
    seed: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified train/test split on the label column (used for metadata only)."""
    from sklearn.model_selection import train_test_split as _skl_split
    train_df, test_df = _skl_split(
        df,
        test_size=test_frac,
        stratify=df[LABEL_COL],
        random_state=seed,
    )
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_training_pipeline(args: argparse.Namespace) -> None:
    t_start = time.time()

    # ---- 1. Load ----
    df = _load_dataset(args.dataset)

    # ---- 2. Validate ----
    _validate(DATASET_PATHS[args.dataset])

    # ---- 3. Preprocess (fit on normal training data only, split internally) ----
    logger.info("Fitting preprocessor on normal training samples only (label=0)...")
    preprocessor = TelemetryPreprocessor(scaler_type="minmax")
    # fit_transform returns: X_train_scaled, X_test_scaled, y_train, y_test, feature_cols
    X_train_normal, X_test_scaled, y_train_normal, y_test, feature_cols = preprocessor.fit_transform(
        df,
        label_col=LABEL_COL,
        type_col=TYPE_COL,
        train_normal_only=True,
        test_size=args.test_frac,
        random_state=args.seed,
        auto_save=True,
    )
    input_dim = X_train_normal.shape[1]
    logger.info(
        "Normal training samples: %d  |  feature_dim: %d  |  test samples: %d",
        len(X_train_normal),
        input_dim,
        len(X_test_scaled),
    )

    # ---- 4. Train autoencoder ----
    trainer = AutoencoderTrainer(
        input_dim=input_dim,
        epochs=args.epochs,
        batch_size=args.batch,
        lr=args.lr,
        patience=args.patience,
        val_fraction=args.val_frac,
    )
    summary = trainer.train(X_train_normal)
    logger.info("Training summary: %s", summary)

    # ---- 5. Calibrate threshold on held-out portion of normal train ----
    logger.info("Calibrating anomaly threshold (percentile=%.0f)...", args.percentile)
    # Use last 10% of normal train as calibration holdout (already scaled by preprocessor)
    n_cal = max(50, int(len(X_train_normal) * 0.10))
    X_cal = X_train_normal[-n_cal:]
    model = AutoencoderTrainer.load_checkpoint()
    calibrator = ThresholdCalibrator(percentile=args.percentile)
    threshold = calibrator.calibrate(model, X_cal)
    logger.info("Threshold set to %.6f", threshold)

    # ---- 6. Get attack types for test breakdown ----
    # Re-load df to extract attack_types aligned with the test split
    # (preprocessor does stratified split internally; we approximate with same seed)
    _, test_df_raw = _split_data(df, test_frac=args.test_frac, seed=args.seed)
    attack_types = test_df_raw[TYPE_COL].values if TYPE_COL in test_df_raw.columns else None

    # ---- 7. Autoencoder inference on test set ----
    import torch
    device = next(model.parameters()).device
    model.eval()
    all_scores: list[float] = []

    with torch.no_grad():
        for start in range(0, len(X_test_scaled), args.batch):
            batch = torch.tensor(
                X_test_scaled[start : start + args.batch], dtype=torch.float32
            ).to(device)
            recon = model(batch)
            mse = ((recon - batch) ** 2).mean(dim=1).cpu().numpy()
            all_scores.extend(mse.tolist())

    ae_scores = np.array(all_scores)

    # ---- 8. Evaluate autoencoder ----
    evaluator = AnomalyEvaluator()
    evaluator.evaluate_autoencoder(ae_scores, y_test, threshold, attack_types)

    # ---- 9. Baseline (IsolationForest) ----
    if not args.skip_baseline:
        logger.info("Training IsolationForest baseline on normal train data...")
        baseline = BaselineAnomalyDetector(contamination=0.5)
        baseline.fit(X_train_normal)
        bl_scores = baseline.decision_scores(X_test_scaled)
        evaluator.evaluate_baseline(bl_scores, y_test)
        evaluator.compare()

    # ---- 10. Save report & print summary ----
    evaluator.save_report()
    evaluator.print_summary()

    elapsed = time.time() - t_start
    logger.info(
        "Pipeline complete in %.1f seconds. Artifacts saved to: %s",
        elapsed,
        settings.model_path.parent,
    )
    print(f"\n[SUCCESS] All artifacts saved to: {settings.model_path.parent}")
    print(f"   Threshold : {threshold:.6f}")
    print(f"   Report    : {evaluator.report_path}")
    print(f"   Model     : {settings.model_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train TelemetryAutoencoder for Windows anomaly detection."
    )
    parser.add_argument(
        "--dataset",
        choices=["windows10", "windows7"],
        default="windows10",
        help="Which dataset to train on (default: windows10)",
    )
    parser.add_argument("--epochs",    type=int,   default=80,    help="Max epochs (default 80)")
    parser.add_argument("--batch",     type=int,   default=256,   help="Batch size (default 256)")
    parser.add_argument("--lr",        type=float, default=1e-3,  help="Learning rate (default 1e-3)")
    parser.add_argument("--patience",  type=int,   default=12,    help="Early stopping patience (default 12)")
    parser.add_argument("--percentile",type=float, default=95.0,  help="Threshold percentile (default 95)")
    parser.add_argument("--test-frac", type=float, default=0.20,  help="Test fraction (default 0.20)")
    parser.add_argument("--val-frac",  type=float, default=0.10,  help="Validation fraction of normal (default 0.10)")
    parser.add_argument("--seed",      type=int,   default=42,    help="Random seed (default 42)")
    parser.add_argument(
        "--skip-baseline",
        action="store_true",
        help="Skip IsolationForest baseline evaluation",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_training_pipeline(args)
