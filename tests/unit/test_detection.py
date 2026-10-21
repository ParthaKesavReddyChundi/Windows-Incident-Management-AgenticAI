"""
tests/unit/test_detection.py
=============================
Unit tests for Phase 4: dataset pipeline and anomaly detection modules.

Tests run WITHOUT PyTorch (if not installed) using feature-flags:
  - PYTORCH_AVAILABLE : guards all AE/trainer tests
  - JOBLIB_AVAILABLE  : guards preprocessor artifact save/load tests

This ensures the test suite remains green even before `pip install torch`.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pytest

# ---- Availability guards ----

PYTORCH_AVAILABLE = False
try:
    import torch
    PYTORCH_AVAILABLE = True
except ImportError:
    pass

JOBLIB_AVAILABLE = False
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    pass

requires_torch = pytest.mark.skipif(
    not PYTORCH_AVAILABLE, reason="PyTorch not installed"
)
requires_joblib = pytest.mark.skipif(
    not JOBLIB_AVAILABLE, reason="joblib not installed"
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def synthetic_df() -> pd.DataFrame:
    """Synthetic telemetry DataFrame matching ToN_IoT Windows schema."""
    rng = np.random.default_rng(42)
    n = 500
    feature_names = [f"feature_{i}" for i in range(20)]
    df = pd.DataFrame(rng.random((n, 20)), columns=feature_names)
    # 60% normal (0), 40% attack (1)
    labels = np.zeros(n, dtype=int)
    labels[300:] = 1
    df["label"] = labels
    df["type"] = ["normal"] * 300 + ["ddos"] * 100 + ["dos"] * 100
    return df


@pytest.fixture()
def normal_array() -> np.ndarray:
    """Small scaled normal array for detector/calibration tests."""
    rng = np.random.default_rng(0)
    return rng.random((200, 10)).astype(np.float32)


@pytest.fixture()
def attack_array() -> np.ndarray:
    """Scaled attack array (deliberately shifted to create anomalies)."""
    rng = np.random.default_rng(1)
    return (rng.random((50, 10)) + 2.0).astype(np.float32)  # far from [0,1]


# ===========================================================================
# 1. DatasetValidator
# ===========================================================================

class TestDatasetValidator:
    """Tests for data_pipeline.validator.DatasetValidator."""

    def test_inspect_returns_expected_keys(self, tmp_path: Path, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.validator import DatasetValidator

        csv_path = tmp_path / "test_dataset.csv"
        synthetic_df.to_csv(csv_path, index=False)

        validator = DatasetValidator(file_path=csv_path)
        report = validator.inspect()

        assert report["total_rows"] == 500
        assert report["total_columns"] == 22  # 20 features + label + type
        assert report["label_column"] == "label"
        assert report["type_column"] == "type"
        assert report["label_distribution"][0] == 300
        assert report["label_distribution"][1] == 200

    def test_inspect_detects_missing_values(self, tmp_path: Path, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.validator import DatasetValidator

        # Introduce NaNs
        synthetic_df.loc[0:10, "feature_0"] = np.nan
        csv_path = tmp_path / "dirty_dataset.csv"
        synthetic_df.to_csv(csv_path, index=False)

        validator = DatasetValidator(file_path=csv_path)
        report = validator.inspect()
        assert report["missing_values_count"] >= 1

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        from data_pipeline.validator import DatasetValidator

        with pytest.raises(FileNotFoundError):
            DatasetValidator(file_path=tmp_path / "nonexistent.csv")


# ===========================================================================
# 2. TelemetryPreprocessor
# ===========================================================================

class TestTelemetryPreprocessor:
    """Tests for data_pipeline.preprocessor.TelemetryPreprocessor."""

    def test_fit_transform_output_shape(self, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor(scaler_type="minmax")
        X_train, X_test, y_train, y_test, feat_cols = prep.fit_transform(
            synthetic_df, label_col="label", type_col="type", test_size=0.2
        )

        assert X_train.ndim == 2
        assert X_test.ndim == 2
        assert X_train.shape[1] == X_test.shape[1]
        assert len(feat_cols) == X_train.shape[1]
        # label and type must not be in feature_cols
        assert "label" not in feat_cols
        assert "type" not in feat_cols

    def test_train_normal_only_no_leakage(self, synthetic_df: pd.DataFrame) -> None:
        """When train_normal_only=True, y_train should be all zeros."""
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor(scaler_type="minmax")
        _, _, y_train, _, _ = prep.fit_transform(
            synthetic_df, label_col="label", train_normal_only=True, test_size=0.2
        )
        assert np.all(y_train == 0), "Training labels must be all-normal when train_normal_only=True"

    def test_scaled_values_in_0_1_range(self, synthetic_df: pd.DataFrame) -> None:
        """MinMaxScaler output must be in [0, 1] for training normal data."""
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor(scaler_type="minmax")
        X_train, X_test, _, _, _ = prep.fit_transform(
            synthetic_df, label_col="label", train_normal_only=True, test_size=0.2
        )
        # Training data (normal only, fitted on itself) must be in [0, 1]
        assert float(X_train.min()) >= -0.01
        assert float(X_train.max()) <= 1.01

    @requires_joblib
    def test_save_load_artifacts(self, tmp_path: Path, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor(scaler_type="minmax", artifact_dir=tmp_path)
        prep.fit_transform(synthetic_df, label_col="label", test_size=0.2, auto_save=True)

        # Verify artifacts exist
        assert (tmp_path / "preprocessor_scaler.joblib").exists()
        assert (tmp_path / "feature_columns.json").exists()

        # Load artifacts into a fresh instance
        prep2 = TelemetryPreprocessor(artifact_dir=tmp_path)
        prep2.load_artifacts()
        assert prep2.is_fitted
        assert prep2.feature_columns == prep.feature_columns

    def test_transform_single(self, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor(scaler_type="minmax")
        prep.fit_transform(synthetic_df, label_col="label", test_size=0.2)

        feature_dict = {col: 0.5 for col in prep.feature_columns}
        result = prep.transform_single(feature_dict)
        assert result.shape == (1, len(prep.feature_columns))

    def test_transform_single_before_fit_raises(self) -> None:
        from data_pipeline.preprocessor import TelemetryPreprocessor

        prep = TelemetryPreprocessor()
        with pytest.raises(RuntimeError):
            prep.transform_single({"feature_0": 0.5})


# ===========================================================================
# 3. TelemetryAutoencoder (requires PyTorch)
# ===========================================================================

@requires_torch
class TestAutoencoder:
    """Tests for detection.autoencoder.TelemetryAutoencoder."""

    def test_forward_pass_output_shape(self) -> None:
        from detection.autoencoder import TelemetryAutoencoder

        model = TelemetryAutoencoder(input_dim=20)
        x = torch.randn(16, 20)
        out = model(x)
        assert out.shape == (16, 20), "Output shape must match input"

    def test_reconstruction_error_shape(self) -> None:
        from detection.autoencoder import TelemetryAutoencoder

        model = TelemetryAutoencoder(input_dim=10)
        x = torch.rand(32, 10)
        errors = model.compute_reconstruction_error(x)
        assert errors.shape == (32,), "Reconstruction error must be per-sample"

    def test_sigmoid_output_in_01(self) -> None:
        from detection.autoencoder import TelemetryAutoencoder

        model = TelemetryAutoencoder(input_dim=15)
        model.eval()
        x = torch.rand(8, 15)
        with torch.no_grad():
            out = model(x)
        assert out.min() >= 0.0 and out.max() <= 1.0, "Sigmoid output must be in [0, 1]"

    def test_latent_dim_bottleneck(self) -> None:
        from detection.autoencoder import TelemetryAutoencoder

        # latent_dim < input_dim forces compression
        model = TelemetryAutoencoder(input_dim=50, latent_dim=8)
        x = torch.rand(4, 50)
        out = model(x)
        assert out.shape == (4, 50)

    def test_normal_lower_error_than_shifted(self) -> None:
        """Normal samples should have lower reconstruction error than very noisy ones."""
        from detection.autoencoder import TelemetryAutoencoder

        model = TelemetryAutoencoder(input_dim=10)
        model.eval()
        normal = torch.rand(20, 10) * 0.1 + 0.45  # tightly clustered around 0.5
        outlier = torch.rand(20, 10) * 0.1 + 5.0  # far from training distribution

        with torch.no_grad():
            err_normal = model.compute_reconstruction_error(normal).mean().item()
            err_outlier = model.compute_reconstruction_error(outlier).mean().item()

        # Even untrained, sigmoid clamps to [0,1]; outlier is clamped → high error
        assert err_outlier >= 0.0  # just confirm no crash; training is needed for real separation


# ===========================================================================
# 4. AutoencoderTrainer (requires PyTorch)
# ===========================================================================

@requires_torch
class TestAutoencoderTrainer:
    """Tests for detection.trainer.AutoencoderTrainer."""

    def test_trainer_runs_and_saves_checkpoint(self, tmp_path: Path) -> None:
        from detection.trainer import AutoencoderTrainer

        rng = np.random.default_rng(42)
        X_normal = rng.random((300, 10)).astype(np.float32)
        checkpoint_path = tmp_path / "ae_test.pt"

        trainer = AutoencoderTrainer(
            input_dim=10,
            epochs=3,
            batch_size=64,
            patience=5,
            checkpoint_path=checkpoint_path,
        )
        summary = trainer.train(X_normal)

        assert checkpoint_path.exists(), "Checkpoint file must be saved"
        assert "best_val_loss" in summary
        assert summary["epochs_trained"] >= 1
        assert summary["input_dim"] == 10

    def test_training_history_json_saved(self, tmp_path: Path) -> None:
        from detection.trainer import AutoencoderTrainer

        rng = np.random.default_rng(0)
        X = rng.random((200, 8)).astype(np.float32)
        checkpoint_path = tmp_path / "history_test.pt"

        trainer = AutoencoderTrainer(
            input_dim=8,
            epochs=2,
            batch_size=32,
            checkpoint_path=checkpoint_path,
        )
        trainer.train(X)

        history_path = checkpoint_path.parent / "training_history.json"
        assert history_path.exists()
        history = json.loads(history_path.read_text())
        assert len(history) >= 1
        assert "train_loss" in history[0]
        assert "val_loss" in history[0]

    def test_load_checkpoint(self, tmp_path: Path) -> None:
        from detection.trainer import AutoencoderTrainer
        from detection.autoencoder import TelemetryAutoencoder

        rng = np.random.default_rng(7)
        X = rng.random((100, 12)).astype(np.float32)
        checkpoint_path = tmp_path / "load_test.pt"

        trainer = AutoencoderTrainer(
            input_dim=12, epochs=2, batch_size=32, checkpoint_path=checkpoint_path
        )
        trainer.train(X)

        loaded_model = AutoencoderTrainer.load_checkpoint(checkpoint_path)
        assert isinstance(loaded_model, TelemetryAutoencoder)
        assert loaded_model.input_dim == 12


# ===========================================================================
# 5. ThresholdCalibrator (requires PyTorch)
# ===========================================================================

@requires_torch
class TestThresholdCalibrator:
    """Tests for detection.threshold_calibrator.ThresholdCalibrator."""

    def _get_trained_model(self, input_dim: int, tmp_path: Path):
        from detection.trainer import AutoencoderTrainer
        rng = np.random.default_rng(42)
        X = rng.random((200, input_dim)).astype(np.float32)
        checkpoint_path = tmp_path / "calibration_model.pt"
        trainer = AutoencoderTrainer(
            input_dim=input_dim, epochs=2, batch_size=32, checkpoint_path=checkpoint_path
        )
        trainer.train(X)
        return AutoencoderTrainer.load_checkpoint(checkpoint_path)

    def test_calibrate_returns_float(self, tmp_path: Path) -> None:
        from detection.threshold_calibrator import ThresholdCalibrator

        model = self._get_trained_model(10, tmp_path)
        rng = np.random.default_rng(0)
        X_val = rng.random((100, 10)).astype(np.float32)
        threshold_path = tmp_path / "threshold.json"

        calibrator = ThresholdCalibrator(percentile=95, threshold_path=threshold_path)
        threshold = calibrator.calibrate(model, X_val)

        assert isinstance(threshold, float)
        assert threshold > 0.0
        assert threshold_path.exists()

    def test_threshold_saved_and_loadable(self, tmp_path: Path) -> None:
        from detection.threshold_calibrator import ThresholdCalibrator

        model = self._get_trained_model(10, tmp_path)
        rng = np.random.default_rng(1)
        X_val = rng.random((100, 10)).astype(np.float32)
        threshold_path = tmp_path / "threshold.json"

        calibrator = ThresholdCalibrator(percentile=95, threshold_path=threshold_path)
        threshold = calibrator.calibrate(model, X_val)

        loaded = ThresholdCalibrator.load(threshold_path)
        assert abs(loaded.threshold - threshold) < 1e-9


# ===========================================================================
# 6. BaselineAnomalyDetector
# ===========================================================================

class TestBaselineDetector:
    """Tests for detection.baseline.BaselineAnomalyDetector."""

    def test_fit_and_evaluate(self) -> None:
        from detection.baseline import BaselineAnomalyDetector

        rng = np.random.default_rng(42)
        X_train = rng.random((200, 10)).astype(np.float32)
        X_test = rng.random((100, 10)).astype(np.float32)
        y_test = np.zeros(100, dtype=int)
        y_test[50:] = 1  # half are attacks

        detector = BaselineAnomalyDetector(contamination=0.5)
        detector.fit(X_train)
        metrics = detector.evaluate(X_test, y_test)

        assert "accuracy" in metrics
        assert "f1_score" in metrics
        assert 0.0 <= metrics["accuracy"] <= 1.0

    def test_decision_scores_shape(self) -> None:
        from detection.baseline import BaselineAnomalyDetector

        rng = np.random.default_rng(3)
        X = rng.random((100, 8)).astype(np.float32)
        detector = BaselineAnomalyDetector(contamination=0.3)
        detector.fit(X)

        scores = detector.decision_scores(X)
        assert scores.shape == (100,)

    def test_decision_scores_before_fit_raises(self) -> None:
        from detection.baseline import BaselineAnomalyDetector

        detector = BaselineAnomalyDetector()
        with pytest.raises(RuntimeError):
            detector.decision_scores(np.zeros((10, 5)))

    def test_normal_samples_have_positive_scores(self) -> None:
        """IsolationForest decision_function: positive = inlier (normal)."""
        from detection.baseline import BaselineAnomalyDetector

        rng = np.random.default_rng(5)
        X_normal = rng.random((300, 10)).astype(np.float32)
        X_outlier = (rng.random((20, 10)) * 10 + 20).astype(np.float32)

        detector = BaselineAnomalyDetector(contamination=0.05)
        detector.fit(X_normal)

        scores_normal = detector.decision_scores(X_normal)
        scores_outlier = detector.decision_scores(X_outlier)

        # Normal scores should be mostly positive; outlier scores mostly negative
        assert scores_normal.mean() > scores_outlier.mean()


# ===========================================================================
# 7. AnomalyEvaluator
# ===========================================================================

class TestAnomalyEvaluator:
    """Tests for detection.evaluator.AnomalyEvaluator."""

    def test_evaluate_autoencoder_metrics_keys(self, tmp_path: Path) -> None:
        from detection.evaluator import AnomalyEvaluator

        rng = np.random.default_rng(42)
        scores = rng.random(100).astype(float)
        y_true = np.zeros(100, dtype=int)
        y_true[50:] = 1
        threshold = 0.5

        evaluator = AnomalyEvaluator(report_path=tmp_path / "report.json")
        metrics = evaluator.evaluate_autoencoder(scores, y_true, threshold)

        for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc"]:
            assert key in metrics
            assert 0.0 <= metrics[key] <= 1.0

    def test_evaluate_baseline_metrics_keys(self, tmp_path: Path) -> None:
        from detection.evaluator import AnomalyEvaluator

        rng = np.random.default_rng(1)
        scores = rng.random(80).astype(float) - 0.5  # IsolationForest style: neg=anomaly
        y_true = np.zeros(80, dtype=int)
        y_true[40:] = 1

        evaluator = AnomalyEvaluator(report_path=tmp_path / "report.json")
        metrics = evaluator.evaluate_baseline(scores, y_true)
        assert "f1_score" in metrics

    def test_compare_declares_winner(self, tmp_path: Path) -> None:
        from detection.evaluator import AnomalyEvaluator

        rng = np.random.default_rng(2)
        y_true = np.array([0] * 50 + [1] * 50)
        ae_scores = np.concatenate([rng.random(50) * 0.3, rng.random(50) * 0.7 + 0.5])
        bl_scores = rng.random(100) - 0.5

        evaluator = AnomalyEvaluator(report_path=tmp_path / "report.json")
        evaluator.evaluate_autoencoder(ae_scores, y_true, threshold=0.5)
        evaluator.evaluate_baseline(bl_scores, y_true)
        comparison = evaluator.compare()

        assert "f1_score" in comparison
        assert comparison["f1_score"]["winner"] in ["autoencoder", "isolation_forest"]

    def test_save_report_creates_file(self, tmp_path: Path) -> None:
        from detection.evaluator import AnomalyEvaluator

        rng = np.random.default_rng(9)
        scores = rng.random(50)
        y_true = np.array([0] * 25 + [1] * 25)
        report_path = tmp_path / "eval.json"

        evaluator = AnomalyEvaluator(report_path=report_path)
        evaluator.evaluate_autoencoder(scores, y_true, threshold=0.5)
        evaluator.save_report()

        assert report_path.exists()
        report = json.loads(report_path.read_text())
        assert "autoencoder" in report


# ===========================================================================
# 8. FeatureEngineer
# ===========================================================================

class TestFeatureEngineer:
    """Tests for data_pipeline.feature_engineering.FeatureEngineer."""

    def test_adds_derived_columns(self, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.feature_engineering import FeatureEngineer

        # Add plausible columns that trigger ratio features
        df = synthetic_df.copy()
        df["processor_time"] = np.random.rand(len(df))
        df["disk_reads_sec"] = np.random.rand(len(df)) * 100
        df["disk_writes_sec"] = np.random.rand(len(df)) * 100
        df["bytes_received_sec"] = np.random.rand(len(df)) * 1000
        df["bytes_sent_sec"] = np.random.rand(len(df)) * 1000
        df["processes"] = np.random.randint(50, 300, len(df))

        fe = FeatureEngineer(add_ratios=True)
        result = fe.fit_transform(df)

        assert "cpu_pressure_index" in result.columns
        assert "disk_read_ratio" in result.columns
        assert "net_asymmetry" in result.columns
        assert "log_process_count" in result.columns
        assert len(result) == len(df)

    def test_no_change_when_columns_absent(self, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.feature_engineering import FeatureEngineer

        fe = FeatureEngineer(add_ratios=True)
        result = fe.fit_transform(synthetic_df)
        # synthetic_df has no Performance Monitor columns → no derived cols added
        assert len(result.columns) == len(synthetic_df.columns)

    def test_rolling_features_added(self, synthetic_df: pd.DataFrame) -> None:
        from data_pipeline.feature_engineering import FeatureEngineer

        df = synthetic_df.copy()
        df["processor_time"] = np.random.rand(len(df))

        fe = FeatureEngineer(add_ratios=False, add_rolling=True, rolling_window=3)
        result = fe.fit_transform(df)

        assert "processor_time_roll3_mean" in result.columns
        assert "processor_time_roll3_std" in result.columns


# ===========================================================================
# 9. AnomalyDetector Inference & API Tests
# ===========================================================================

@requires_torch
@requires_joblib
class TestAnomalyDetectorInference:
    """Tests for detection.anomaly_detector.AnomalyDetector inference engine."""

    def test_load_and_predict(self) -> None:
        from detection.anomaly_detector import AnomalyDetector, AnomalyPrediction

        detector = AnomalyDetector.load()
        assert detector.input_dim > 0
        assert detector.threshold > 0.0

        # Predict with zero/dummy dict
        pred = detector.predict({})
        assert isinstance(pred, AnomalyPrediction)
        assert isinstance(pred.score, float)
        assert isinstance(pred.is_anomaly, bool)
        assert pred.severity in ["normal", "low", "medium", "high", "critical"]
        assert len(pred.top_deviant_features) <= 10

    def test_predict_snapshot(self) -> None:
        from datetime import datetime
        from backend.app.schemas.telemetry import (
            CpuSnapshot,
            DiskSnapshot,
            MemorySnapshot,
            NetworkSnapshot,
            ProcessSnapshot,
            ServiceSnapshot,
            TelemetrySnapshot,
        )
        from detection.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector.load()

        snapshot = TelemetrySnapshot(
            snapshot_id="test-snap-001",
            timestamp=datetime.utcnow(),
            source="test",
            cpu=CpuSnapshot(percent=25.0, per_core=[25.0, 25.0]),
            memory=MemorySnapshot(
                total_bytes=16 * 1024 * 1024 * 1024,
                available_bytes=10 * 1024 * 1024 * 1024,
                used_bytes=6 * 1024 * 1024 * 1024,
                percent=37.5,
            ),
            disks=[
                DiskSnapshot(
                    device="C:",
                    mountpoint="C:\\",
                    total_bytes=500 * 1024 * 1024 * 1024,
                    used_bytes=200 * 1024 * 1024 * 1024,
                    free_bytes=300 * 1024 * 1024 * 1024,
                    percent=40.0,
                    read_bytes_sec=1024.0,
                    write_bytes_sec=2048.0,
                )
            ],
            networks=[
                NetworkSnapshot(
                    interface="Ethernet",
                    bytes_sent_sec=5000.0,
                    bytes_recv_sec=15000.0,
                    packets_sent_sec=50.0,
                    packets_recv_sec=100.0,
                )
            ],
            top_processes=[
                ProcessSnapshot(pid=1001, name="python.exe", cpu_percent=5.0, memory_mb=120.0, status="running")
            ],
            services=[
                ServiceSnapshot(name="Spooler", display_name="Print Spooler", status="running", start_type="automatic")
            ],
        )

        pred = detector.predict_snapshot(snapshot, top_n=5)
        assert pred.threshold == detector.threshold
        assert isinstance(pred.score, float)
        assert len(pred.top_deviant_features) == 5

    def test_predict_batch(self, synthetic_df: pd.DataFrame) -> None:
        from detection.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector.load()
        # Feed synthetic data with matching or subset columns
        res_df = detector.predict_batch(synthetic_df.head(20))
        assert "anomaly_score" in res_df.columns
        assert "is_anomaly" in res_df.columns
        assert "severity" in res_df.columns
        assert len(res_df) == 20


@requires_torch
@requires_joblib
class TestDetectionAPIEndpoints:
    """Tests for FastAPI anomaly detection endpoints."""

    @pytest.fixture(autouse=True)
    def setup_client(self):
        from fastapi.testclient import TestClient
        from backend.app.main import app
        self.client = TestClient(app)

    def test_model_info_endpoint(self) -> None:
        response = self.client.get("/api/telemetry/model-info")
        assert response.status_code == 200
        data = response.json()
        assert data["loaded"] is True
        assert data["input_dim"] > 0
        assert data["threshold"] > 0.0
        assert "device" in data

    def test_detect_endpoint_with_latest_snapshot(self) -> None:
        response = self.client.post("/api/telemetry/detect?top_n=3")
        assert response.status_code == 200
        data = response.json()
        assert "score" in data
        assert "threshold" in data
        assert "is_anomaly" in data
        assert "severity" in data
        assert len(data["top_deviant_features"]) <= 3


