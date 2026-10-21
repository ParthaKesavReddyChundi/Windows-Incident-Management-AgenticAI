"""
Data Preprocessor and Feature Pipeline for Windows Telemetry Anomaly Detection.

Ensures:
- No data leakage: fit transformations (imputers, scalers) strictly on training normal data.
- Feature alignment: aligns both dataset CSV rows and live psutil/collector snapshots.
- Clean serialization: saves fitted scaler parameters for runtime inference.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler

logger = logging.getLogger(__name__)


class TelemetryPreprocessor:
    """Preprocesses tabular Windows performance telemetry for Deep Learning models."""

    def __init__(
        self,
        scaler_type: str = "minmax",
        artifact_dir: Optional[Path] = None,
    ) -> None:
        self.scaler_type = scaler_type
        self.scaler = MinMaxScaler() if scaler_type == "minmax" else StandardScaler()
        self.feature_columns: List[str] = []
        self.artifact_dir = artifact_dir or (Path(__file__).resolve().parent.parent / "models")
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.is_fitted = False

    def fit_transform(
        self,
        df: pd.DataFrame,
        label_col: str = "label",
        type_col: str = "type",
        train_normal_only: bool = True,
        test_size: float = 0.2,
        random_state: int = 42,
        auto_save: bool = False,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Fits scaler on normal training samples (unsupervised anomaly detection paradigm)
        and transforms both train and test partitions.
        """
        # Exclude non-feature identifier / target columns
        cols_to_drop = [c for c in [label_col, type_col, "ts", "timestamp"] if c in df.columns]
        X = df.drop(columns=cols_to_drop)
        y = df[label_col] if label_col in df.columns else np.zeros(len(df))

        # Filter strictly numeric features
        numeric_df = X.select_dtypes(include=[np.number])
        # Drop columns with zero variance (constants)
        std_series = numeric_df.std()
        valid_cols = std_series[std_series > 1e-6].index.tolist()
        self.feature_columns = valid_cols

        X_numeric = numeric_df[valid_cols].fillna(0.0)

        # Train/test split with stratification on label if available
        X_train, X_test, y_train, y_test = train_test_split(
            X_numeric, y, test_size=test_size, random_state=random_state, stratify=y if len(np.unique(y)) > 1 else None
        )

        if train_normal_only and label_col in df.columns:
            # Semi-supervised / One-class Autoencoder training setup:
            # Autoencoder learns patterns of NORMAL (label=0) data only.
            normal_mask = (y_train == 0)
            X_train_fit = X_train[normal_mask]
        else:
            X_train_fit = X_train

        # Fit strictly on train
        self.scaler.fit(X_train_fit)
        self.is_fitted = True

        X_train_scaled = self.scaler.transform(X_train if not train_normal_only else X_train[y_train == 0])
        X_test_scaled = self.scaler.transform(X_test)
        y_train_out = y_train.values if not train_normal_only else y_train[y_train == 0].values
        y_test_out = y_test.values

        # Save preprocessing artifacts if requested
        if auto_save:
            self.save_artifacts()

        logger.info(
            "Preprocessor fitted: %d features selected, %d train rows, %d test rows",
            len(self.feature_columns),
            len(X_train_scaled),
            len(X_test_scaled),
        )
        return (
            X_train_scaled.astype(np.float32),
            X_test_scaled.astype(np.float32),
            y_train_out,
            y_test_out,
            self.feature_columns,
        )

    def transform_single(self, feature_dict: Dict[str, float]) -> np.ndarray:
        """Transforms a single feature map vector (e.g. from live telemetry)."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted or loaded before transforming new samples")

        row = [feature_dict.get(c, 0.0) for c in self.feature_columns]
        arr = np.array([row], dtype=np.float32)
        return self.scaler.transform(arr).astype(np.float32)

    def save_artifacts(self) -> None:
        scaler_file = self.artifact_dir / "preprocessor_scaler.joblib"
        cols_file = self.artifact_dir / "feature_columns.json"

        joblib.dump(self.scaler, scaler_file)
        with open(cols_file, "w", encoding="utf-8") as f:
            json.dump(self.feature_columns, f, indent=2)

    def load_artifacts(self) -> None:
        scaler_file = self.artifact_dir / "preprocessor_scaler.joblib"
        cols_file = self.artifact_dir / "feature_columns.json"

        if not scaler_file.exists() or not cols_file.exists():
            raise FileNotFoundError("Preprocessor artifacts not found in " + str(self.artifact_dir))

        self.scaler = joblib.load(scaler_file)
        with open(cols_file, "r", encoding="utf-8") as f:
            self.feature_columns = json.load(f)
        self.is_fitted = True
