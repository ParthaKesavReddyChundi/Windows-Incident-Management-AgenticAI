"""
data_pipeline/feature_engineering.py
=====================================
Optional feature engineering applied after raw telemetry normalization.

Currently computes:
- Memory utilization ratio  : memory_used / memory_total
- CPU pressure index        : derived composite CPU load signal
- Disk queue saturation     : normalized disk queue vs throughput ratio
- Process count tier        : binned log-scale process count
- Rolling statistics        : mean and std of a sliding window (for batch data)

In the live system, only instantaneous features are used (no rolling stats),
since we receive one snapshot at a time from the CollectorManager.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Column name constants (matching ToN_IoT Windows dataset feature names)
# These are derived from Windows Performance Monitor counter naming.
# ---------------------------------------------------------------------------

# Adjust these to match exact column names in your dataset if needed.
_PROC_TIME_COL = "processor_time"
_MEM_AVAIL_COL = "available_mbytes"
_DISK_READ_COL = "disk_reads_sec"
_DISK_WRITE_COL = "disk_writes_sec"
_DISK_QUEUE_COL = "avg_disk_queue_length"
_NET_RECV_COL = "bytes_received_sec"
_NET_SENT_COL = "bytes_sent_sec"
_PROC_COUNT_COL = "processes"


# ---------------------------------------------------------------------------

class FeatureEngineer:
    """
    Adds derived features to a telemetry DataFrame.

    Designed to be applied BEFORE the MinMaxScaler in the preprocessing pipeline
    so the scaler can include the derived features.

    Parameters
    ----------
    add_ratios : bool
        Add derived ratio features (memory util, CPU pressure).
    add_rolling : bool
        Add rolling window statistics (only useful for batch/sequential data).
    rolling_window : int
        Number of samples in the rolling window.
    """

    def __init__(
        self,
        add_ratios: bool = True,
        add_rolling: bool = False,
        rolling_window: int = 5,
    ) -> None:
        self.add_ratios = add_ratios
        self.add_rolling = add_rolling
        self.rolling_window = rolling_window
        self._derived_columns: list[str] = []

    # ------------------------------------------------------------------
    def fit(self, df: pd.DataFrame) -> "FeatureEngineer":
        """Fit (currently stateless — kept for sklearn-compatible API)."""
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply feature engineering and return augmented DataFrame."""
        result = df.copy()
        self._derived_columns = []

        if self.add_ratios:
            result = self._add_ratio_features(result)

        if self.add_rolling:
            result = self._add_rolling_features(result)

        logger.debug(
            "FeatureEngineer added %d derived columns: %s",
            len(self._derived_columns),
            self._derived_columns,
        )
        return result

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one step."""
        return self.fit(df).transform(df)

    # ------------------------------------------------------------------
    @property
    def derived_columns(self) -> list[str]:
        """List of derived feature column names added by the last transform()."""
        return list(self._derived_columns)

    # ------------------------------------------------------------------
    def _add_ratio_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add ratio-based derived features where source columns exist."""

        # CPU pressure: processor_time already in [0,1] range (raw % / 100).
        # We add a quadratic amplification to increase sensitivity at high loads.
        if _PROC_TIME_COL in df.columns:
            col = "cpu_pressure_index"
            proc = df[_PROC_TIME_COL].clip(0, 1)
            df[col] = (proc ** 2).round(6)
            self._derived_columns.append(col)

        # Disk I/O ratio: reads / (reads + writes + epsilon)
        if _DISK_READ_COL in df.columns and _DISK_WRITE_COL in df.columns:
            col = "disk_read_ratio"
            r = df[_DISK_READ_COL].clip(lower=0)
            w = df[_DISK_WRITE_COL].clip(lower=0)
            df[col] = (r / (r + w + 1e-6)).round(6)
            self._derived_columns.append(col)

        # Network asymmetry: (sent - received) / (sent + received + epsilon)
        if _NET_RECV_COL in df.columns and _NET_SENT_COL in df.columns:
            col = "net_asymmetry"
            recv = df[_NET_RECV_COL].clip(lower=0)
            sent = df[_NET_SENT_COL].clip(lower=0)
            df[col] = ((sent - recv) / (sent + recv + 1e-6)).round(6)
            self._derived_columns.append(col)

        # Log-scale process count (handles wide dynamic range)
        if _PROC_COUNT_COL in df.columns:
            col = "log_process_count"
            df[col] = np.log1p(df[_PROC_COUNT_COL].clip(lower=0)).round(6)
            self._derived_columns.append(col)

        return df

    # ------------------------------------------------------------------
    def _add_rolling_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add rolling mean and std for key performance counters."""
        target_cols = [
            c for c in [_PROC_TIME_COL, _MEM_AVAIL_COL, _DISK_QUEUE_COL]
            if c in df.columns
        ]
        w = self.rolling_window

        for col in target_cols:
            mean_col = f"{col}_roll{w}_mean"
            std_col = f"{col}_roll{w}_std"
            df[mean_col] = (
                df[col].rolling(window=w, min_periods=1).mean().round(6)
            )
            df[std_col] = (
                df[col].rolling(window=w, min_periods=1).std().fillna(0.0).round(6)
            )
            self._derived_columns.extend([mean_col, std_col])

        return df
