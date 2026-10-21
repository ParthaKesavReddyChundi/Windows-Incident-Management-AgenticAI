"""
Dataset validator and exploratory inspector for ToN_IoT Windows dataset.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


class DatasetValidator:
    """Validates structure, types, missing values, and labels of raw Windows datasets."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        if not self.file_path.exists():
            raise FileNotFoundError(f"Dataset file not found: {self.file_path}")

    def inspect(self, nrows: int = 5000) -> Dict[str, object]:
        """Perform rapid inspection of dataset schema, shape, and label distribution."""
        df_sample = pd.read_csv(self.file_path, nrows=nrows)

        # Check total lines count roughly or via full scan
        df_full = pd.read_csv(self.file_path)
        total_rows, total_cols = df_full.shape

        # Identify label columns
        label_col = "label" if "label" in df_full.columns else None
        type_col = "type" if "type" in df_full.columns else None

        label_dist = df_full[label_col].value_counts().to_dict() if label_col else {}
        type_dist = df_full[type_col].value_counts().to_dict() if type_col else {}

        missing_counts = df_full.isnull().sum()
        cols_with_missing = missing_counts[missing_counts > 0].to_dict()

        return {
            "file": self.file_path.name,
            "total_rows": total_rows,
            "total_columns": total_cols,
            "label_column": label_col,
            "type_column": type_col,
            "label_distribution": label_dist,
            "type_distribution": type_dist,
            "missing_values_count": len(cols_with_missing),
            "sample_columns": list(df_full.columns[:15]),
        }
