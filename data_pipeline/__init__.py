"""
data_pipeline package — dataset loading, validation, and preprocessing.

Modules:
    validator      : DatasetValidator (schema checks, label distribution)
    preprocessor   : TelemetryPreprocessor (MinMaxScaler, fit on normal-only)
    feature_engineering : FeatureEngineer (rolling stats, derived ratios)
"""

from data_pipeline.validator import DatasetValidator
from data_pipeline.preprocessor import TelemetryPreprocessor

__all__ = ["DatasetValidator", "TelemetryPreprocessor"]
