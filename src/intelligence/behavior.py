"""
Behavioral Baselines & Context-Aware Anomaly Profiling
Integrates Isolation Forest unsupervised scoring with context-aware behavior risk.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd

from src.context_behavior import (
    ContextAwareBehaviorDetector,
    raw_to_behavior_risk,
    DEFAULT_FEATURE_COLUMNS
)


class BehavioralProfiler:
    """
    Profiles normal user behavior windows and computes behavioral deviation
    using the trained Isolation Forest anomaly detection model and context factors.
    """

    def __init__(self, models_dir: str = "saved_models/behavior"):
        self.models_dir = models_dir
        self.detector = ContextAwareBehaviorDetector(model_dir=models_dir)
        try:
            self.detector.load_model(models_dir)
        except Exception:
            # Fallback if bundle not in saved_models, check legacy models/
            legacy_dir = "models"
            if os.path.exists(os.path.join(legacy_dir, "isolation_forest.joblib")):
                try:
                    self.detector.iso_forest = joblib.load(os.path.join(legacy_dir, "isolation_forest.joblib"))
                    self.detector.preprocessor = joblib.load(os.path.join(legacy_dir, "isolation_forest_scaler.joblib"))
                except Exception:
                    pass

    def compute_behavior_anomaly_score(self, feature_vector: Dict[str, float]) -> float:
        """
        Returns a normalized behavioral anomaly score from 0.0 (perfectly normal) to 1.0 (highly anomalous).
        """
        df = pd.DataFrame([feature_vector])
        try:
            raw_scores, context_risks = self.detector.predict(df)
            return round(float(context_risks[0]) / 100.0, 4)
        except Exception:
            # Fallback heuristic if models missing
            score = 0.0
            if feature_vector.get("after_hours_activity", 0) > 10:
                score += 0.3
            if feature_vector.get("total_device_events", 0) > 3 or feature_vector.get("usb_usage", 0) > 3:
                score += 0.4
            if feature_vector.get("unique_pcs", 0) > 2:
                score += 0.3
            return min(1.0, score)

    def evaluate_telemetry(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluates batch telemetry and returns detailed DataFrame with both
        raw_anomaly_score and context_aware_behavior_risk.
        """
        return self.detector.predict_detailed(df)


__all__ = [
    "ContextAwareBehaviorDetector",
    "BehavioralProfiler",
    "raw_to_behavior_risk",
    "DEFAULT_FEATURE_COLUMNS"
]
