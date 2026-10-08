"""
Prediction AI: Supervised Insider Threat & Data Leakage Predictor
Uses production-trained XGBoost, Random Forest, and Logistic Regression models.
"""

import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd


class LeakPredictor:
    """
    Inference engine for predicting data leak probability.
    """

    DEFAULT_FEATURES = [
        "http_activity_count",
        "after_hours_activity",
        "logon_count",
        "logoff_count",
        "after_hours_logon",
        "unique_pcs",
        "device_connect_count",
        "device_disconnect_count",
        "total_device_events"
    ]

    def __init__(self, models_dir: str = "models", preferred_model: str = "xgboost"):
        self.models_dir = models_dir
        self.preferred_model = preferred_model
        self.model = None
        self.scaler = None
        self._load()

    def _load(self):
        xgb_path = os.path.join(self.models_dir, "xgboost_model.joblib")
        rf_path = os.path.join(self.models_dir, "rf_model.joblib")
        scaler_path = os.path.join(self.models_dir, "supervised_scaler.joblib")

        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)

        if self.preferred_model == "xgboost" and os.path.exists(xgb_path):
            self.model = joblib.load(xgb_path)
        elif os.path.exists(rf_path):
            self.model = joblib.load(rf_path)
        elif os.path.exists(xgb_path):
            self.model = joblib.load(xgb_path)

    def predict_one(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Predicts leak probability for a single session/user feature dict.
        """
        row = [float(feature_dict.get(k, 0.0)) for k in self.DEFAULT_FEATURES]
        X = np.array([row])

        if self.model is None:
            # Heuristic fallback if model artifact not loaded
            leak_prob = 0.05
            if feature_dict.get("device_connect_count", 0) > 0 and feature_dict.get("after_hours_activity", 0) > 0:
                leak_prob = 0.95
            return {
                "predicted_label": int(leak_prob >= 0.5),
                "risk_probability": round(leak_prob, 4),
                "risk_score": round(leak_prob * 100.0, 2)
            }

        prob = float(self.model.predict_proba(X)[0][1])
        label = int(prob >= 0.5)

        return {
            "predicted_label": label,
            "risk_probability": round(prob, 4),
            "risk_score": round(prob * 100.0, 2)
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Predicts leak probability for a DataFrame containing feature columns.
        """
        df_eval = df.copy()
        for col in self.DEFAULT_FEATURES:
            if col not in df_eval.columns:
                df_eval[col] = 0.0

        X = df_eval[self.DEFAULT_FEATURES].values
        if self.model is not None:
            probs = self.model.predict_proba(X)[:, 1]
            labels = (probs >= 0.5).astype(int)
        else:
            probs = np.zeros(len(df_eval))
            labels = np.zeros(len(df_eval), dtype=int)

        df_eval["risk_probability"] = probs
        df_eval["risk_score"] = np.round(probs * 100.0, 2)
        df_eval["predicted_label"] = labels
        return df_eval
