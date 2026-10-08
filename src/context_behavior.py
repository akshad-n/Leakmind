"""
LeakMind Phase 4: Context-Aware Behavior Risk Engine
Improves upon simple unsupervised Isolation Forest anomaly detection by combining:
1. Raw Isolation Forest decision scores (preserves unsupervised baseline)
2. Temporal & after-hours context (night & weekend activity, off-hours USB)
3. Exfiltration channel context (USB connect/disconnect volumes)
4. Destination threat context (visits to wikileaks, dropbox, external file sharing)
5. Device mobility & unfamiliar asset context (unique PCs, new PC usage)
6. Behavioral frequency & velocity spikes (relative to user's historical baseline)
7. Role & privilege context (LDAP privileged accounts)
8. File access proxy patterns (USB transfer & upload movement proxies; raw file.csv omitted)

Produces both:
- raw_anomaly_score
- context_aware_behavior_risk (0.0 to 100.0)
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.interfaces.behavior_interface import BaseBehaviorDetector
from src.utils.logger import get_logger

logger = get_logger("leakmind.context_behavior")

# Standard 15 features supported by CERT dataset
DEFAULT_FEATURE_COLUMNS = [
    "login_frequency",
    "logoff_count",
    "after_hours_logon",
    "unique_pcs",
    "new_device",
    "usb_usage",
    "device_connect_count",
    "device_disconnect_count",
    "after_hours_device",
    "web_activity",
    "after_hours_activity",
    "external_destination",
    "privileged_account",
    "user_historical_activity",
    "activity_spike_ratio"
]


def raw_to_behavior_risk(decision_score: np.ndarray) -> np.ndarray:
    """
    Transforms Isolation Forest decision function scores into a calibrated
    base behavior risk score bounded to [0.0, 100.0].
    decision_function returns negative values for anomalies, positive for inliers.
    """
    decision_score = np.asarray(decision_score, dtype=float)
    risk = 100.0 / (1.0 + np.exp(decision_score * 10.0))
    return np.round(np.clip(risk, 0.0, 100.0), 2)


class ContextAwareBehaviorDetector(BaseBehaviorDetector):
    """
    Context-Aware Behavior Risk Detector.
    Preserves raw Isolation Forest anomaly detection while augmenting risk
    with domain-specific contextual security multipliers.
    """

    def __init__(
        self,
        model_dir: str = "saved_models/behavior",
        context_weights: Optional[Dict[str, float]] = None
    ):
        self.model_dir = Path(model_dir)
        self.iso_forest: Optional[IsolationForest] = None
        self.preprocessor: Optional[StandardScaler] = None
        self.feature_columns: List[str] = list(DEFAULT_FEATURE_COLUMNS)
        self.config: Dict[str, Any] = {}

        # Configurable contextual weights
        self.context_weights = context_weights or {
            "w_temporal_logon": 0.5,
            "w_temporal_device": 1.2,
            "w_temporal_activity": 0.3,
            "w_usb_connect": 0.8,
            "w_usb_usage": 0.4,
            "w_destination_ext": 2.0,
            "w_device_hopping": 0.6,
            "w_device_new": 0.8,
            "w_frequency_spike": 0.4,
            "w_role_privilege": 0.3
        }

    def train_model(
        self,
        X: pd.DataFrame,
        feature_columns: Optional[List[str]] = None,
        n_estimators: int = 100,
        contamination: float = 0.05,
        random_state: int = 42,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Trains the underlying Isolation Forest model and fits the feature preprocessor.
        """
        if feature_columns is not None:
            self.feature_columns = list(feature_columns)

        # Align features
        X_df = X[self.feature_columns].copy().fillna(0.0)

        logger.info(f"Fitting StandardScaler on {len(X_df)} samples...")
        self.preprocessor = StandardScaler()
        X_scaled = self.preprocessor.fit_transform(X_df)

        logger.info(f"Fitting IsolationForest (n_estimators={n_estimators}, contamination={contamination})...")
        self.iso_forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.iso_forest.fit(X_scaled)

        self.config = {
            "model_type": "ContextAwareIsolationForest",
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state,
            "feature_count": len(self.feature_columns),
            "training_samples": len(X_df),
            "context_weights": self.context_weights
        }
        return self.config

    def save_model(self, model_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Saves all required artifacts into model_dir for cross-machine portability.
        """
        save_path = Path(model_dir) if model_dir else self.model_dir
        save_path.mkdir(parents=True, exist_ok=True)

        paths = {}
        if self.iso_forest is not None:
            model_file = save_path / "isolation_forest.joblib"
            joblib.dump(self.iso_forest, model_file)
            paths["model"] = str(model_file)

        if self.preprocessor is not None:
            prep_file = save_path / "preprocessing.joblib"
            joblib.dump(self.preprocessor, prep_file)
            paths["preprocessor"] = str(prep_file)

        feat_file = save_path / "feature_columns.json"
        with open(feat_file, "w", encoding="utf-8") as f:
            json.dump({"feature_columns": self.feature_columns, "count": len(self.feature_columns)}, f, indent=2)
        paths["feature_columns"] = str(feat_file)

        conf_file = save_path / "context_config.json"
        with open(conf_file, "w", encoding="utf-8") as f:
            json.dump({
                **self.config,
                "context_weights": self.context_weights,
                "supported_context_dimensions": [
                    "user_historical_behavior",
                    "time_of_activity",
                    "after_hours_behavior",
                    "role",
                    "file_access_pattern_proxy",
                    "device_behavior",
                    "usb_behavior",
                    "destination_behavior",
                    "frequency_changes"
                ]
            }, f, indent=2)
        paths["config"] = str(conf_file)

        # Also save the full pipeline instance
        pipe_file = save_path / "context_behavior_pipeline.joblib"
        joblib.dump(self, pipe_file)
        paths["pipeline"] = str(pipe_file)

        logger.info(f"Saved complete Context-Aware Behavior bundle to {save_path}")
        return paths

    def load_model(self, model_dir: Optional[str] = None):
        """
        Loads the pre-trained bundle without retraining.
        """
        path = Path(model_dir) if model_dir else self.model_dir
        if not path.exists():
            raise FileNotFoundError(f"Model directory not found: {path}")

        model_file = path / "isolation_forest.joblib"
        prep_file = path / "preprocessing.joblib"
        feat_file = path / "feature_columns.json"
        conf_file = path / "context_config.json"

        if not model_file.exists() or not prep_file.exists() or not feat_file.exists():
            raise FileNotFoundError(f"Missing mandatory model bundle files in {path}")

        self.iso_forest = joblib.load(model_file)
        self.preprocessor = joblib.load(prep_file)

        with open(feat_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.feature_columns = data.get("feature_columns", DEFAULT_FEATURE_COLUMNS)

        if conf_file.exists():
            with open(conf_file, "r", encoding="utf-8") as f:
                self.config = json.load(f)
                if "context_weights" in self.config:
                    self.context_weights = self.config["context_weights"]

        logger.info(f"Loaded Context-Aware Behavior bundle from {path} (Zero Retraining).")

    def compute_context_breakdown(self, df_input: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Computes the security context factors across all supported telemetry dimensions:
        1. Temporal & After-Hours
        2. USB Behavior
        3. Destination Behavior
        4. Device Mobility & Workstation Switching
        5. Behavioral Frequency & Velocity Spikes
        6. Role & Privilege Clearance
        7. File Access Proxy Movement
        """
        w = self.context_weights
        n = len(df_input)

        def _s(col: str, d: float = 0.0) -> np.ndarray:
            if col in df_input.columns:
                return pd.to_numeric(df_input[col], errors="coerce").fillna(d).values
            return np.full(n, d, dtype=float)

        # 1. Temporal context (time of activity, after-hours)
        after_logon = _s("after_hours_logon", 0.0)
        after_device = _s("after_hours_device", 0.0)
        after_act = _s("after_hours_activity", 0.0)

        temporal_factor = np.clip(
            w.get("w_temporal_logon", 0.5) * np.minimum(after_logon, 2.0) +
            w.get("w_temporal_device", 1.2) * np.minimum(after_device, 2.0) +
            w.get("w_temporal_activity", 0.3) * np.minimum(after_act, 5.0),
            0.0, 3.5
        )

        # 2. USB exfiltration context
        usb_usage = _s("usb_usage", 0.0)
        dev_conn = _s("device_connect_count", 0.0)
        usb_factor = np.clip(
            w.get("w_usb_connect", 0.8) * np.minimum(dev_conn, 3.0) +
            w.get("w_usb_usage", 0.4) * np.minimum(usb_usage, 4.0),
            0.0, 3.5
        )

        # 3. Destination context (wikileaks, dropbox, personal cloud)
        ext_dest = _s("external_destination", 0.0)
        destination_factor = np.clip(
            w.get("w_destination_ext", 2.0) * np.minimum(ext_dest, 2.0),
            0.0, 3.5
        )

        # 4. Device mobility context (unique PCs, new workstation)
        unique_pcs = _s("unique_pcs", 1.0)
        new_dev = _s("new_device", 0.0)
        device_factor = np.clip(
            w.get("w_device_hopping", 0.6) * np.maximum(0, unique_pcs - 1) +
            w.get("w_device_new", 0.8) * np.minimum(new_dev, 1.0),
            0.0, 2.5
        )

        # 5. Frequency changes & velocity spikes
        spike = _s("activity_spike_ratio", 1.0)
        frequency_factor = np.clip(
            w.get("w_frequency_spike", 0.4) * np.maximum(0, spike - 1.5) / 2.0,
            0.0, 2.0
        )

        # 6. Role & privilege context (IT Admin, Director, VP)
        priv = _s("privileged_account", 0.0)
        role_factor = np.clip(
            w.get("w_role_privilege", 0.3) * priv,
            0.0, 1.0
        )

        # 7. Total Context Multiplier
        context_multiplier = 1.0 + (
            temporal_factor +
            usb_factor +
            destination_factor +
            device_factor +
            frequency_factor +
            role_factor
        )

        return {
            "temporal_factor": np.round(temporal_factor, 3),
            "usb_factor": np.round(usb_factor, 3),
            "destination_factor": np.round(destination_factor, 3),
            "device_factor": np.round(device_factor, 3),
            "frequency_factor": np.round(frequency_factor, 3),
            "role_factor": np.round(role_factor, 3),
            "context_multiplier": np.round(context_multiplier, 3)
        }

    def predict(
        self,
        X: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Infers both raw anomaly scores and context-aware behavior risk.
        Returns:
            raw_anomaly_score: Isolation Forest decision function score
            context_aware_behavior_risk: Risk score (0.0 to 100.0)
        """
        if self.iso_forest is None or self.preprocessor is None:
            raise RuntimeError("Model or preprocessor not loaded. Call load_model() or train_model() first.")

        # Align features to schema
        X_aligned = pd.DataFrame(0.0, index=X.index, columns=self.feature_columns)
        for col in self.feature_columns:
            if col in X.columns:
                X_aligned[col] = pd.to_numeric(X[col], errors="coerce").fillna(0.0)

        # 1. Compute Raw Anomaly Score
        X_scaled = self.preprocessor.transform(X_aligned)
        raw_anomaly_score = self.iso_forest.decision_function(X_scaled)
        base_risk = raw_to_behavior_risk(raw_anomaly_score)

        # 2. Compute Context Multipliers
        breakdown = self.compute_context_breakdown(X)
        mult = breakdown["context_multiplier"]

        # 3. Calibrate Context-Aware Behavior Risk
        context_aware_risk = np.round(np.clip(base_risk * mult, 0.0, 100.0), 2)
        return raw_anomaly_score, context_aware_risk

    def predict_detailed(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Executes inference and returns comprehensive telemetry dataframe
        containing both raw_anomaly_score and context_aware_behavior_risk,
        as well as all individual contextual risk factors.
        """
        raw_scores, context_risks = self.predict(df)
        base_risks = raw_to_behavior_risk(raw_scores)
        breakdown = self.compute_context_breakdown(df)

        id_cols = [c for c in ["user", "day"] if c in df.columns]
        result_df = df[id_cols].copy() if id_cols else pd.DataFrame(index=df.index)

        result_df["raw_anomaly_score"] = np.round(raw_scores, 4)
        result_df["raw_isolation_forest_risk"] = base_risks
        result_df["context_multiplier"] = breakdown["context_multiplier"]
        result_df["temporal_factor"] = breakdown["temporal_factor"]
        result_df["usb_factor"] = breakdown["usb_factor"]
        result_df["destination_factor"] = breakdown["destination_factor"]
        result_df["device_factor"] = breakdown["device_factor"]
        result_df["frequency_factor"] = breakdown["frequency_factor"]
        result_df["role_factor"] = breakdown["role_factor"]
        result_df["context_aware_behavior_risk"] = context_risks
        result_df["anomaly_flag"] = np.where(context_risks >= 50.0, -1, 1)

        # Map to alert levels
        def get_alert_level(score):
            if score >= 80.0:
                return "CRITICAL"
            elif score >= 60.0:
                return "HIGH"
            elif score >= 40.0:
                return "MEDIUM"
            return "LOW"

        result_df["risk_level"] = result_df["context_aware_behavior_risk"].apply(get_alert_level)
        return result_df


# Alias for pipeline compatibility
ContextAwareBehaviorModel = ContextAwareBehaviorDetector
