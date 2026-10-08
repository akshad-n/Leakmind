"""
LeakMind Phase 8: Multi-Evidence Risk Fusion Engine
Integrates multi-evidence streams across behavior, sensitive data, graph provenance,
temporal correlation, and contextual telemetry into a calibrated final risk assessment.

Supported Models:
- Logistic Regression
- Random Forest
- XGBoost (Production Gradient Boosted Classifier)

Strictly conforms to BaseRiskFusion.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.interfaces.fusion_interface import BaseRiskFusion
from src.utils.logger import get_logger

logger = get_logger("leakmind.fusion")

# Canonical 10 multi-evidence input features
DEFAULT_FUSION_FEATURES = [
    "behavior_risk",
    "sensitivity_risk",
    "graph_risk",
    "leakage_chain_score",
    "destination_risk",
    "historical_user_risk",
    "after_hours_activity",
    "usb_activity",
    "new_device",
    "external_destination"
]


class MultiEvidenceRiskFusion(BaseRiskFusion):
    """
    Supervised Multi-Evidence Risk Fusion Engine combining all analytical dimensions.
    """

    def __init__(
        self,
        model_type: str = "xgboost",
        feature_columns: Optional[List[str]] = None
    ):
        self.model_type = model_type.lower()
        self.feature_columns = feature_columns or list(DEFAULT_FUSION_FEATURES)
        self.model = None
        self.preprocessor = StandardScaler()
        self.is_fitted = False
        self.config: Dict[str, Any] = {}

    def _init_classifier(self, **kwargs) -> Any:
        """Instantiates selected classifier architecture."""
        if self.model_type == "xgboost":
            import xgboost as xgb
            params = {
                "n_estimators": 100,
                "max_depth": 4,
                "learning_rate": 0.05,
                "subsample": 0.8,
                "colsample_bytree": 0.6,
                "colsample_bynode": 0.6,
                "random_state": 42,
                "eval_metric": "logloss"
            }
            params.update(kwargs)
            return xgb.XGBClassifier(**params)
        elif self.model_type in ["rf", "random_forest"]:
            params = {
                "n_estimators": 100,
                "max_depth": 5,
                "min_samples_split": 2,
                "random_state": 42
            }
            params.update(kwargs)
            return RandomForestClassifier(**params)
        elif self.model_type in ["lr", "logistic_regression"]:
            params = {
                "C": 1.0,
                "max_iter": 1000,
                "random_state": 42
            }
            params.update(kwargs)
            return LogisticRegression(**params)
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}. Choose from 'xgboost', 'random_forest', 'logistic_regression'.")

    def train_fusion(
        self,
        X_train: pd.DataFrame,
        y_train: Union[pd.Series, np.ndarray],
        feature_columns: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Trains the risk fusion classifier on extracted multi-evidence features.
        """
        if feature_columns:
            self.feature_columns = list(feature_columns)

        missing_feats = [c for c in self.feature_columns if c not in X_train.columns]
        if missing_feats:
            raise ValueError(f"X_train missing required fusion features: {missing_feats}")

        X_subset = X_train[self.feature_columns].copy().fillna(0.0)
        y_arr = np.array(y_train).ravel()

        logger.info(f"Fitting StandardScaler preprocessor on {len(X_subset)} training samples across {len(self.feature_columns)} features...")
        X_scaled = self.preprocessor.fit_transform(X_subset)

        logger.info(f"Training {self.model_type.upper()} risk fusion classifier...")
        self.model = self._init_classifier(**kwargs)

        # For XGBoost and tree models, we can use raw or scaled features
        if self.model_type in ["logistic_regression", "lr"]:
            self.model.fit(X_scaled, y_arr)
        else:
            self.model.fit(X_subset.values, y_arr)

        self.is_fitted = True
        self.config = {
            "engine": "MultiEvidenceRiskFusion",
            "model_type": self.model_type,
            "feature_columns": self.feature_columns,
            "feature_count": len(self.feature_columns),
            "training_samples": len(X_subset)
        }

        logger.info(f"{self.model_type.upper()} fusion training completed successfully.")
        return self.config

    def predict(
        self,
        X: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Infers final leakage probability and risk score (0.0 to 100.0).
        Returns:
            final_risk_probability: Probabilities in [0.0, 1.0]
            risk_score: Normalized risk percentages in [0.0, 100.0]
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("MultiEvidenceRiskFusion model is not fitted or loaded.")

        X_aligned = pd.DataFrame(0.0, index=range(len(X)), columns=self.feature_columns)
        for c in self.feature_columns:
            if c in X.columns:
                X_aligned[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0).values

        if self.model_type in ["logistic_regression", "lr"]:
            X_in = self.preprocessor.transform(X_aligned)
        else:
            X_in = X_aligned.values

        probs = self.model.predict_proba(X_in)[:, 1]
        risk_scores = np.clip(probs * 100.0, 0.0, 100.0)

        return probs, risk_scores

    def predict_one(self, feature_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Infers risk for a single session / user feature dictionary."""
        df_single = pd.DataFrame([feature_dict])
        prob, score = self.predict(df_single)
        final_prob = float(prob[0])
        final_score = float(score[0])

        if final_score >= 80.0:
            tier = "CRITICAL"
        elif final_score >= 60.0:
            tier = "HIGH"
        elif final_score >= 35.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return {
            "final_risk_probability": round(final_prob, 4),
            "risk_score": round(final_score, 2),
            "risk_tier": tier,
            "model_type": self.model_type,
            "features_evaluated": {k: feature_dict.get(k, 0.0) for k in self.feature_columns}
        }

    def save_model(self, model_dir: Union[str, Path]) -> Dict[str, str]:
        """
        Saves portable model bundle to saved_models/risk/.
        Specifically saves:
        - For XGBoost: saved_models/risk/xgboost_model.json
        - preprocessing.joblib
        - feature_columns.json
        - config.json
        """
        out_dir = Path(model_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        saved_files = {}

        # 1. Save Preprocessor
        prep_path = out_dir / "preprocessing.joblib"
        joblib.dump(self.preprocessor, prep_path)
        saved_files["preprocessing"] = str(prep_path)

        # 2. Save Feature Columns
        feat_path = out_dir / "feature_columns.json"
        with open(feat_path, "w", encoding="utf-8") as f:
            json.dump({
                "feature_columns": self.feature_columns,
                "count": len(self.feature_columns)
            }, f, indent=2)
        saved_files["feature_columns"] = str(feat_path)

        # 3. Save Model Artifact
        if self.model_type == "xgboost":
            model_path = out_dir / "xgboost_model.json"
            self.model.save_model(str(model_path))
            saved_files["model"] = str(model_path)
        elif self.model_type in ["rf", "random_forest"]:
            model_path = out_dir / "rf_model.joblib"
            joblib.dump(self.model, model_path)
            saved_files["model"] = str(model_path)
        else:
            model_path = out_dir / "lr_model.joblib"
            joblib.dump(self.model, model_path)
            saved_files["model"] = str(model_path)

        # 4. Save Config
        conf_path = out_dir / "config.json"
        config_data = {
            "engine": "MultiEvidenceRiskFusion",
            "model_type": self.model_type,
            "feature_columns": self.feature_columns,
            "model_file": Path(saved_files["model"]).name,
            "preprocessor_file": "preprocessing.joblib",
            "version": "1.0.0"
        }
        with open(conf_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        saved_files["config"] = str(conf_path)

        logger.info(f"Saved {self.model_type.upper()} model bundle to {out_dir}")
        return saved_files

    def load_model(self, model_dir: Union[str, Path]):
        """
        Loads portable model bundle for zero-retraining inference.
        """
        in_dir = Path(model_dir)
        if not in_dir.exists():
            raise FileNotFoundError(f"Directory not found: {in_dir}")

        prep_path = in_dir / "preprocessing.joblib"
        feat_path = in_dir / "feature_columns.json"
        conf_path = in_dir / "config.json"

        if not prep_path.exists() or not feat_path.exists() or not conf_path.exists():
            raise FileNotFoundError(f"Missing mandatory fusion artifacts in {in_dir}")

        self.preprocessor = joblib.load(prep_path)

        with open(feat_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.feature_columns = data.get("feature_columns", DEFAULT_FUSION_FEATURES)

        with open(conf_path, "r", encoding="utf-8") as f:
            self.config = json.load(f)
            self.model_type = self.config.get("model_type", "xgboost")

        model_filename = self.config.get("model_file")
        if not model_filename:
            model_filename = "xgboost_model.json" if self.model_type == "xgboost" else "model.joblib"

        model_path = in_dir / model_filename
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        if self.model_type == "xgboost":
            import xgboost as xgb
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(model_path))
        else:
            self.model = joblib.load(model_path)

        self.is_fitted = True
        logger.info(f"Loaded {self.model_type.upper()} fusion model from {in_dir} (Zero Retraining).")


__all__ = ["MultiEvidenceRiskFusion", "DEFAULT_FUSION_FEATURES"]
