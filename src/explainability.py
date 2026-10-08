"""
LeakMind Phase 9: SHAP Model Explainability Engine
Implements TreeExplainer interpretability for the production XGBoost risk model.
Generates:
1. Global feature importance (mean absolute SHAP across all evaluated instances)
2. Individual incident explanations with top positive and top negative risk factors
   using actual SHAP values (never hardcoded).

Conforms to BaseExplainer.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import shap
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.interfaces.explainer_interface import BaseExplainer
from src.utils.logger import get_logger

logger = get_logger("leakmind.explainability")

# Plain-English forensic translations for technical feature keys
HUMAN_FEATURE_NAMES = {
    "sensitivity_risk": "Sensitive file access",
    "external_destination": "External destination",
    "usb_activity": "USB activity",
    "after_hours_activity": "After-hours behavior",
    "leakage_chain_score": "Multi-stage leakage chain",
    "graph_risk": "Provenance graph risk",
    "behavior_risk": "Behavioral anomaly risk",
    "destination_risk": "Destination egress risk",
    "historical_user_risk": "Historical activity deviation",
    "new_device": "Unfamiliar device access"
}


class ShapRiskExplainer(BaseExplainer):
    """
    Production SHAP interpretability engine for the trained XGBoost risk fusion model.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        feature_names: Optional[List[str]] = None
    ):
        self.model = model
        self.feature_names = feature_names
        self.explainer: Optional[shap.TreeExplainer] = None
        self.base_value: float = 0.0
        if model is not None:
            self.fit_explainer(model)

    def fit_explainer(self, model: Any, background_data: Optional[pd.DataFrame] = None):
        """
        Initializes the SHAP TreeExplainer on the trained XGBoost model.
        """
        self.model = model
        try:
            self.explainer = shap.TreeExplainer(self.model)
            ev = self.explainer.expected_value
            self.base_value = float(ev[0]) if isinstance(ev, (list, np.ndarray)) else float(ev)
            logger.info(f"Initialized SHAP TreeExplainer with base expected value: {self.base_value:.4f}")
        except Exception as e:
            logger.error(f"Failed to initialize TreeExplainer: {e}")
            raise

    @classmethod
    def load(
        cls,
        model_path: str = "saved_models/risk/xgboost_model.json",
        feature_columns_path: str = "saved_models/risk/feature_columns.json"
    ) -> "ShapRiskExplainer":
        """
        Factory loader loading saved XGBoost model and feature configuration.
        """
        m_file = Path(model_path)
        f_file = Path(feature_columns_path)

        if not m_file.exists():
            raise FileNotFoundError(f"XGBoost model file not found at: {m_file}")

        model = xgb.XGBClassifier()
        model.load_model(str(m_file))

        feat_names = None
        if f_file.exists():
            with open(f_file, "r", encoding="utf-8") as f:
                feat_names = json.load(f).get("feature_columns")

        return cls(model=model, feature_names=feat_names)

    @staticmethod
    def _categorize_contribution(shap_val: float) -> str:
        """
        Categorizes contribution tier using actual SHAP magnitude.
        """
        mag = abs(shap_val)
        if mag >= 0.50:
            return "high contribution" if shap_val > 0 else "high mitigation"
        elif mag >= 0.10:
            return "moderate contribution" if shap_val > 0 else "moderate mitigation"
        elif mag >= 0.02:
            return "low contribution" if shap_val > 0 else "low mitigation"
        else:
            return "minimal contribution" if shap_val > 0 else "minimal mitigation"

    def explain_instance(
        self,
        instance: Union[pd.Series, Dict[str, Any], np.ndarray],
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Calculates local feature attributions for a single incident using true SHAP values.
        """
        if self.explainer is None:
            raise RuntimeError("SHAP explainer is not fitted. Call fit_explainer first.")

        feats = feature_names or self.feature_names
        if feats is None:
            raise ValueError("Feature names must be provided to explain_instance.")

        # Prepare single 1xD array
        if isinstance(instance, pd.Series):
            row_vals = [float(instance.get(k, 0.0)) for k in feats]
        elif isinstance(instance, dict):
            row_vals = [float(instance.get(k, 0.0)) for k in feats]
        else:
            row_vals = list(instance)

        X_row = np.array([row_vals])

        # Compute true TreeExplainer SHAP values
        raw_shap = self.explainer.shap_values(X_row)
        shap_vector = raw_shap[0] if isinstance(raw_shap, np.ndarray) and raw_shap.ndim > 1 else raw_shap

        # Compute probability and risk score from model
        prob = float(self.model.predict_proba(X_row)[:, 1][0])
        final_risk_score = round(prob * 100.0, 1)

        # Build feature attribution dictionary
        shap_dict = {}
        positive_factors = []
        negative_factors = []

        for name, actual_val, s_val in zip(feats, row_vals, shap_vector):
            human_label = HUMAN_FEATURE_NAMES.get(name, name.replace("_", " ").title())
            s_float = float(s_val)
            contrib_tier = self._categorize_contribution(s_float)

            factor_data = {
                "feature": name,
                "label": human_label,
                "actual_value": round(float(actual_val), 2),
                "shap_value": round(s_float, 4),
                "contribution": contrib_tier
            }
            shap_dict[name] = factor_data

            if s_float > 0.0001:
                positive_factors.append(factor_data)
            elif s_float < -0.0001:
                negative_factors.append(factor_data)

        # Sort factors by absolute magnitude descending
        positive_factors.sort(key=lambda x: x["shap_value"], reverse=True)
        negative_factors.sort(key=lambda x: x["shap_value"])  # Most negative first

        # Generate formatted explanation matching user's requested specification
        lines = [f"Final Risk: {final_risk_score:.0f}%\n"]
        for item in positive_factors:
            lines.append(f"{item['label']}: {item['contribution']}")

        formatted_narrative = "\n".join(lines)

        return {
            "final_risk_score": final_risk_score,
            "final_risk_probability": round(prob, 4),
            "base_value": round(self.base_value, 4),
            "shap_values": shap_dict,
            "top_positive_risk_factors": positive_factors,
            "top_negative_risk_factors": negative_factors,
            "formatted_explanation": formatted_narrative
        }

    def compute_global_feature_importance(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        feature_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Calculates global feature importance via mean absolute SHAP values across all samples.
        """
        if self.explainer is None:
            raise RuntimeError("SHAP explainer is not fitted.")

        feats = feature_names or self.feature_names
        if isinstance(X, pd.DataFrame):
            if feats is None:
                feats = list(X.columns)
            X_mat = X[feats].values
        else:
            X_mat = np.array(X)
            if feats is None:
                feats = [f"feature_{i}" for i in range(X_mat.shape[1])]

        shap_matrix = self.explainer.shap_values(X_mat)
        mean_abs_shap = np.mean(np.abs(shap_matrix), axis=0)
        mean_shap = np.mean(shap_matrix, axis=0)

        total_shap = float(np.sum(mean_abs_shap))
        rel_pct = (mean_abs_shap / total_shap * 100.0) if total_shap > 0 else np.zeros_like(mean_abs_shap)

        rankings = []
        for name, ma, ms, pct in zip(feats, mean_abs_shap, mean_shap, rel_pct):
            human_label = HUMAN_FEATURE_NAMES.get(name, name.replace("_", " ").title())
            rankings.append({
                "feature": name,
                "label": human_label,
                "mean_abs_shap": round(float(ma), 4),
                "mean_shap": round(float(ms), 4),
                "relative_importance_pct": round(float(pct), 2),
                "primary_direction": "Risk Driver" if ms > 0 else "Risk Mitigator"
            })

        rankings.sort(key=lambda x: x["mean_abs_shap"], reverse=True)

        return {
            "total_samples": len(X_mat),
            "feature_count": len(feats),
            "expected_base_value": round(self.base_value, 4),
            "rankings": rankings
        }


# Aliases
LeakExplainability = ShapRiskExplainer

__all__ = ["ShapRiskExplainer", "LeakExplainability", "HUMAN_FEATURE_NAMES"]
