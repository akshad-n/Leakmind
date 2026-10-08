"""
Multi-Evidence Risk Fusion Interface (Phase 8)
Fuses behavior, sensitivity, graph provenance, and temporal evidence into a calibrated final risk score.
Compares XGBoost against Logistic Regression and Random Forest.
Output: final_risk_probability and risk_score (0–100%).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd


class BaseRiskFusion(ABC):
    """
    Abstract interface for multi-evidence machine learning risk fusion.
    """

    @abstractmethod
    def train_fusion(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        feature_columns: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Trains the multi-evidence risk fusion model."""
        pass

    @abstractmethod
    def save_model(self, model_dir: str) -> Dict[str, str]:
        """Saves portable model bundle to saved_models/risk/."""
        pass

    @abstractmethod
    def load_model(self, model_dir: str):
        """Loads portable model bundle for cross-laptop inference."""
        pass

    @abstractmethod
    def predict(
        self,
        X: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            final_risk_probability: Probabilities in [0.0, 1.0]
            risk_score: Normalized risk percentages in [0.0, 100.0]
        """
        pass
