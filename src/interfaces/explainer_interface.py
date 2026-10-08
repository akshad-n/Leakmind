"""
SHAP Explainability Interface (Phase 9)
Defines abstract contract for explaining risk predictions via SHAP values.
Values must come from the actual trained model, never hardcoded.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd


class BaseExplainer(ABC):
    """
    Abstract interface for model interpretability and risk explanation.
    """

    @abstractmethod
    def fit_explainer(self, model: Any, background_data: Optional[pd.DataFrame] = None):
        """Initializes the SHAP TreeExplainer or Explainer with background dataset."""
        pass

    @abstractmethod
    def explain_instance(
        self,
        instance: pd.Series,
        feature_names: List[str]
    ) -> Dict[str, Any]:
        """
        Calculates local feature attributions for a single incident.
        Returns:
            base_value: Expected baseline risk
            shap_values: Dict of feature -> shap contribution
            top_positive_drivers: Features driving risk up
            narrative: Generated human-readable explanation
        """
        pass
