"""
Behavior AI Interface (Phase 2)
Defines abstract contract for unsupervised behavior anomaly detection.
Output: anomaly_score and normalized behavior_risk (0–100).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd


class BaseBehaviorDetector(ABC):
    """
    Abstract interface for unsupervised user behavior anomaly detection.
    """

    @abstractmethod
    def train_model(
        self,
        X: pd.DataFrame,
        feature_columns: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Trains the behavior anomaly detection model."""
        pass

    @abstractmethod
    def save_model(self, model_dir: str) -> Dict[str, str]:
        """Saves model, preprocessor, feature columns, and config for cross-laptop portability."""
        pass

    @abstractmethod
    def load_model(self, model_dir: str):
        """Loads model, preprocessor, feature columns, and config without retraining."""
        pass

    @abstractmethod
    def predict(
        self,
        X: pd.DataFrame
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Infers anomaly score and normalized behavior risk.
        Returns:
            anomaly_score: Raw algorithm output (e.g. Isolation Forest decision function)
            behavior_risk: Scaled risk score bounded to [0.0, 100.0]
        """
        pass
