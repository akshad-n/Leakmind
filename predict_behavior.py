"""
LeakMind Phase 2: Behavior Anomaly Inference
Loads the saved Isolation Forest model, preprocessing pipeline, and feature schema
to predict anomaly scores and normalized behavior risk (0-100) WITHOUT retraining.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union
import joblib
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.logger import get_logger

logger = get_logger("leakmind.predict_behavior")


def raw_to_behavior_risk(decision_score: np.ndarray) -> np.ndarray:
    """
    Transforms Isolation Forest decision function scores into a calibrated
    behavior risk score bounded to [0.0, 100.0].
    """
    risk = 100.0 / (1.0 + np.exp(decision_score * 10.0))
    return np.round(np.clip(risk, 0.0, 100.0), 2)


class BehaviorPredictor:
    """
    Portable inference engine for unsupervised behavior anomaly detection.
    Loads saved model, scaler, and feature schema without retraining.
    """

    def __init__(self, model_dir: str = "saved_models/behavior"):
        self.model_dir = Path(model_dir)
        self.model = None
        self.preprocessor = None
        self.feature_columns: List[str] = []
        self.config: Dict = {}
        self.load()

    def load(self):
        """Loads portable model bundle from disk."""
        model_file = self.model_dir / "isolation_forest.joblib"
        prep_file = self.model_dir / "preprocessing.joblib"
        feat_file = self.model_dir / "feature_columns.json"
        conf_file = self.model_dir / "config.json"

        if not model_file.exists():
            raise FileNotFoundError(f"Model file not found: {model_file}. Run train_behavior_model.py first.")
        if not prep_file.exists():
            raise FileNotFoundError(f"Preprocessor file not found: {prep_file}")
        if not feat_file.exists():
            raise FileNotFoundError(f"Feature schema file not found: {feat_file}")

        self.model = joblib.load(model_file)
        self.preprocessor = joblib.load(prep_file)

        with open(feat_file, "r", encoding="utf-8") as f:
            feat_data = json.load(f)
            self.feature_columns = feat_data.get("feature_columns", [])

        if conf_file.exists():
            with open(conf_file, "r", encoding="utf-8") as f:
                self.config = json.load(f)

        logger.info(f"Loaded Isolation Forest bundle from {self.model_dir} (Features: {len(self.feature_columns)}). No retraining required.")

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Infers anomaly scores and normalized behavior risk for an input dataframe.
        Separates identifiers, applies preprocessing, and returns output table.
        """
        df_input = df.copy()

        # Preserve identifiers if present
        id_cols = [c for c in ["user", "day"] if c in df_input.columns]
        result_df = df_input[id_cols].copy() if id_cols else pd.DataFrame(index=df_input.index)

        # Align columns to exact feature schema
        X = pd.DataFrame(0.0, index=df_input.index, columns=self.feature_columns)
        for col in self.feature_columns:
            if col in df_input.columns:
                X[col] = pd.to_numeric(df_input[col], errors="coerce").fillna(0.0)
            else:
                X[col] = 0.0

        # Apply loaded preprocessor (no fitting)
        X_scaled = self.preprocessor.transform(X)

        # Generate anomaly scores from loaded model
        # decision_function: lower means more anomalous
        raw_anomaly_score = self.model.decision_function(X_scaled)
        
        # Binary prediction: 1 = Normal, -1 = Anomaly
        anomaly_flags = self.model.predict(X_scaled)

        # Convert to normalized behavior risk (0 - 100)
        behavior_risks = raw_to_behavior_risk(raw_anomaly_score)

        result_df["anomaly_score"] = np.round(raw_anomaly_score, 4)
        result_df["anomaly_flag"] = anomaly_flags
        result_df["behavior_risk"] = behavior_risks

        return result_df


def main():
    parser = argparse.ArgumentParser(description="LeakMind Behavior Anomaly Inference")
    parser.add_argument("--input", type=str, default=None, help="Path to input features CSV")
    parser.add_argument("--model-dir", type=str, default="saved_models/behavior", help="Model directory")
    parser.add_argument("--limit", type=int, default=10, help="Number of rows to display")
    args = parser.parse_args()

    predictor = BehaviorPredictor(model_dir=args.model_dir)

    if args.input and os.path.exists(args.input):
        print(f"Loading input data from: {args.input}")
        df = pd.read_csv(args.input)
    else:
        # Default test data from Phase 1 test partition or supervised set
        test_path = Path("data/processed/test_features.csv")
        if not test_path.exists():
            test_path = Path("data/processed/cert_daily_features.csv")
        print(f"No custom input specified. Loading test data from: {test_path}")
        df = pd.read_csv(test_path, nrows=args.limit)

    results = predictor.predict(df)

    print("\n" + "=" * 70)
    print("BEHAVIOR ANOMALY INFERENCE RESULTS (WITHOUT RETRAINING)")
    print("=" * 70)
    print(results.head(args.limit))
    print("=" * 70)
    print(f"Evaluated {len(results)} samples.")
    print(f"Anomalies detected: {(results['anomaly_flag'] == -1).sum()} / {len(results)}")
    print(f"Mean Behavior Risk: {results['behavior_risk'].mean():.2f}%")


if __name__ == "__main__":
    main()
