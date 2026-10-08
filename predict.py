"""
LeakMind Phase 3: Portable Inference Engine (Laptop B)
Executes inference on new data using the pre-trained Isolation Forest bundle.
Strictly ZERO RETRAINING performed during inference.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from load_model import load_behavior_bundle
from src.utils.logger import get_logger

logger = get_logger("leakmind.predict")


def raw_to_behavior_risk(decision_score: np.ndarray) -> np.ndarray:
    """
    Transforms Isolation Forest decision function scores into a calibrated
    behavior risk score bounded to [0.0, 100.0].
    decision_function returns negative values for anomalies, positive for inliers.
    """
    risk = 100.0 / (1.0 + np.exp(decision_score * 10.0))
    return np.round(np.clip(risk, 0.0, 100.0), 2)


class LeakMindPredictor:
    """
    Portable inference pipeline executing on Laptop B without retraining.
    """

    def __init__(self, model_dir: str = "saved_models/behavior"):
        self.model_dir = model_dir
        self.model, self.preprocessor, self.feature_columns, self.config, self.env = (
            load_behavior_bundle(model_dir)
        )

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Runs inference on new input data without retraining.
        1. Separates identifiers/timestamps.
        2. Aligns input features to exact training column ordering.
        3. Applies pre-fitted preprocessor.
        4. Computes anomaly score and normalized behavior risk (0-100).
        """
        df_input = df.copy()

        # Separate identifiers
        id_cols = [c for c in ["user", "day"] if c in df_input.columns]
        result_df = df_input[id_cols].copy() if id_cols else pd.DataFrame(index=df_input.index)

        # Align features to exact training schema
        X = pd.DataFrame(0.0, index=df_input.index, columns=self.feature_columns)
        for col in self.feature_columns:
            if col in df_input.columns:
                X[col] = pd.to_numeric(df_input[col], errors="coerce").fillna(0.0)
            else:
                X[col] = 0.0

        # Apply loaded preprocessing pipeline (strictly transform, NO fit)
        X_scaled = self.preprocessor.transform(X)

        # Infer anomaly scores from loaded model
        raw_anomaly_score = self.model.decision_function(X_scaled)
        anomaly_flags = self.model.predict(X_scaled)  # 1 = Normal, -1 = Anomaly
        behavior_risks = raw_to_behavior_risk(raw_anomaly_score)

        # Contextual risk modulation factors
        after_logon = pd.to_numeric(df_input.get("after_hours_logon", 0), errors="coerce").fillna(0).values
        after_device = pd.to_numeric(df_input.get("after_hours_device", 0), errors="coerce").fillna(0).values
        after_act = pd.to_numeric(df_input.get("after_hours_activity", 0), errors="coerce").fillna(0).values
        usb_usage = pd.to_numeric(df_input.get("usb_usage", 0), errors="coerce").fillna(0).values
        dev_conn = pd.to_numeric(df_input.get("device_connect_count", 0), errors="coerce").fillna(0).values
        ext_dest = pd.to_numeric(df_input.get("external_destination", 0), errors="coerce").fillna(0).values
        unique_pcs = pd.to_numeric(df_input.get("unique_pcs", 1), errors="coerce").fillna(1).values
        new_dev = pd.to_numeric(df_input.get("new_device", 0), errors="coerce").fillna(0).values
        spike = pd.to_numeric(df_input.get("activity_spike_ratio", 1.0), errors="coerce").fillna(1.0).values
        priv = pd.to_numeric(df_input.get("privileged_account", 0), errors="coerce").fillna(0).values

        ctx_mult = 1.0 + (
            np.clip(0.5 * np.minimum(after_logon, 2.0) + 1.2 * np.minimum(after_device, 2.0) + 0.3 * np.minimum(after_act, 5.0), 0.0, 3.5) +
            np.clip(0.8 * np.minimum(dev_conn, 3.0) + 0.4 * np.minimum(usb_usage, 4.0), 0.0, 3.5) +
            np.clip(2.0 * np.minimum(ext_dest, 2.0), 0.0, 3.5) +
            np.clip(0.6 * np.maximum(0, unique_pcs - 1) + 0.8 * np.minimum(new_dev, 1.0), 0.0, 2.5) +
            np.clip(0.4 * np.maximum(0, spike - 1.5) / 2.0, 0.0, 2.0) +
            np.clip(0.3 * priv, 0.0, 1.0)
        )
        context_aware_risk = np.round(np.clip(behavior_risks * ctx_mult, 0.0, 100.0), 2)

        result_df["anomaly_score"] = np.round(raw_anomaly_score, 4)
        result_df["anomaly_flag"] = anomaly_flags
        result_df["behavior_risk"] = behavior_risks
        result_df["context_aware_behavior_risk"] = context_aware_risk

        return result_df


def main():
    parser = argparse.ArgumentParser(description="LeakMind Portable Inference Engine")
    parser.add_argument("--input", type=str, default=None, help="Path to input features CSV")
    parser.add_argument("--output", type=str, default=None, help="Optional output CSV path")
    parser.add_argument("--model-dir", type=str, default="saved_models/behavior", help="Model directory")
    parser.add_argument("--limit", type=int, default=10, help="Number of preview records")
    args = parser.parse_args()

    print("=" * 70)
    print("LEAKMIND PORTABLE INFERENCE EXECUTION (LAPTOP B)")
    print("=" * 70)

    # Initialize predictor (loads model bundle without retraining)
    predictor = LeakMindPredictor(model_dir=args.model_dir)

    # Load input data
    if args.input and os.path.exists(args.input):
        print(f"Loading input telemetry from: {args.input}")
        df = pd.read_csv(args.input)
    else:
        # Load sample from test partition
        test_path = Path("data/processed/test_features.csv")
        if not test_path.exists():
            test_path = Path("data/processed/cert_daily_features.csv")
        print(f"No custom input specified. Loading test evaluation set from: {test_path}")
        df = pd.read_csv(test_path, nrows=args.limit)

    # Execute inference
    predictions = predictor.predict(df)

    print("\n" + "=" * 70)
    print("INFERENCE PREDICTION RESULTS (ZERO RETRAINING)")
    print("=" * 70)
    print(predictions.head(args.limit).to_string(index=False))
    print("-" * 70)
    print(f"Total Evaluated Records: {len(predictions):,}")
    print(f"Anomalous Days Detected : {(predictions['anomaly_flag'] == -1).sum():,} / {len(predictions):,}")
    print(f"Mean Behavior Risk Score: {predictions['behavior_risk'].mean():.2f}%")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        predictions.to_csv(out_path, index=False)
        print(f"Saved inference predictions to: {out_path}")

    print("=" * 70)


if __name__ == "__main__":
    main()
