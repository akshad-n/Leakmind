"""
LeakMind Phase 4: Context-Aware Behavior Prediction Engine
Loads the portable Context-Aware Behavior bundle and performs inference on new telemetry.
Strictly ZERO RETRAINING performed during inference.

Outputs both:
- raw_anomaly_score (unsupervised Isolation Forest baseline)
- context_aware_behavior_risk (contextually modulated risk score 0.0 - 100.0)
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.context_behavior import (
    ContextAwareBehaviorDetector,
    raw_to_behavior_risk,
    DEFAULT_FEATURE_COLUMNS
)
from src.utils.logger import get_logger

logger = get_logger("leakmind.predict_context_behavior")


class ContextBehaviorPredictor:
    """
    Context-aware inference pipeline running with strictly zero retraining.
    """

    def __init__(self, model_dir: str = "saved_models/behavior"):
        self.model_dir = model_dir
        self.detector = ContextAwareBehaviorDetector(model_dir=model_dir)
        self.detector.load_model(model_dir)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Executes inference returning detailed telemetry with both
        raw_anomaly_score and context_aware_behavior_risk.
        """
        return self.detector.predict_detailed(df)


def main():
    parser = argparse.ArgumentParser(description="LeakMind Context-Aware Behavior Prediction Engine")
    parser.add_argument("--input", type=str, default=None, help="Path to input features CSV")
    parser.add_argument("--output", type=str, default=None, help="Optional output CSV path")
    parser.add_argument("--model-dir", type=str, default="saved_models/behavior", help="Model directory")
    parser.add_argument("--limit", type=int, default=10, help="Number of preview records")
    args = parser.parse_args()

    print("=" * 75)
    print("LEAKMIND CONTEXT-AWARE BEHAVIOR INFERENCE (ZERO RETRAINING)")
    print("=" * 75)

    # 1. Initialize predictor (loads pre-trained bundle without retraining)
    predictor = ContextBehaviorPredictor(model_dir=args.model_dir)

    # 2. Ingest telemetry
    if args.input and os.path.exists(args.input):
        print(f"Loading input telemetry from: {args.input}")
        df = pd.read_csv(args.input)
    else:
        test_path = Path("data/processed/cert_context_supervised.csv")
        if not test_path.exists():
            test_path = Path("data/processed/cert_daily_features.csv")
        print(f"No custom input specified. Loading test evaluation set from: {test_path}")
        df = pd.read_csv(test_path, nrows=args.limit)

    # 3. Perform context-aware inference
    predictions = predictor.predict(df)

    display_cols = [
        "user", "day", "raw_anomaly_score", "raw_isolation_forest_risk",
        "context_multiplier", "context_aware_behavior_risk", "risk_level"
    ]
    avail_cols = [c for c in display_cols if c in predictions.columns]

    print("\n" + "=" * 75)
    print("INFERENCE RESULTS: DUAL-SCORE TELEMETRY")
    print("=" * 75)
    print(predictions[avail_cols].head(args.limit).to_string(index=False))
    print("-" * 75)
    print(f"Total Evaluated Records     : {len(predictions):,}")
    print(f"High/Critical Risk Detected : {(predictions['context_aware_behavior_risk'] >= 60.0).sum():,} / {len(predictions):,}")
    print(f"Mean Raw IF Anomaly Score   : {predictions['raw_anomaly_score'].mean():.4f}")
    print(f"Mean Raw IF Risk Score      : {predictions['raw_isolation_forest_risk'].mean():.2f}%")
    print(f"Mean Context-Aware Risk     : {predictions['context_aware_behavior_risk'].mean():.2f}%")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        predictions.to_csv(out_path, index=False)
        print(f"Saved complete inference predictions to: {out_path}")

    print("=" * 75)


if __name__ == "__main__":
    main()
