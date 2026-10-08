"""
LeakMind Phase 8: Multi-Evidence Risk Fusion Inference Tool
Loads saved model artifacts from saved_models/risk/ (zero retraining)
and evaluates risk scores and probabilities across multi-evidence streams.

Usage:
  # Predict from feature values
  python predict_risk.py --behavior 85 --sensitivity 90 --graph 75 --temporal 85
  
  # Predict from a CSV dataset
  python predict_risk.py --input data/processed/cert_context_supervised.csv
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.fusion import MultiEvidenceRiskFusion, DEFAULT_FUSION_FEATURES
from src.utils.logger import get_logger

logger = get_logger("leakmind.predict_risk")


def load_fusion_engine(model_dir: str = "saved_models/risk") -> MultiEvidenceRiskFusion:
    """Loads portable fusion engine without retraining."""
    engine = MultiEvidenceRiskFusion()
    engine.load_model(model_dir)
    return engine


def predict_sample(
    engine: MultiEvidenceRiskFusion,
    feature_dict: Dict[str, float]
) -> Dict[str, Any]:
    """Evaluates risk for a single multi-evidence feature profile."""
    return engine.predict_one(feature_dict)


def main():
    parser = argparse.ArgumentParser(
        description="LeakMind Phase 8: Multi-Evidence Risk Predictor"
    )
    parser.add_argument("--model-dir", type=str, default="saved_models/risk", help="Path to saved model bundle")
    parser.add_argument("--input", type=str, default=None, help="Optional CSV file to predict on")
    parser.add_argument("--behavior", type=float, default=25.0, help="behavior_risk (0-100)")
    parser.add_argument("--sensitivity", type=float, default=10.0, help="sensitivity_risk (0-100)")
    parser.add_argument("--graph", type=float, default=15.0, help="graph_risk (0-100)")
    parser.add_argument("--temporal", type=float, default=0.0, help="leakage_chain_score (0-100)")
    parser.add_argument("--dest-risk", type=float, default=5.0, help="destination_risk (0-100)")
    parser.add_argument("--user-risk", type=float, default=20.0, help="historical_user_risk (0-100)")
    parser.add_argument("--after-hours", type=float, default=0.0, help="after_hours_activity count")
    parser.add_argument("--usb", type=float, default=0.0, help="usb_activity count")
    parser.add_argument("--new-dev", type=float, default=0.0, help="new_device indicator (0 or 1)")
    parser.add_argument("--ext-dest", type=float, default=0.0, help="external_destination indicator (0 or 1)")

    args = parser.parse_args()

    engine = load_fusion_engine(args.model_dir)

    print("=" * 70)
    print(" LEAKMIND: MULTI-EVIDENCE RISK FUSION PREDICTION")
    print("=" * 70)
    print(f" [+] Model Engine   : {engine.model_type.upper()}")
    print(f" [+] Loaded Artifact: {args.model_dir}/xgboost_model.json")

    sample_feats = {
        "behavior_risk": args.behavior,
        "sensitivity_risk": args.sensitivity,
        "graph_risk": args.graph,
        "leakage_chain_score": args.temporal,
        "destination_risk": args.dest_risk,
        "historical_user_risk": args.user_risk,
        "after_hours_activity": args.after_hours,
        "usb_activity": args.usb,
        "new_device": args.new_dev,
        "external_destination": args.ext_dest
    }

    result = predict_sample(engine, sample_feats)

    print("\n[INPUT MULTI-EVIDENCE PROFILE]")
    for k, v in sample_feats.items():
        print(f"  - {k:24s}: {v}")

    print("\n[ASSESSMENT OUTCOME]")
    print(f"  * Final Risk Probability : {result['final_risk_probability']:.4f} ({result['final_risk_probability']*100:.2f}%)")
    print(f"  * Calibrated Risk Score  : {result['risk_score']:.1f} / 100.0")
    print(f"  * Threat Severity Tier   : {result['risk_tier']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
