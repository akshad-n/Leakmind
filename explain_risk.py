"""
LeakMind Phase 9: SHAP Explainability & Incident Interpretability Pipeline
Computes true SHAP values using the production trained XGBoost risk model.

Outputs:
1. Global Feature Importance across all evaluated telemetry.
2. Individual Incident Explanations for all high-risk incidents:
   - Final Risk Score
   - Top Positive Risk Factors (driving risk up)
   - Top Negative Risk Factors (mitigating risk)
   - Formatted forensic summary per user prompt specification.

Strict Constraint: Uses actual SHAP values - never hardcodes example values.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import shap
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.explainability import ShapRiskExplainer, HUMAN_FEATURE_NAMES
from train_risk_model import build_multimodal_dataset
from src.utils.logger import get_logger

logger = get_logger("leakmind.explain_risk")


def run_explainability_pipeline(
    model_path: str = "saved_models/risk/xgboost_model.json",
    feature_columns_path: str = "saved_models/risk/feature_columns.json",
    data_path: str = "data/processed/cert_context_supervised.csv",
    save_dir: str = "saved_models/risk",
    reports_dir: str = "reports",
    high_risk_threshold: float = 60.0
) -> Dict[str, Any]:
    """
    Executes the complete Phase 9 SHAP Explainability pipeline.
    """
    print("=" * 80)
    print("LEAKMIND PHASE 9: SHAP RISK EXPLAINABILITY PIPELINE")
    print("=" * 80)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    rep_path = Path(reports_dir)
    rep_path.mkdir(parents=True, exist_ok=True)

    # 1. Load Trained XGBoost Model & Features
    print("[1/4] Loading Trained XGBoost Risk Model & Feature Order...")
    explainer_engine = ShapRiskExplainer.load(model_path, feature_columns_path)
    feat_cols = explainer_engine.feature_names
    print(f"      Loaded Model from : {model_path}")
    print(f"      Feature Count     : {len(feat_cols)}")
    print(f"      Features Order    : {feat_cols}")

    # 2. Build Multi-Evidence Telemetry
    print("\n[2/4] Assembling Multi-Evidence Telemetry Dataset...")
    df_fused, _ = build_multimodal_dataset(data_path)
    X = df_fused[feat_cols]
    y = df_fused["insider_label"]
    print(f"      Evaluated Samples : {len(df_fused)} (Normal: {(y == 0).sum()}, Insider: {(y == 1).sum()})")

    # 3. Compute Global Feature Importance
    print("\n[3/4] Computing Global Feature Importance across entire dataset...")
    global_importance = explainer_engine.compute_global_feature_importance(X)

    print("\n" + "=" * 80)
    print("GLOBAL SHAP FEATURE IMPORTANCE (ACTUAL MODEL ATTRIBUTIONS)")
    print("=" * 80)
    print(f"{'Rank':4s} {'Feature Name':26s} {'Human Forensic Label':30s} {'Mean |SHAP|':12s} {'Relative %':10s} {'Direction':14s}")
    print("-" * 102)
    for rank, item in enumerate(global_importance["rankings"], 1):
        print(
            f"#{rank:<3d} "
            f"{item['feature']:26s} "
            f"{item['label']:30s} "
            f"{item['mean_abs_shap']:10.4f}   "
            f"{item['relative_importance_pct']:8.2f}%   "
            f"{item['primary_direction']:14s}"
        )
    print("-" * 102)

    # 4. Explain Individual High-Risk Incidents
    print("\n[4/4] Generating Local SHAP Explanations for High-Risk Incidents...")
    # Evaluate model predictions
    probs = explainer_engine.model.predict_proba(X.values)[:, 1]
    scores = probs * 100.0

    high_risk_mask = scores >= high_risk_threshold
    high_risk_indices = df_fused[high_risk_mask].index.tolist()
    print(f"      Total High-Risk Incidents Identified (Risk >= {high_risk_threshold}%): {len(high_risk_indices)}")

    incident_explanations = []

    print("\n" + "=" * 80)
    print("INDIVIDUAL HIGH-RISK INCIDENT EXPLANATIONS (ACTUAL SHAP CONTRIBUTIONS)")
    print("=" * 80)

    for idx in high_risk_indices:
        row = X.loc[idx]
        user = str(df_fused.loc[idx, "user"])
        actual_label = int(df_fused.loc[idx, "insider_label"])

        explanation = explainer_engine.explain_instance(row)
        explanation["user"] = user
        explanation["index"] = int(idx)
        explanation["ground_truth_label"] = actual_label
        incident_explanations.append(explanation)

        print(f"\n[INCIDENT: {user}] (Ground Truth: {'INSIDER' if actual_label == 1 else 'NORMAL'})")
        print("-" * 60)
        print(f"Final Risk: {explanation['final_risk_score']:.0f}%\n")

        print("Top positive risk factors:")
        if explanation["top_positive_risk_factors"]:
            for f in explanation["top_positive_risk_factors"]:
                print(f"  {f['label']}: {f['contribution']} (+{f['shap_value']:.3f}, val={f['actual_value']})")
        else:
            print("  None (no positive drivers)")

        print("\nTop negative risk factors:")
        if explanation["top_negative_risk_factors"]:
            for f in explanation["top_negative_risk_factors"]:
                print(f"  {f['label']}: {f['contribution']} ({f['shap_value']:.3f}, val={f['actual_value']})")
        else:
            print("  None (no mitigating factors)")

        print("\nForensic Incident Narrative (User Prompt Specification Format):")
        print("  " + "\n  ".join(explanation["formatted_explanation"].splitlines()))
        print("-" * 60)

    # 5. Export Explanations & Reports
    summary_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "model_path": str(model_path),
        "total_samples_analyzed": len(df_fused),
        "high_risk_threshold": high_risk_threshold,
        "high_risk_incidents_count": len(incident_explanations),
        "base_expected_value": explainer_engine.base_value,
        "global_feature_importance": global_importance["rankings"],
        "high_risk_incidents": incident_explanations
    }

    report_file1 = rep_path / "shap_explainability_report.json"
    report_file2 = save_path / "shap_summary.json"

    with open(report_file1, "w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)
    with open(report_file2, "w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)

    print(f"\n[+] Saved complete SHAP report to : {report_file1}")
    print(f"[+] Saved summary artifacts to   : {report_file2}")
    print("=" * 80)
    print("PHASE 9 SHAP EXPLAINABILITY PIPELINE COMPLETE!")
    print("=" * 80)

    return summary_report


def main():
    parser = argparse.ArgumentParser(
        description="LeakMind Phase 9: SHAP Explainability & Incident Attribution"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="saved_models/risk/xgboost_model.json",
        help="Path to trained XGBoost model JSON"
    )
    parser.add_argument(
        "--features",
        type=str,
        default="saved_models/risk/feature_columns.json",
        help="Path to feature columns JSON"
    )
    parser.add_argument(
        "--data",
        type=str,
        default="data/processed/cert_context_supervised.csv",
        help="Path to input dataset"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=60.0,
        help="High risk threshold (default 60.0%%)"
    )

    args = parser.parse_args()
    run_explainability_pipeline(
        model_path=args.model,
        feature_columns_path=args.features,
        data_path=args.data,
        high_risk_threshold=args.threshold
    )


if __name__ == "__main__":
    main()
