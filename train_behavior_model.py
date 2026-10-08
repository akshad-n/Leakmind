"""
LeakMind Phase 2: Behavior Anomaly Model Training
Trains Isolation Forest on processed CERT features, normalizes risk to 0-100,
evaluates against CERT insider threat benchmark labels, and saves portable artifacts.
"""

import json
import os
import sys
import time
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix
)

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.logger import get_logger

logger = get_logger("leakmind.train_behavior")


def raw_to_behavior_risk(decision_score: np.ndarray) -> np.ndarray:
    """
    Transforms Isolation Forest decision function scores into a calibrated
    behavior risk score bounded to [0.0, 100.0].
    decision_function returns negative values for anomalies, positive for inliers.
    """
    risk = 100.0 / (1.0 + np.exp(decision_score * 10.0))
    return np.round(np.clip(risk, 0.0, 100.0), 2)


def train_behavior_model(
    data_path: str = "data/processed/cert_daily_features.csv",
    save_dir: str = "saved_models/behavior",
    n_estimators: int = 100,
    contamination: float = 0.05,
    random_state: int = 42
):
    print("=" * 70)
    print("LEAKMIND PHASE 2: ISOLATION FOREST BEHAVIOR DETECTOR TRAINING")
    print("=" * 70)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)

    # 1. Load Processed Features from Phase 1
    logger.info(f"Loading training data from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"[1/5] Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")

    # 2. Separate Identifiers/Timestamps from Model Features
    id_cols = [c for c in ["user", "day"] if c in df.columns]
    feature_cols = [c for c in df.columns if c not in id_cols]

    print(f"[2/5] Feature Separation:")
    print(f"  - Identifiers/Timestamps : {id_cols}")
    print(f"  - Model Input Features ({len(feature_cols)}): {feature_cols}")

    X = df[feature_cols].copy()

    # 3. Handle Missing Values
    null_count = X.isna().sum().sum()
    if null_count > 0:
        logger.warning(f"Found {null_count} NaNs in feature matrix. Imputing with 0.0.")
        X = X.fillna(0.0)
    else:
        print("  - Missing Values Check    : 0 NaNs detected (Dataset clean)")

    # 4. Fit Preprocessing Pipeline (StandardScaler)
    print("\n[3/5] Fitting Preprocessing Pipeline...")
    preprocessor = StandardScaler()
    X_scaled = preprocessor.fit_transform(X)

    # 5. Train Isolation Forest
    print("\n[4/5] Training Isolation Forest...")
    iso_forest = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    iso_forest.fit(X_scaled)
    print("  - Model training complete.")

    # 6. Save Portable Model Artifacts
    print("\n[5/5] Saving Portable Model Bundle to saved_models/behavior/...")
    model_file = save_path / "isolation_forest.joblib"
    prep_file = save_path / "preprocessing.joblib"
    feat_file = save_path / "feature_columns.json"
    conf_file = save_path / "config.json"

    joblib.dump(iso_forest, model_file)
    joblib.dump(preprocessor, prep_file)

    with open(feat_file, "w", encoding="utf-8") as f:
        json.dump({"feature_columns": feature_cols, "count": len(feature_cols)}, f, indent=2)

    config_data = {
        "model_type": "IsolationForest",
        "n_estimators": n_estimators,
        "contamination": contamination,
        "random_state": random_state,
        "feature_count": len(feature_cols),
        "training_samples": len(df),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
    with open(conf_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    print(f"  [+] Saved Model         : {model_file}")
    print(f"  [+] Saved Preprocessor  : {prep_file}")
    print(f"  [+] Saved Feature Schema: {feat_file}")
    print(f"  [+] Saved Model Config  : {conf_file}")

    # 7. Evaluate on CERT Insider Threat Benchmark Labels
    print("\n" + "=" * 70)
    print("BENCHMARK EVALUATION (CERT INSIDER THREAT GROUND TRUTH)")
    print("=" * 70)

    eval_data_path = Path("data/processed/X_daily_supervised.csv")
    eval_labels_path = Path("data/processed/y_daily_supervised.csv")

    if eval_data_path.exists() and eval_labels_path.exists():
        X_eval_raw = pd.read_csv(eval_data_path)
        y_eval = pd.read_csv(eval_labels_path).iloc[:, 0].values

        # Align features to the 15 trained feature columns
        # Fill missing features with 0.0 (or matching columns)
        X_eval_aligned = pd.DataFrame(0.0, index=range(len(X_eval_raw)), columns=feature_cols)
        
        # Column mapping from daily supervised format to full feature format
        col_alias_map = {
            "http_activity_count": "web_activity",
            "after_hours_activity": "after_hours_activity",
            "logon_count": "login_frequency",
            "logoff_count": "logoff_count",
            "after_hours_logon": "after_hours_logon",
            "unique_pcs": "unique_pcs",
            "device_connect_count": "device_connect_count",
            "device_disconnect_count": "device_disconnect_count",
            "total_device_events": "usb_usage"
        }
        for src_col, target_col in col_alias_map.items():
            if src_col in X_eval_raw.columns and target_col in X_eval_aligned.columns:
                X_eval_aligned[target_col] = X_eval_raw[src_col].values

        X_eval_scaled = preprocessor.transform(X_eval_aligned)
        raw_decision_scores = iso_forest.decision_function(X_eval_scaled)
        behavior_risks = raw_to_behavior_risk(raw_decision_scores)

        # Invert decision score for anomaly ranking (lower decision function = higher anomaly)
        y_scores = -raw_decision_scores
        
        # Predictions based on the Isolation Forest contamination threshold (decision_function < 0)
        y_pred = (raw_decision_scores < 0).astype(int)

        prec = precision_score(y_eval, y_pred, zero_division=0)
        rec = recall_score(y_eval, y_pred, zero_division=0)
        f1 = f1_score(y_eval, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_eval, y_scores)
        
        prec_curve, rec_curve, _ = precision_recall_curve(y_eval, y_scores)
        pr_auc = auc(rec_curve, prec_curve)

        cm = confusion_matrix(y_eval, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"Evaluation Set Size : {len(y_eval)} (Normal: {tn+fp}, Insiders: {tp+fn})")
        print(f"Confusion Matrix    : TN={tn}, FP={fp}, FN={fn}, TP={tp}")
        print("-" * 50)
        print(f"Precision           : {prec:.4f}")
        print(f"Recall              : {rec:.4f}")
        print(f"F1-Score            : {f1:.4f}")
        print(f"ROC-AUC             : {roc_auc:.4f}")
        print(f"PR-AUC              : {pr_auc:.4f}")
        print(f"False Positive Rate : {fpr:.4f}")
        print("-" * 50)
        print(f"Sample Inferred Behavior Risks (0-100):")
        print(f"  - Mean Risk for Normal Days   : {behavior_risks[y_eval == 0].mean():.2f}%")
        print(f"  - Mean Risk for Insider Events: {behavior_risks[y_eval == 1].mean():.2f}%")
    else:
        print("Supervised CERT evaluation dataset not found. Unsupervised training complete.")

    print("=" * 70)


if __name__ == "__main__":
    train_behavior_model()
