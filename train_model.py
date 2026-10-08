"""
LeakMind Phase 3: Model Training & Portability Packaging (Laptop A)
Trains the Isolation Forest behavior detector on CERT features and packages
the model, preprocessor, feature schema, configuration, and environment metadata
into a self-contained portable bundle for cross-laptop deployment.
"""

import json
import os
import platform
import sys
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.logger import get_logger

logger = get_logger("leakmind.train_model")


def capture_environment_metadata() -> dict:
    """Captures library versions and system environment for portability validation."""
    import sklearn
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "scikit_learn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "pandas_version": pd.__version__,
        "numpy_version": np.__version__
    }


def train_and_export_bundle(
    data_path: str = "data/processed/cert_daily_features.csv",
    save_dir: str = "saved_models/behavior",
    n_estimators: int = 100,
    contamination: float = 0.05,
    random_state: int = 42
):
    print("=" * 70)
    print("LEAKMIND MODEL PORTABILITY: TRAINING & PACKAGING (LAPTOP A)")
    print("=" * 70)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Processed CERT Telemetry
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Processed features dataset not found at: {data_path}")

    print(f"[1/5] Ingesting processed feature dataset from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"      Total records loaded: {len(df):,} rows")

    # 2. Separate Identifiers from Model Features
    id_cols = [c for c in ["user", "day"] if c in df.columns]
    feature_cols = [c for c in df.columns if c not in id_cols]

    print(f"[2/5] Isolating model feature schema:")
    print(f"      Identifiers (Excluded from training): {id_cols}")
    print(f"      Model Features ({len(feature_cols)}): {feature_cols}")

    X = df[feature_cols].copy().fillna(0.0)

    # 3. Fit Preprocessing Pipeline
    print(f"[3/5] Fitting StandardScaler preprocessing pipeline on Laptop A...")
    preprocessor = StandardScaler()
    X_scaled = preprocessor.fit_transform(X)

    # 4. Train Isolation Forest
    print(f"[4/5] Training Isolation Forest model (contamination={contamination})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_scaled)
    print("      Model training complete.")

    # 5. Package Portable Bundle for Laptop B
    print(f"[5/5] Exporting self-contained bundle to: {save_path}/")

    model_file = save_path / "isolation_forest.joblib"
    prep_file = save_path / "preprocessing.joblib"
    feat_file = save_path / "feature_columns.json"
    conf_file = save_path / "config.json"
    env_file = save_path / "environment.json"

    # Save binary estimator & scaler
    joblib.dump(model, model_file)
    joblib.dump(preprocessor, prep_file)

    # Save exact feature column ordering
    with open(feat_file, "w", encoding="utf-8") as f:
        json.dump({"feature_columns": feature_cols, "count": len(feature_cols)}, f, indent=2)

    # Save model hyperparameters & training context
    config_data = {
        "model_type": "IsolationForest",
        "n_estimators": n_estimators,
        "contamination": contamination,
        "random_state": random_state,
        "feature_count": len(feature_cols),
        "training_samples": len(df),
        "created_at_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }
    with open(conf_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)

    # Save environment / library versions
    env_data = capture_environment_metadata()
    with open(env_file, "w", encoding="utf-8") as f:
        json.dump(env_data, f, indent=2)

    print(f"  [+] 1. Model Estimator         -> {model_file.name}")
    print(f"  [+] 2. Preprocessing Pipeline  -> {prep_file.name}")
    print(f"  [+] 3. Feature Column Schema   -> {feat_file.name}")
    print(f"  [+] 4. Model Configuration     -> {conf_file.name}")
    print(f"  [+] 5. Environment Metadata    -> {env_file.name}")

    print("=" * 70)
    print("PORTABLE MODEL BUNDLE READY FOR LAPTOP B DEPLOYMENT!")
    print(f"Copy the '{save_dir}' folder to Laptop B and run 'predict.py'.")
    print("=" * 70)


if __name__ == "__main__":
    train_and_export_bundle()
