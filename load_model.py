"""
LeakMind Phase 3: Model Bundle Loader (Laptop B)
Loads the portable Isolation Forest bundle (model, preprocessor, feature schema, config)
and verifies readiness for inference with ZERO retraining.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
import joblib

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.logger import get_logger

logger = get_logger("leakmind.load_model")


def load_behavior_bundle(
    model_dir: str = "saved_models/behavior"
) -> Tuple[Any, Any, List[str], Dict[str, Any], Dict[str, Any]]:
    """
    Loads all five components of the portable model bundle from disk:
    1. model: Trained IsolationForest instance
    2. preprocessor: Fitted StandardScaler instance
    3. feature_columns: Ordered list of feature names
    4. config: Model hyperparameter dictionary
    5. environment: Library version metadata from training machine
    """
    path = Path(model_dir)
    if not path.exists():
        raise FileNotFoundError(f"Model directory does not exist: {path}")

    model_file = path / "isolation_forest.joblib"
    prep_file = path / "preprocessing.joblib"
    feat_file = path / "feature_columns.json"
    conf_file = path / "config.json"
    env_file = path / "environment.json"

    # Verify presence of mandatory artifacts
    required_files = [model_file, prep_file, feat_file, conf_file]
    missing = [str(f.name) for f in required_files if not f.exists()]
    if missing:
        raise FileNotFoundError(f"Incomplete bundle in {model_dir}. Missing: {missing}")

    # 1. Load Model
    model = joblib.load(model_file)

    # 2. Load Preprocessor
    preprocessor = joblib.load(prep_file)

    # 3. Load Feature Columns
    with open(feat_file, "r", encoding="utf-8") as f:
        feat_data = json.load(f)
        feature_columns = feat_data.get("feature_columns", [])

    # 4. Load Config
    with open(conf_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    # 5. Load Environment Info (if present)
    env_info = {}
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            env_info = json.load(f)

    logger.info(f"Successfully loaded portable bundle from {model_dir} ({len(feature_columns)} features).")
    return model, preprocessor, feature_columns, config, env_info


def main():
    parser = argparse.ArgumentParser(description="LeakMind Portable Model Loader")
    parser.add_argument("--model-dir", type=str, default="saved_models/behavior", help="Bundle directory")
    args = parser.parse_args()

    print("=" * 70)
    print("LEAKMIND MODEL PORTABILITY: BUNDLE VERIFICATION (LAPTOP B)")
    print("=" * 70)
    print(f"Inspecting portable model bundle at: {args.model_dir}/\n")

    try:
        model, preprocessor, features, conf, env = load_behavior_bundle(args.model_dir)

        print("[+] 1. Model Estimator Loaded:")
        print(f"      Type          : {type(model).__name__}")
        print(f"      n_estimators  : {getattr(model, 'n_estimators', 'N/A')}")
        print(f"      contamination : {getattr(model, 'contamination', 'N/A')}")

        print("\n[+] 2. Preprocessing Pipeline Loaded:")
        print(f"      Type          : {type(preprocessor).__name__}")
        print(f"      Features In   : {getattr(preprocessor, 'n_features_in_', len(features))}")

        print(f"\n[+] 3. Feature Column Ordering ({len(features)} Features):")
        for i, col in enumerate(features, 1):
            print(f"      {i:2d}. {col}")

        print("\n[+] 4. Model Configuration:")
        for k, v in conf.items():
            print(f"      - {k}: {v}")

        if env:
            print("\n[+] 5. Training Environment Metadata (From Laptop A):")
            for k, v in env.items():
                print(f"      - {k}: {v}")

        print("\n" + "=" * 70)
        print("VERIFICATION SUCCESSFUL: MODEL IS 100% READY FOR INFERENCE")
        print("ZERO RETRAINING REQUIRED ON THIS LAPTOP!")
        print("=" * 70)

    except Exception as e:
        print(f"[!] Bundle verification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
