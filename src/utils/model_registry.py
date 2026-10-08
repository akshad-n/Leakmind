"""
Model Portability & Registry System
Supports training on Laptop A and inference on Laptop B without retraining.
Packages models alongside their preprocessing pipelines, feature schemas, and configurations.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib

from .logger import get_logger

logger = get_logger("leakmind.model_registry")


class ModelRegistry:
    """
    Standard interface for saving and loading portable models and their preprocessing pipelines.
    """

    @staticmethod
    def save_model(
        model: Any,
        preprocessor: Any,
        feature_columns: List[str],
        config: Dict[str, Any],
        model_dir: str,
        model_filename: str = "model.joblib"
    ) -> Dict[str, str]:
        """
        Saves model, preprocessing object, feature column definitions, and config into model_dir.
        
        Saved files:
        1. <model_filename> (e.g. isolation_forest.joblib or xgboost_model.json)
        2. preprocessing.joblib
        3. feature_columns.json
        4. config.json
        """
        out_dir = Path(model_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Save Model
        model_path = out_dir / model_filename
        if model_filename.endswith(".json") and hasattr(model, "save_model"):
            # Native XGBoost JSON format
            model.save_model(str(model_path))
        else:
            joblib.dump(model, model_path)

        # 2. Save Preprocessor / Scaler
        prep_path = out_dir / "preprocessing.joblib"
        joblib.dump(preprocessor, prep_path)

        # 3. Save Feature Columns
        feat_path = out_dir / "feature_columns.json"
        with open(feat_path, "w", encoding="utf-8") as f:
            json.dump({"feature_columns": list(feature_columns), "count": len(feature_columns)}, f, indent=2)

        # 4. Save Config
        conf_path = out_dir / "config.json"
        with open(conf_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Model and portable artifacts saved successfully to: {out_dir}")
        return {
            "model_path": str(model_path),
            "preprocessing_path": str(prep_path),
            "feature_columns_path": str(feat_path),
            "config_path": str(conf_path)
        }

    @staticmethod
    def load_model(
        model_dir: str,
        model_filename: str = "model.joblib"
    ) -> Tuple[Any, Any, List[str], Dict[str, Any]]:
        """
        Loads the portable bundle from model_dir.
        Returns: (model, preprocessor, feature_columns, config)
        """
        in_dir = Path(model_dir)
        if not in_dir.exists():
            raise FileNotFoundError(f"Model directory does not exist: {in_dir}")

        model_path = in_dir / model_filename
        prep_path = in_dir / "preprocessing.joblib"
        feat_path = in_dir / "feature_columns.json"
        conf_path = in_dir / "config.json"

        # Check for presence
        missing = [str(p.name) for p in [model_path, prep_path, feat_path, conf_path] if not p.exists()]
        if missing:
            raise FileNotFoundError(f"Missing required portable model artifacts in {in_dir}: {missing}")

        # 1. Load Model
        if model_filename.endswith(".json"):
            import xgboost as xgb
            model = xgb.XGBClassifier()
            model.load_model(str(model_path))
        else:
            model = joblib.load(model_path)

        # 2. Load Preprocessor
        preprocessor = joblib.load(prep_path)

        # 3. Load Feature Columns
        with open(feat_path, "r", encoding="utf-8") as f:
            feat_data = json.load(f)
            feature_columns = feat_data.get("feature_columns", [])

        # 4. Load Config
        with open(conf_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        logger.info(f"Model bundle loaded successfully from {in_dir} (Features: {len(feature_columns)})")
        return model, preprocessor, feature_columns, config


# Standardized functional wrappers as requested
def save_model(model: Any, preprocessor: Any, feature_columns: List[str], config: Dict[str, Any], model_dir: str, model_filename: str = "model.joblib") -> Dict[str, str]:
    return ModelRegistry.save_model(model, preprocessor, feature_columns, config, model_dir, model_filename)

def load_model(model_dir: str, model_filename: str = "model.joblib") -> Tuple[Any, Any, List[str], Dict[str, Any]]:
    return ModelRegistry.load_model(model_dir, model_filename)
