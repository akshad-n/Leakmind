"""
LeakMind Configuration Manager
Provides portable path resolution and centralized configuration access across different laptops.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class ConfigManager:
    """
    Manages LeakMind configuration and ensures path portability between environments.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.project_root = self._detect_project_root()
        if config_path is None:
            self.config_path = self.project_root / "config" / "config.json"
        else:
            self.config_path = Path(config_path)
            if not self.config_path.is_absolute():
                self.config_path = self.project_root / self.config_path

        self._config: Dict[str, Any] = {}
        self.load()

    def _detect_project_root(self) -> Path:
        """
        Detects project root directory by traversing upwards until finding config/ or requirements.txt.
        """
        current = Path(__file__).resolve().parent
        for parent in [current] + list(current.parents):
            if (parent / "config" / "config.json").exists() or (parent / "requirements.txt").exists():
                return parent
        # Fallback to current working directory
        return Path(os.getcwd()).resolve()

    def load(self):
        """Loads configuration from JSON file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found at: {self.config_path}")
        with open(self.config_path, "r", encoding="utf-8") as f:
            self._config = json.load(f)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves top-level configuration key."""
        return self._config.get(key, default)

    def resolve_path(self, relative_path: str) -> Path:
        """Resolves relative project path to an absolute path on the host machine."""
        return (self.project_root / relative_path).resolve()

    @property
    def project_title(self) -> str:
        return self._config.get("project_title", "LeakMind")

    @property
    def datasets_config(self) -> Dict[str, Any]:
        return self._config.get("datasets", {})

    @property
    def model_portability_config(self) -> Dict[str, Any]:
        return self._config.get("model_portability", {})

    @property
    def policy_thresholds(self) -> Dict[str, float]:
        return self._config.get("policy_engine", {}).get("thresholds", {
            "allow_max": 40.0,
            "monitor_max": 70.0,
            "alert_max": 90.0,
            "block_min": 90.0
        })

    def get_model_save_dir(self, module_type: str) -> Path:
        """
        Returns portable directory path for saving/loading models:
        'behavior', 'sensitivity', or 'risk'
        """
        mapping = {
            "behavior": "saved_models/behavior",
            "sensitivity": "saved_models/sensitivity",
            "risk": "saved_models/risk"
        }
        rel_path = mapping.get(module_type, f"saved_models/{module_type}")
        full_path = self.resolve_path(rel_path)
        full_path.mkdir(parents=True, exist_ok=True)
        return full_path


# Global default configuration instance
config = ConfigManager()
