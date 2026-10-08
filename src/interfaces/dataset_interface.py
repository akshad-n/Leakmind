"""
Dataset Ingestion Interface & Discovery Registry
Supports CERT insider threat dataset and provides graceful degradation when optional datasets
(DARPA Transparent Computing and Sensitive PII) are not yet available.
"""

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import os

from ..utils.config import config
from ..utils.logger import get_logger

logger = get_logger("leakmind.dataset_registry")


class DatasetStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_AVAILABLE_YET = "NOT_AVAILABLE_YET"
    PARTIAL = "PARTIAL"


class BaseDatasetConnector(ABC):
    """
    Abstract interface for all dataset connectors.
    """

    @abstractmethod
    def check_availability(self) -> DatasetStatus:
        """Checks if dataset files are accessible on disk."""
        pass

    @abstractmethod
    def get_summary(self) -> Dict[str, Any]:
        """Returns metadata summary of the dataset."""
        pass


class CERTDatasetConnector(BaseDatasetConnector):
    """
    Connector for CERT Insider Threat dataset.
    """

    def __init__(self, raw_dir: Optional[str] = None):
        if raw_dir is None:
            cert_cfg = config.datasets_config.get("cert", {})
            self.raw_dir = config.resolve_path(cert_cfg.get("raw_dir", "data/raw/r1/r1"))
        else:
            self.raw_dir = Path(raw_dir)

    def check_availability(self) -> DatasetStatus:
        if not self.raw_dir.exists():
            return DatasetStatus.NOT_AVAILABLE_YET

        required = ["logon.csv", "device.csv", "http.csv"]
        found = [f for f in required if (self.raw_dir / f).exists()]

        if len(found) == len(required):
            return DatasetStatus.AVAILABLE
        elif len(found) > 0:
            return DatasetStatus.PARTIAL
        return DatasetStatus.NOT_AVAILABLE_YET

    def get_summary(self) -> Dict[str, Any]:
        status = self.check_availability()
        files_info = {}
        if status != DatasetStatus.NOT_AVAILABLE_YET:
            for item in self.raw_dir.glob("*.csv"):
                files_info[item.name] = {
                    "size_mb": round(item.stat().st_size / (1024 * 1024), 2)
                }

        return {
            "name": "CERT Insider Threat Dataset",
            "status": status.value,
            "path": str(self.raw_dir),
            "files": files_info,
            "is_primary": True
        }


class SensitiveDataPIIConnector(BaseDatasetConnector):
    """
    Connector for future Sensitive Data & PII dataset (Phase 5).
    Gracefully degrades when dataset is missing.
    """

    def __init__(self, raw_dir: Optional[str] = None):
        if raw_dir is None:
            pii_cfg = config.datasets_config.get("sensitive_data_pii", {})
            self.raw_dir = config.resolve_path(pii_cfg.get("raw_dir", "data/raw/pii"))
        else:
            self.raw_dir = Path(raw_dir)

    def check_availability(self) -> DatasetStatus:
        if not self.raw_dir.exists():
            return DatasetStatus.NOT_AVAILABLE_YET
        files = list(self.raw_dir.glob("*"))
        return DatasetStatus.AVAILABLE if files else DatasetStatus.NOT_AVAILABLE_YET

    def get_summary(self) -> Dict[str, Any]:
        status = self.check_availability()
        return {
            "name": "Sensitive Data & PII Dataset",
            "status": status.value,
            "path": str(self.raw_dir),
            "note": "Optional dataset for Phase 5. Gracefully bypassed when missing."
        }


class DARPABigDataConnector(BaseDatasetConnector):
    """
    Connector for future DARPA Transparent Computing provenance dataset (Phase 6).
    Gracefully degrades when dataset or Neo4j instance is missing.
    """

    def __init__(self, raw_dir: Optional[str] = None):
        if raw_dir is None:
            darpa_cfg = config.datasets_config.get("darpa_tc", {})
            self.raw_dir = config.resolve_path(darpa_cfg.get("raw_dir", "data/raw/darpa"))
        else:
            self.raw_dir = Path(raw_dir)

    def check_availability(self) -> DatasetStatus:
        if not self.raw_dir.exists():
            return DatasetStatus.NOT_AVAILABLE_YET
        files = list(self.raw_dir.glob("*"))
        return DatasetStatus.AVAILABLE if files else DatasetStatus.NOT_AVAILABLE_YET

    def get_summary(self) -> Dict[str, Any]:
        status = self.check_availability()
        return {
            "name": "DARPA Transparent Computing Provenance Dataset",
            "status": status.value,
            "path": str(self.raw_dir),
            "note": "Optional dataset for Phase 6. Gracefully bypassed when missing."
        }


class DatasetRegistry:
    """
    Central discovery registry managing dataset availability without throwing unhandled exceptions.
    """

    def __init__(self):
        self.cert = CERTDatasetConnector()
        self.pii = SensitiveDataPIIConnector()
        self.darpa = DARPABigDataConnector()

    def discover_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Discovers all datasets and returns comprehensive status dictionary.
        """
        summary = {
            "cert": self.cert.get_summary(),
            "sensitive_data_pii": self.pii.get_summary(),
            "darpa_tc": self.darpa.get_summary()
        }
        logger.info(f"Dataset status check: CERT={summary['cert']['status']}, PII={summary['sensitive_data_pii']['status']}, DARPA={summary['darpa_tc']['status']}")
        return summary
