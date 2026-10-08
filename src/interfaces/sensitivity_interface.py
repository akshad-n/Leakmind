"""
Sensitive Data AI Interface (Phase 5)
Defines abstract contract for PII, financial, credentials, and confidential information detection.
Levels: LOW, MEDIUM, HIGH, CRITICAL.
Output: sensitivity_score (0–100) and sensitivity_level.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class SensitivityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BaseSensitivityDetector(ABC):
    """
    Abstract interface for sensitive content and PII detection.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Indicates if sensitive data module is available or pending dataset."""
        pass

    @abstractmethod
    def analyze_content(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, SensitivityLevel, List[str]]:
        """
        Analyzes payload or document content.
        Returns:
            sensitivity_score: float 0.0 to 100.0
            sensitivity_level: SensitivityLevel Enum
            detected_entities: List of matched PII or sensitive patterns
        """
        pass
