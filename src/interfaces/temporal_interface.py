"""
Temporal Event Correlation Interface (Phase 7)
Defines abstract contract for correlating multi-stage temporal event sequences.
Example sequence: Sensitive File Access -> USB Connect (10m) -> Copy -> External Upload (30m).
Output: leakage_chain_score (0–100).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseTemporalCorrelator(ABC):
    """
    Abstract interface for temporal leakage sequence correlation.
    """

    @abstractmethod
    def correlate_events(
        self,
        events: List[Dict[str, Any]],
        window_minutes: int = 60
    ) -> Dict[str, Any]:
        """
        Evaluates temporal chains within rolling time windows.
        Returns:
            leakage_chain_score: float 0.0 to 100.0
            matched_sequences: List of triggered temporal attack patterns
            stages_completed: int
        """
        pass
