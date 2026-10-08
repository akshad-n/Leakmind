"""
Policy Engine Interface (Phase 10)
Defines abstract contract for policy-based response: ALLOW, MONITOR, ALERT, BLOCK.
Thresholds are configurable and tunable via validation feedback.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    ALERT = "ALERT"
    ALERT_APPROVAL = "ALERT / APPROVAL"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class BasePolicyEngine(ABC):
    """
    Abstract interface for automated policy evaluation and response dispatching.
    Thresholds represent initial heuristic boundaries and are explicitly not claimed to be optimal.
    """

    @abstractmethod
    def evaluate(
        self,
        risk_score: float,
        sensitivity_level: Any = "LOW",
        destination_risk: Any = "Internal",
        context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Any:
        """
        Maps risk score, sensitivity level, destination risk, and context to an actionable policy response.
        Returns a policy evaluation result containing:
        - decision
        - reason
        - risk
        - policy_rule_triggered
        """
        pass

    @abstractmethod
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Configures or fine-tunes policy boundaries dynamically."""
        pass

    @abstractmethod
    def get_thresholds(self) -> Dict[str, float]:
        """Returns active threshold dictionary."""
        pass
