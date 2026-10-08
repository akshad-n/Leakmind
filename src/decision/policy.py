"""
LeakMind Policy Engine (Phase 10)
Translates multi-evidence risk assessments, data sensitivity levels, egress destinations,
and environmental context into automated, policy-aware defensive actions.

Inputs:
- final risk: Quantitative risk score [0.0 - 100.0]
- sensitivity level: LOW, MEDIUM, HIGH, CRITICAL
- destination risk: Egress destination (e.g. "External Cloud", "USB", "Internal") or destination score
- context: Environmental signals (after_hours, user, process, device, etc.)

Initial Configurable Rules:
- risk < 40        -> ALLOW
- 40 <= risk < 70  -> MONITOR
- 70 <= risk <= 90 -> ALERT / APPROVAL
- risk > 90        -> BLOCK

Notice:
These initial policy thresholds (40, 70, 90) represent heuristic baseline governance boundaries
for demonstration and control. They are explicitly NOT claimed to be optimal without organization-specific
calibration and empirical loss tuning.
"""

import enum
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from ..interfaces.policy_interface import BasePolicyEngine, PolicyDecision
from ..utils.logger import get_logger

logger = get_logger("leakmind.policy")

POLICY_OPTIMALITY_DISCLAIMER = (
    "Notice: Configurable policy thresholds (40, 70, 90) represent initial heuristic baseline "
    "governance boundaries and are explicitly NOT claimed to be optimal."
)


class PolicyAction(str, enum.Enum):
    """Actions dispatched by the policy and decision engines."""
    OBSERVE = "OBSERVE"
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    ALERT = "ALERT"
    ALERT_APPROVAL = "ALERT / APPROVAL"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    RESTRICT_BLOCK = "RESTRICT_BLOCK"
    BLOCK = "BLOCK"
    ENCRYPT_QUARANTINE = "ENCRYPT_QUARANTINE"


@dataclass
class PolicyRule:
    """
    Configurable policy rule definition.
    """
    rule_id: str
    name: str
    condition_desc: str
    decision: str
    priority: int = 50
    condition_fn: Optional[Callable[[float, str, Any, Dict[str, Any]], bool]] = None


@dataclass
class PolicyResult:
    """
    Structured outcome of a policy evaluation.
    Conforms to the required Phase 10 outputs:
    - decision
    - reason
    - risk
    - policy_rule_triggered
    """
    decision: str
    reason: str
    risk: float
    policy_rule_triggered: str
    sensitivity_level: str = "LOW"
    destination_risk: Any = "Internal"
    context: Dict[str, Any] = field(default_factory=dict)
    action: Optional[PolicyAction] = None

    @property
    def value(self) -> str:
        """Enables enum duck-typing compatibility with PolicyAction / PolicyDecision."""
        return self.decision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "risk": float(self.risk),
            "policy_rule_triggered": self.policy_rule_triggered,
            "sensitivity_level": self.sensitivity_level,
            "destination_risk": self.destination_risk,
            "context": self.context,
            "action": self.action.value if self.action else self.decision,
            "disclaimer": POLICY_OPTIMALITY_DISCLAIMER
        }

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __str__(self) -> str:
        dest_str = str(self.destination_risk)
        return (
            f"Risk = {self.risk:g}\n"
            f"Sensitivity = {self.sensitivity_level}\n"
            f"Destination = {dest_str}\n\n"
            f"Decision = {self.decision}"
        )


class PolicyEngine(BasePolicyEngine):
    """
    LeakMind Policy Engine (Phase 10).
    Evaluates multi-evidence risk, data sensitivity, destination risk, and context against
    configurable rules to produce actionable containment and monitoring decisions.
    """

    DISCLAIMER = POLICY_OPTIMALITY_DISCLAIMER

    def __init__(
        self,
        allow_threshold: float = 40.0,
        monitor_threshold: float = 70.0,
        alert_threshold: float = 90.0,
        block_threshold: float = 90.0,
        config_path: Optional[str] = None,
        enable_contextual_escalation: bool = True
    ):
        """
        Initializes the Policy Engine with configurable thresholds.

        Parameters:
        - allow_threshold: Maximum risk for ALLOW (default < 40.0 -> ALLOW)
        - monitor_threshold: Upper boundary for MONITOR (default 40.0 <= risk < 70.0 -> MONITOR)
        - alert_threshold: Upper boundary for ALERT / APPROVAL (default 70.0 <= risk <= 90.0 -> ALERT / APPROVAL)
        - block_threshold: Lower boundary for BLOCK (default risk > 90.0 -> BLOCK)
        """
        self.allow_threshold = float(allow_threshold)
        self.monitor_threshold = float(monitor_threshold)
        self.alert_threshold = float(alert_threshold)
        self.block_threshold = float(block_threshold)
        self.enable_contextual_escalation = enable_contextual_escalation
        self.custom_rules: List[PolicyRule] = []

        if config_path and os.path.exists(config_path):
            self.load_config(config_path)

        logger.info(
            f"Initialized PolicyEngine (allow<{self.allow_threshold}, "
            f"monitor<{self.monitor_threshold}, alert<={self.alert_threshold}, block>{self.block_threshold}). "
            f"{self.DISCLAIMER}"
        )

    def get_thresholds(self) -> Dict[str, float]:
        """Returns active threshold dictionary."""
        return {
            "allow_threshold": self.allow_threshold,
            "monitor_threshold": self.monitor_threshold,
            "alert_threshold": self.alert_threshold,
            "block_threshold": self.block_threshold
        }

    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """
        Configures or fine-tunes policy boundaries dynamically.
        Validates monotonic ordering: 0 <= allow <= monitor <= alert <= block <= 100.
        """
        allow = float(new_thresholds.get("allow_threshold", self.allow_threshold))
        monitor = float(new_thresholds.get("monitor_threshold", self.monitor_threshold))
        alert = float(new_thresholds.get("alert_threshold", self.alert_threshold))
        block = float(new_thresholds.get("block_threshold", self.block_threshold))

        if not (0.0 <= allow <= monitor <= alert <= block <= 100.0):
            raise ValueError(
                f"Invalid threshold ordering: ensure 0 <= allow ({allow}) <= monitor ({monitor}) "
                f"<= alert ({alert}) <= block ({block}) <= 100"
            )

        self.allow_threshold = allow
        self.monitor_threshold = monitor
        self.alert_threshold = alert
        self.block_threshold = block

        logger.info(
            f"Policy thresholds updated: allow<{self.allow_threshold}, monitor<{self.monitor_threshold}, "
            f"alert<={self.alert_threshold}, block>{self.block_threshold}"
        )

    def add_rule(self, rule: PolicyRule):
        """Adds a custom user-defined policy rule."""
        self.custom_rules.append(rule)
        self.custom_rules.sort(key=lambda r: r.priority, reverse=True)

    def _normalize_sensitivity(self, sensitivity_level: Any) -> str:
        """Normalizes sensitivity input into LOW, MEDIUM, HIGH, or CRITICAL."""
        if hasattr(sensitivity_level, "value"):
            return str(sensitivity_level.value).upper()
        if isinstance(sensitivity_level, (int, float)):
            if sensitivity_level >= 75.0:
                return "CRITICAL"
            elif sensitivity_level >= 50.0:
                return "HIGH"
            elif sensitivity_level >= 25.0:
                return "MEDIUM"
            return "LOW"
        s_str = str(sensitivity_level).strip().upper()
        if "CRIT" in s_str:
            return "CRITICAL"
        elif "HIGH" in s_str:
            return "HIGH"
        elif "MED" in s_str:
            return "MEDIUM"
        return "LOW"

    def _is_external_destination(self, destination: Any) -> bool:
        """Determines whether destination represents an external, untrusted, or egress target."""
        if isinstance(destination, (int, float)):
            return destination >= 50.0
        d_str = str(destination).strip().lower()
        external_keywords = [
            "external", "cloud", "usb", "removable", "public", "internet",
            "dropbox", "drive", "box", "s3", "github", "pastebin", "personal", "remote"
        ]
        return any(k in d_str for k in external_keywords)

    def evaluate(
        self,
        final_risk: float,
        sensitivity_level: Any = "LOW",
        destination_risk: Any = "Internal",
        context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> PolicyResult:
        """
        Evaluates risk score, data sensitivity, destination risk, and context against configurable policy rules.

        Inputs:
        - final_risk: Risk score (0.0 to 100.0)
        - sensitivity_level: LOW, MEDIUM, HIGH, CRITICAL (or enum/score)
        - destination_risk: Destination name (e.g., 'External Cloud') or risk score
        - context: Optional environment metadata dict

        Returns:
        PolicyResult with:
        - decision: ALLOW, MONITOR, ALERT / APPROVAL, BLOCK
        - reason: Explainable policy rationale
        - risk: Evaluated risk score
        - policy_rule_triggered: Identifier of triggered rule
        """
        # Support kwargs / polymorphic calling conventions
        if "risk_score" in kwargs:
            final_risk = kwargs["risk_score"]
        elif "risk" in kwargs:
            final_risk = kwargs["risk"]

        if isinstance(sensitivity_level, dict):
            # Interface compatibility: caller passed context as 2nd positional parameter
            ctx = sensitivity_level
            sensitivity_level = ctx.get("sensitivity_level", "LOW")
            destination_risk = ctx.get("destination_risk", "Internal")
            context = ctx

        context = context or {}
        risk = float(final_risk)
        norm_sensitivity = self._normalize_sensitivity(sensitivity_level)
        is_external = self._is_external_destination(destination_risk)

        # 1. Evaluate custom rules first (sorted by priority descending)
        for custom_rule in self.custom_rules:
            if custom_rule.condition_fn:
                try:
                    if custom_rule.condition_fn(risk, norm_sensitivity, destination_risk, context):
                        return PolicyResult(
                            decision=custom_rule.decision,
                            reason=f"Custom rule triggered: {custom_rule.name}. {custom_rule.condition_desc}",
                            risk=risk,
                            policy_rule_triggered=custom_rule.rule_id,
                            sensitivity_level=norm_sensitivity,
                            destination_risk=destination_risk,
                            context=context,
                            action=self._map_to_policy_action(custom_rule.decision)
                        )
                except Exception as e:
                    logger.warning(f"Error evaluating custom rule {custom_rule.rule_id}: {e}")

        # 2. Contextual Escalation Rules (Configurable)
        if self.enable_contextual_escalation:
            # Rule: Critical Data Egress Containment
            # High-risk exfiltration of CRITICAL assets to External/Cloud targets
            if risk > self.block_threshold and norm_sensitivity == "CRITICAL" and is_external:
                return PolicyResult(
                    decision="BLOCK",
                    reason=(
                        f"Risk score ({risk:.1f}%) exceeds critical threshold (>{self.block_threshold:.1f}%) "
                        f"with CRITICAL sensitive data directed to {destination_risk} destination. "
                        f"Immediate blocking and session isolation enforced."
                    ),
                    risk=risk,
                    policy_rule_triggered="RULE_CRITICAL_EGRESS_BLOCK",
                    sensitivity_level=norm_sensitivity,
                    destination_risk=destination_risk,
                    context=context,
                    action=PolicyAction.BLOCK
                )

            # Rule: After-hours Removable Storage Vector
            is_after_hours = (
                context.get("is_after_hours", False)
                or context.get("after_hours_activity", 0) > 0
                or context.get("after_hours", False)
            )
            has_usb = (
                "usb" in str(destination_risk).lower()
                or context.get("usb_activity", 0) > 0
                or context.get("is_after_hours_usb", False)
            )
            if is_after_hours and has_usb and risk >= 80.0:
                return PolicyResult(
                    decision="BLOCK",
                    reason=(
                        f"After-hours removable storage exfiltration vector detected with elevated risk ({risk:.1f}%). "
                        f"Endpoint storage transfer blocked per organizational physical containment policy."
                    ),
                    risk=risk,
                    policy_rule_triggered="RULE_AFTER_HOURS_USB_BLOCK",
                    sensitivity_level=norm_sensitivity,
                    destination_risk=destination_risk,
                    context=context,
                    action=PolicyAction.RESTRICT_BLOCK
                )

            # Rule: Sensitive Data Egress Escalation
            if norm_sensitivity in ("HIGH", "CRITICAL") and is_external and risk >= self.monitor_threshold:
                if risk > self.block_threshold:
                    # Captured above or falls through to base block
                    pass
                else:
                    return PolicyResult(
                        decision="ALERT / APPROVAL",
                        reason=(
                            f"Sensitive data ({norm_sensitivity}) egress directed to external target ({destination_risk}) "
                            f"with elevated risk ({risk:.1f}%). Action suspended pending security approval."
                        ),
                        risk=risk,
                        policy_rule_triggered="RULE_SENSITIVE_EGRESS_APPROVAL",
                        sensitivity_level=norm_sensitivity,
                        destination_risk=destination_risk,
                        context=context,
                        action=PolicyAction.ALERT_APPROVAL
                    )

        # 3. Baseline Configurable Threshold Rules:
        # risk < 40        -> ALLOW
        # 40 <= risk < 70  -> MONITOR
        # 70 <= risk <= 90 -> ALERT / APPROVAL
        # risk > 90        -> BLOCK

        if risk > self.block_threshold:
            decision = "BLOCK"
            rule_id = "RULE_HIGH_RISK_BLOCK"
            reason = (
                f"Risk score ({risk:.1f}%) exceeds critical block threshold (>{self.block_threshold:.1f}%). "
                f"Operation strictly blocked and isolated."
            )
            action = PolicyAction.BLOCK

        elif risk >= self.monitor_threshold:
            # 70.0 <= risk <= 90.0
            decision = "ALERT / APPROVAL"
            rule_id = "RULE_ELEVATED_RISK_ALERT_APPROVAL"
            reason = (
                f"Risk score ({risk:.1f}%) falls within alert/approval threshold band "
                f"({self.monitor_threshold:.1f}%–{self.alert_threshold:.1f}%). "
                f"SOC alert raised; managerial approval required before authorization."
            )
            action = PolicyAction.ALERT_APPROVAL

        elif risk >= self.allow_threshold:
            # 40.0 <= risk < 70.0
            decision = "MONITOR"
            rule_id = "RULE_MODERATE_RISK_MONITOR"
            reason = (
                f"Risk score ({risk:.1f}%) falls within monitoring threshold band "
                f"({self.allow_threshold:.1f}%–{self.monitor_threshold:.1f}%). "
                f"Activity permitted under enhanced telemetry recording and behavioral tracking."
            )
            action = PolicyAction.MONITOR

        else:
            # risk < 40.0
            decision = "ALLOW"
            rule_id = "RULE_LOW_RISK_ALLOW"
            reason = (
                f"Risk score ({risk:.1f}%) is below allow threshold (<{self.allow_threshold:.1f}%). "
                f"Activity permitted under standard organizational policy."
            )
            action = PolicyAction.ALLOW

        return PolicyResult(
            decision=decision,
            reason=reason,
            risk=risk,
            policy_rule_triggered=rule_id,
            sensitivity_level=norm_sensitivity,
            destination_risk=destination_risk,
            context=context,
            action=action
        )

    def _map_to_policy_action(self, decision: str) -> PolicyAction:
        """Helper to map string decisions to PolicyAction enums."""
        d = decision.strip().upper()
        if "BLOCK" in d:
            return PolicyAction.BLOCK
        elif "APPROVAL" in d or "ALERT" in d:
            return PolicyAction.ALERT_APPROVAL
        elif "MONITOR" in d:
            return PolicyAction.MONITOR
        return PolicyAction.ALLOW

    def evaluate_risk(
        self,
        risk_score: float,
        has_secret_content: bool = False,
        is_after_hours_usb: bool = False,
        **kwargs
    ) -> PolicyAction:
        """
        Backward-compatibility facade for existing callers (e.g. test.py, dashboard).
        Returns PolicyAction enum directly.
        """
        # Critical override rules from earlier baseline
        if has_secret_content and risk_score >= 80.0:
            return PolicyAction.ENCRYPT_QUARANTINE

        if is_after_hours_usb and risk_score >= 85.0:
            return PolicyAction.RESTRICT_BLOCK

        res = self.evaluate(
            final_risk=risk_score,
            sensitivity_level="CRITICAL" if has_secret_content else "LOW",
            destination_risk="USB" if is_after_hours_usb else "Internal",
            context={
                "has_secret_content": has_secret_content,
                "is_after_hours_usb": is_after_hours_usb
            }
        )
        return res.action or self._map_to_policy_action(res.decision)

    def save_config(self, filepath: str):
        """Saves current threshold configuration to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        config_data = {
            "thresholds": self.get_thresholds(),
            "enable_contextual_escalation": self.enable_contextual_escalation,
            "disclaimer": self.DISCLAIMER,
            "rules": [
                {
                    "rule_id": "RULE_CRITICAL_EGRESS_BLOCK",
                    "name": "Critical Data Egress Containment",
                    "condition": "risk > 90.0 and sensitivity == 'CRITICAL' and destination is external",
                    "decision": "BLOCK"
                },
                {
                    "rule_id": "RULE_HIGH_RISK_BLOCK",
                    "name": "Critical Risk Boundary Violation",
                    "condition": "risk > 90.0",
                    "decision": "BLOCK"
                },
                {
                    "rule_id": "RULE_ELEVATED_RISK_ALERT_APPROVAL",
                    "name": "Elevated Risk Alert and Approval",
                    "condition": "70.0 <= risk <= 90.0",
                    "decision": "ALERT / APPROVAL"
                },
                {
                    "rule_id": "RULE_MODERATE_RISK_MONITOR",
                    "name": "Moderate Risk Behavioral Monitor",
                    "condition": "40.0 <= risk < 70.0",
                    "decision": "MONITOR"
                },
                {
                    "rule_id": "RULE_LOW_RISK_ALLOW",
                    "name": "Baseline Permitted Activity",
                    "condition": "risk < 40.0",
                    "decision": "ALLOW"
                }
            ]
        }
        with open(filepath, "w") as f:
            json.dump(config_data, f, indent=2)
        logger.info(f"Saved policy configuration to {filepath}")

    def load_config(self, filepath: str):
        """Loads threshold configuration from JSON file."""
        with open(filepath, "r") as f:
            data = json.load(f)
        if "thresholds" in data:
            self.update_thresholds(data["thresholds"])
        if "enable_contextual_escalation" in data:
            self.enable_contextual_escalation = bool(data["enable_contextual_escalation"])
        logger.info(f"Loaded policy configuration from {filepath}")
