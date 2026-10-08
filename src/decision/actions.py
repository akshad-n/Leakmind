"""
Decision Engine: Action Dispatcher & Protective Enforcement
Executes containment actions: Observe, Alert, Approval, Block, Quarantine/Encrypt.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from ..security.audit import system_audit_logger
from ..security.encryption import FieldEncryptor
from .policy import PolicyAction


@dataclass
class ExecutionResult:
    action_type: PolicyAction
    status: str              # EXECUTED, PENDING_APPROVAL, LOGGED
    details: Dict[str, Any]
    audit_hash: str


class DecisionEngine:
    """
    Executes automated defense, policy enforcement, and containment workflows.
    """

    def __init__(self, encryptor: Optional[FieldEncryptor] = None):
        self.encryptor = encryptor or FieldEncryptor()

    def execute_decision(
        self,
        user: str,
        action: Any,
        resource: str = "ENDPOINT",
        payload_data: str = ""
    ) -> ExecutionResult:
        details = {"target_user": user, "target_resource": resource}
        act_val = getattr(action, "value", str(action))

        if act_val in (PolicyAction.OBSERVE, "OBSERVE"):
            status = "OBSERVED"
            details["action_summary"] = "Telemetry recorded into baseline observation store."

        elif act_val in (PolicyAction.MONITOR, "MONITOR"):
            status = "MONITORED_AND_LOGGED"
            details["action_summary"] = f"Activity monitored and telemetry recorded into baseline observation store for {user}."

        elif act_val in (PolicyAction.ALLOW, "ALLOW"):
            status = "ALLOWED"
            details["action_summary"] = "Action permitted under standard policy."

        elif act_val in (PolicyAction.ALERT, "ALERT"):
            status = "ALERT_DISPATCHED"
            details["action_summary"] = f"SOC Alert raised for user {user} on resource {resource}."

        elif act_val in (PolicyAction.REQUIRE_APPROVAL, PolicyAction.ALERT_APPROVAL, "ALERT / APPROVAL", "REQUIRE_APPROVAL"):
            status = "PENDING_APPROVAL"
            details["action_summary"] = "Transfer halted pending CISO/SecOps authorization."

        elif act_val in (PolicyAction.BLOCK, PolicyAction.RESTRICT_BLOCK, "BLOCK", "RESTRICT_BLOCK"):
            status = "RESTRICTED_BLOCKED"
            details["action_summary"] = f"Blocked access to {resource}. Session locked for {user}."

        elif act_val in (PolicyAction.ENCRYPT_QUARANTINE, "ENCRYPT_QUARANTINE"):
            status = "ENCRYPTED_AND_QUARANTINED"
            enc_token = self.encryptor.encrypt(payload_data) if payload_data else "EMPTY_PAYLOAD"
            details["action_summary"] = f"Payload cryptographically encrypted and isolated. Quarantine Token: {enc_token[:16]}..."
            details["ciphertext_sample"] = enc_token[:32]

        else:
            status = "UNKNOWN"
            details["action_summary"] = f"Action {act_val} logged."

        # Record into cryptographically hash-chained audit log
        audit_rec = system_audit_logger.log(
            actor="LEAKMIND_DECISION_ENGINE",
            action=str(act_val),
            resource=resource,
            details=details
        )

        return ExecutionResult(
            action_type=action,
            status=status,
            details=details,
            audit_hash=audit_rec.current_hash
        )
