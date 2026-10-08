"""
Cryptographically Hash-Chained Tamper-Evident Audit Logger
"""

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import List, Optional


@dataclass
class AuditRecord:
    index: int
    timestamp: float
    actor: str
    action: str
    resource: str
    details: dict
    prev_hash: str
    current_hash: str = ""

    def calculate_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "details": self.details,
            "prev_hash": self.prev_hash
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw_bytes).hexdigest()


class AuditLogger:
    """
    Maintains a hash-chained sequence of audit events.
    Any tampering with previous records invalidates the chain.
    """

    def __init__(self):
        self._chain: List[AuditRecord] = []
        self._genesis()

    def _genesis(self):
        gen = AuditRecord(
            index=0,
            timestamp=time.time(),
            actor="SYSTEM_INIT",
            action="GENESIS",
            resource="LEAKMIND_CORE",
            details={"status": "initialized"},
            prev_hash="0" * 64,
        )
        gen.current_hash = gen.calculate_hash()
        self._chain.append(gen)

    def log(self, actor: str, action: str, resource: str, details: Optional[dict] = None) -> AuditRecord:
        prev = self._chain[-1]
        record = AuditRecord(
            index=len(self._chain),
            timestamp=time.time(),
            actor=actor,
            action=action,
            resource=resource,
            details=details or {},
            prev_hash=prev.current_hash,
        )
        record.current_hash = record.calculate_hash()
        self._chain.append(record)
        return record

    def verify_integrity(self) -> bool:
        """Verifies that no record has been modified or excised."""
        for i in range(1, len(self._chain)):
            curr = self._chain[i]
            prev = self._chain[i - 1]
            if curr.prev_hash != prev.current_hash:
                return False
            if curr.calculate_hash() != curr.current_hash:
                return False
        return True

    def get_records(self) -> List[dict]:
        return [asdict(r) for r in self._chain]


# Global audit logger instance
system_audit_logger = AuditLogger()
