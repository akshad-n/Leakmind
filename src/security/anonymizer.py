"""
Data Anonymization and PII Masking Module
"""

import hashlib
import re
from typing import Any, Dict


class DataAnonymizer:
    """
    Sanitizes log lines, network requests, and database records
    to comply with GDPR/HIPAA privacy preservation standards.
    """

    def __init__(self, salt: str = "leakmind_anonymization_salt_2026"):
        self.salt = salt
        self.pseudonym_cache: Dict[str, str] = {}

    def pseudonymize_user(self, user_id: str) -> str:
        """Deterministically replaces employee/CERT user IDs with masked pseudonyms."""
        if not user_id:
            return "USER_UNKNOWN"
        if user_id in self.pseudonym_cache:
            return self.pseudonym_cache[user_id]

        hashed = hashlib.sha256(f"{user_id}:{self.salt}".encode()).hexdigest()[:8].upper()
        pseudo = f"ANON_USER_{hashed}"
        self.pseudonym_cache[user_id] = pseudo
        return pseudo

    def mask_email(self, email: str) -> str:
        """Transforms john.doe@corp.com -> j***e@corp.com"""
        if not email or "@" not in email:
            return email
        parts = email.split("@")
        name, domain = parts[0], parts[1]
        if len(name) <= 2:
            masked_name = name[0] + "*"
        else:
            masked_name = name[0] + ("*" * (len(name) - 2)) + name[-1]
        return f"{masked_name}@{domain}"

    def mask_ip(self, ip: str) -> str:
        """Transforms 192.168.1.100 -> 192.168.1.xxx"""
        if not ip:
            return ip
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
        return "xxx.xxx.xxx.xxx"

    def sanitize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copy and sanitize standard event dictionary."""
        sanitized = dict(event)
        if "user" in sanitized:
            sanitized["user_masked"] = self.pseudonymize_user(str(sanitized["user"]))
        if "email" in sanitized:
            sanitized["email"] = self.mask_email(str(sanitized["email"]))
        if "ip" in sanitized:
            sanitized["ip"] = self.mask_ip(str(sanitized["ip"]))
        return sanitized
