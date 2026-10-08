"""
Authentication and Role-Based Access Control (RBAC)
"""

import enum
import hashlib
import time
from typing import Dict, List, Optional


class Role(str, enum.Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"
    READ_ONLY = "READ_ONLY"


ROLE_PERMISSIONS: Dict[Role, List[str]] = {
    Role.ADMIN: [
        "view_dashboard",
        "view_alerts",
        "view_shap",
        "enforce_policy",
        "quarantine_action",
        "manage_users",
        "decrypt_payloads"
    ],
    Role.SECURITY_ANALYST: [
        "view_dashboard",
        "view_alerts",
        "view_shap",
        "enforce_policy",
        "quarantine_action"
    ],
    Role.AUDITOR: [
        "view_dashboard",
        "view_alerts",
        "view_audit_logs",
        "export_reports"
    ],
    Role.READ_ONLY: [
        "view_dashboard",
        "view_alerts"
    ]
}


class SecurityContext:
    def __init__(self, user_id: str, username: str, role: Role, token: str):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.token = token

    def has_permission(self, permission: str) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, [])
        return permission in allowed


# Pre-configured demo users for testing & dashboard
USER_DATABASE = {
    "sec_admin": {"password_hash": hashlib.sha256("Admin@LeakMind2026".encode()).hexdigest(), "role": Role.ADMIN, "name": "Chief Information Security Officer"},
    "analyst_jane": {"password_hash": hashlib.sha256("Analyst@LeakMind".encode()).hexdigest(), "role": Role.SECURITY_ANALYST, "name": "Jane Doe (Lead Threat Analyst)"},
    "auditor_bob": {"password_hash": hashlib.sha256("Audit@LeakMind".encode()).hexdigest(), "role": Role.AUDITOR, "name": "Bob Smith (Compliance Auditor)"},
}


def authenticate_user(username: str, password_plain: str) -> Optional[SecurityContext]:
    """Authenticates credentials and returns a session SecurityContext."""
    user = USER_DATABASE.get(username)
    if not user:
        return None
    entered_hash = hashlib.sha256(password_plain.encode()).hexdigest()
    if entered_hash != user["password_hash"]:
        return None

    token = hashlib.sha256(f"{username}:{time.time()}:leakmind".encode()).hexdigest()
    return SecurityContext(
        user_id=username,
        username=user["name"],
        role=user["role"],
        token=token
    )
