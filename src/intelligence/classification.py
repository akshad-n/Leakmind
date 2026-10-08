"""
IAM Privilege Management & Data Sensitivity Classification
"""

import enum
import re
from typing import Dict, List, Optional


class SensitivityLevel(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_SECRET = "RESTRICTED_SECRET"


SENSITIVITY_WEIGHTS: Dict[SensitivityLevel, float] = {
    SensitivityLevel.PUBLIC: 0.0,
    SensitivityLevel.INTERNAL: 25.0,
    SensitivityLevel.CONFIDENTIAL: 60.0,
    SensitivityLevel.RESTRICTED_SECRET: 100.0,
}


class IAMManager:
    """
    Tracks employee roles, clearance tiers, and high-risk termination/flight-risk flags.
    """

    def __init__(self):
        self.user_roles: Dict[str, dict] = {}
        # Pre-populate some watchlists based on CERT r4.2 threat scenarios
        self.watchlist = {"MYD0978", "RAB0589", "PNL0301", "EGD0132", "FSC0601", "XHW0498"}

    def register_user(self, user_id: str, department: str = "Engineering", clearance: str = "Standard", on_watchlist: bool = False):
        self.user_roles[user_id] = {
            "department": department,
            "clearance": clearance,
            "on_watchlist": on_watchlist or (user_id in self.watchlist)
        }

    def get_user_risk_multiplier(self, user_id: str) -> float:
        info = self.user_roles.get(user_id, {})
        if info.get("on_watchlist", False) or user_id in self.watchlist:
            return 1.35  # 35% higher risk weighting
        if info.get("clearance") == "Executive":
            return 1.2
        return 1.0


class DataSensitivityClassifier:
    """
    Classifies file names, database assets, and AI prompt strings into sensitivity categories.
    """

    SECRET_PATTERNS = [
        re.compile(r"(?i)(api[\s_-]?key|secret[\s_-]?(key|token)|bearer\s+[a-zA-Z0-9_\-\.]+)", re.IGNORECASE),
        re.compile(r"(?i)(password|private[\s_-]?key|BEGIN RSA PRIVATE KEY)", re.IGNORECASE),
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),  # Credit Card
        re.compile(r"(?i)(confidential|proprietary|nda|restricted|patent|salary|layoff)"),
    ]

    def classify_text(self, text: str) -> SensitivityLevel:
        if not text:
            return SensitivityLevel.INTERNAL

        text_lower = text.lower()
        if any(p.search(text) for p in self.SECRET_PATTERNS[:2]):
            return SensitivityLevel.RESTRICTED_SECRET

        if any(p.search(text) for p in self.SECRET_PATTERNS[2:]):
            return SensitivityLevel.CONFIDENTIAL

        if any(kw in text_lower for kw in ["internal", "roadmap", "spec", "draft"]):
            return SensitivityLevel.INTERNAL

        return SensitivityLevel.INTERNAL

    def classify_filename(self, filename: str) -> SensitivityLevel:
        fn = filename.lower()
        if any(ext in fn for ext in [".key", ".pem", ".pfx", "secret", "credentials"]):
            return SensitivityLevel.RESTRICTED_SECRET
        if any(kw in fn for kw in ["financial", "q4_results", "merger", "patent", "salary"]):
            return SensitivityLevel.CONFIDENTIAL
        if any(ext in fn for ext in [".pdf", ".docx", ".xlsx", ".csv", ".py"]):
            return SensitivityLevel.INTERNAL
        return SensitivityLevel.PUBLIC
