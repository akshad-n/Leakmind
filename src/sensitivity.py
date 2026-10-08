"""
LeakMind Phase 5: Sensitive Data & PII Detection Module
Modular, independent detection engine for sensitive enterprise content:
- PII (SSN, Passport, Driver License, Full Name)
- Email addresses
- Phone numbers (domestic & international)
- Financial information (Credit Card, Salary, Tax ID)
- Bank information (IBAN, Routing number, Account number, SWIFT)
- Credentials (Passwords, API keys, JWT bearer tokens, Private RSA/SSH keys)
- Confidential information (Mergers, Trade secrets, NDAs, Layoff rosters, Patents)

Provides:
- Rule-based / regex deterministic detection
- Lightweight TF-IDF + Classifier semantic detection
- sensitivity_score (0.0 to 100.0)
- sensitivity_level (LOW, MEDIUM, HIGH, CRITICAL)

Operates strictly independent from CERT.
"""

import json
import os
import re
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.interfaces.sensitivity_interface import BaseSensitivityDetector, SensitivityLevel
from src.utils.logger import get_logger

logger = get_logger("leakmind.sensitivity")


def luhn_checksum_is_valid(card_number_str: str) -> bool:
    """Validates credit card checksum using the Luhn (mod 10) algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class SensitiveRuleEngine:
    """
    High-precision regex and heuristic rule detector for structured sensitive markers.
    """

    PATTERNS = {
        # Credentials & Keys (Weight: 95 - 100 -> CRITICAL)
        "private_key": (re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", re.IGNORECASE), 100.0, "CRITICAL"),
        "aws_access_key": (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 95.0, "CRITICAL"),
        "stripe_key": (re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,34}\b"), 95.0, "CRITICAL"),
        "github_token": (re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{36}\b"), 95.0, "CRITICAL"),
        "jwt_bearer": (re.compile(r"\bBearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b"), 90.0, "CRITICAL"),
        "api_key_generic": (re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,64})['\"]?\b"), 90.0, "CRITICAL"),
        "password_in_uri": (re.compile(r"(?i)(?:postgres|mysql|mongodb|redis|amqp)://[a-zA-Z0-9_\-]+:([^\s@:]+)@[a-zA-Z0-9_\-\.]+"), 95.0, "CRITICAL"),
        "plaintext_password": (re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,32})['\"]?\b"), 85.0, "CRITICAL"),

        # Financial Information (Weight: 80 - 95 -> HIGH / CRITICAL)
        "credit_card": (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b"), 95.0, "CRITICAL"),
        "salary_compensation": (re.compile(r"(?i)\b(?:salary|compensation|payroll|bonus)\s*[:=]?\s*\$?\d{2,3}(?:,\d{3})*(?:\.\d{2})?\b"), 70.0, "HIGH"),
        "tax_id_ein": (re.compile(r"\b\d{2}-\d{7}\b"), 75.0, "HIGH"),

        # Bank Information (Weight: 85 - 95 -> CRITICAL)
        "iban": (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"), 95.0, "CRITICAL"),
        "routing_number": (re.compile(r"(?i)\b(?:routing(?:\s+number)?|aba)\s*[:=]?\s*(\d{9})\b"), 90.0, "CRITICAL"),
        "bank_account": (re.compile(r"(?i)\b(?:account\s+number|acct\s*#?)\s*[:=]?\s*(\d{6,17})\b"), 85.0, "CRITICAL"),
        "swift_bic": (re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"), 65.0, "HIGH"),

        # PII (Weight: 75 - 95 -> HIGH / CRITICAL)
        "ssn": (re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 95.0, "CRITICAL"),
        "passport": (re.compile(r"(?i)\bpassport(?:\s+number)?\s*[:=]?\s*([A-Z0-9]{8,10})\b"), 80.0, "HIGH"),
        "driver_license": (re.compile(r"(?i)\b(?:driver['’]?s?\s*license|dl)\s*[:=]?\s*([A-Z0-9\-]{7,14})\b"), 75.0, "HIGH"),

        # Confidential & Trade Secrets (Weight: 65 - 85 -> HIGH / CRITICAL)
        "confidential_marking": (re.compile(r"(?i)\b(?:strictly\s+confidential|proprietary|trade\s+secret|nda\s+bound|attorney-client\s+privileged|patent\s+pending)\b"), 80.0, "HIGH"),
        "corporate_secret": (re.compile(r"(?i)\b(?:merger\s+terms|acquisition\s+target|workforce\s+reduction|layoff\s+roster|unreleased\s+source\s+code|vulnerability\s+exploit)\b"), 75.0, "HIGH"),

        # Email & Phone (Weight: 35 - 50 -> MEDIUM)
        "email_address": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), 45.0, "MEDIUM"),
        "phone_number": (re.compile(r"(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b|\+\d{1,3}\s?\d{2,4}\s?\d{3,4}\s?\d{3,4}\b"), 40.0, "MEDIUM"),
    }

    def evaluate_text(self, text: str) -> Dict[str, Any]:
        """
        Executes rule matching on text input.
        Returns:
            detected_entities: List of matched pattern descriptions
            max_rule_score: Maximum single pattern severity score
            aggregate_rule_score: Combined severity score bounded to [0.0, 100.0]
            matched_categories: Categorical breakdown
        """
        if not text or not isinstance(text, str):
            return {
                "detected_entities": [],
                "max_rule_score": 0.0,
                "aggregate_rule_score": 0.0,
                "categories": {}
            }

        detected = []
        scores = []
        categories = {}

        for rule_name, (regex, score, level) in self.PATTERNS.items():
            matches = regex.findall(text)
            if matches:
                # If credit card, run Luhn check to prevent false positives
                if rule_name == "credit_card":
                    valid_cards = [m for m in matches if luhn_checksum_is_valid(m if isinstance(m, str) else m[0])]
                    if not valid_cards:
                        continue
                    matches = valid_cards

                entity_desc = f"{rule_name} (Matches: {len(matches)}, Severity: {level})"
                detected.append(entity_desc)
                scores.append(score)
                categories[rule_name] = len(matches)

        if not scores:
            return {
                "detected_entities": [],
                "max_rule_score": 0.0,
                "aggregate_rule_score": 0.0,
                "categories": {}
            }

        max_score = max(scores)
        # Aggregate formula: base max score + small accumulation for multiple violations
        extra = min(15.0, (len(scores) - 1) * 5.0)
        agg_score = round(min(100.0, max_score + extra), 2)

        return {
            "detected_entities": detected,
            "max_rule_score": round(max_score, 2),
            "aggregate_rule_score": agg_score,
            "categories": categories
        }


class DataSensitivityClassifier(BaseSensitivityDetector):
    """
    Hybrid Sensitive-Data Detection Engine.
    Combines deterministic regex rule evaluation with a lightweight TF-IDF n-gram classifier.
    Operates independently from CERT.
    """

    def __init__(self, model_dir: str = "saved_models/sensitivity"):
        self.model_dir = Path(model_dir)
        self.rule_engine = SensitiveRuleEngine()
        self.vectorizer = None
        self.classifier = None
        self.classes_ = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.is_trained = False

        # Attempt loading if available
        self._load_if_exists()

    def is_available(self) -> bool:
        """Module is active and ready."""
        return True

    def load_model(self, model_dir: Optional[Union[str, Path]] = None):
        """Loads trained sensitivity models from directory."""
        if model_dir:
            self.model_dir = Path(model_dir)
        self._load_if_exists()

    def _load_if_exists(self):
        v_path = self.model_dir / "tfidf_vectorizer.joblib"
        c_path = self.model_dir / "sensitivity_classifier.joblib"
        if v_path.exists() and c_path.exists():
            try:
                self.vectorizer = joblib.load(v_path)
                self.classifier = joblib.load(c_path)
                self.is_trained = True
                logger.info(f"Loaded lightweight sensitivity classifier from {self.model_dir}")
            except Exception as e:
                logger.warning(f"Could not load pre-trained sensitivity classifier: {e}")

    def train(self, texts: List[str], labels: List[str]):
        """
        Trains the lightweight TF-IDF n-gram classifier on sensitive corpus.
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        logger.info(f"Training lightweight sensitivity classifier on {len(texts)} samples...")
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=1200,
            sublinear_tf=True
        )
        X_vec = self.vectorizer.fit_transform(texts)

        self.classifier = LogisticRegression(
            C=1.5,
            max_iter=300,
            random_state=42
        )
        self.classifier.fit(X_vec, labels)
        self.classes_ = list(self.classifier.classes_)
        self.is_trained = True
        logger.info(f"Sensitivity classifier trained across classes: {self.classes_}")

    def save_model(self, model_dir: Optional[str] = None) -> Dict[str, str]:
        """Saves model and preprocessor artifacts to disk."""
        path = Path(model_dir) if model_dir else self.model_dir
        path.mkdir(parents=True, exist_ok=True)

        saved = {}
        if self.vectorizer is not None:
            v_file = path / "tfidf_vectorizer.joblib"
            joblib.dump(self.vectorizer, v_file)
            saved["vectorizer"] = str(v_file)

        if self.classifier is not None:
            c_file = path / "sensitivity_classifier.joblib"
            joblib.dump(self.classifier, c_file)
            saved["classifier"] = str(c_file)

        # Save rule engine configuration
        conf_file = path / "rule_config.json"
        rule_meta = {
            "patterns_count": len(self.rule_engine.PATTERNS),
            "pattern_names": list(self.rule_engine.PATTERNS.keys()),
            "classes": self.classes_,
            "thresholds": {
                "CRITICAL": 85.0,
                "HIGH": 60.0,
                "MEDIUM": 30.0,
                "LOW": 0.0
            }
        }
        with open(conf_file, "w", encoding="utf-8") as f:
            json.dump(rule_meta, f, indent=2)
        saved["config"] = str(conf_file)

        # Full pipeline object
        pipe_file = path / "sensitivity_pipeline.joblib"
        joblib.dump(self, pipe_file)
        saved["pipeline"] = str(pipe_file)

        logger.info(f"Saved complete sensitivity bundle to {path}")
        return saved

    def analyze_content(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, SensitivityLevel, List[str]]:
        """
        Analyzes payload or document content.
        Combines deterministic rule matching with lightweight ML classifier inference.
        Returns:
            sensitivity_score: float 0.0 to 100.0
            sensitivity_level: SensitivityLevel Enum (LOW, MEDIUM, HIGH, CRITICAL)
            detected_entities: List of matched PII, financial, or credential patterns
        """
        if not text or not isinstance(text, str):
            return 0.0, SensitivityLevel.LOW, []

        # 1. Deterministic Rule Matching
        rule_res = self.rule_engine.evaluate_text(text)
        rule_score = rule_res["aggregate_rule_score"]
        detected_entities = rule_res["detected_entities"]

        # 2. Lightweight Classifier Inference
        ml_pred = None
        ml_probs = {}
        if self.is_trained and self.vectorizer is not None and self.classifier is not None:
            try:
                vec = self.vectorizer.transform([text])
                ml_pred = str(self.classifier.predict(vec)[0])
                probs = self.classifier.predict_proba(vec)[0]
                ml_probs = {str(c): float(p) for c, p in zip(self.classifier.classes_, probs)}
            except Exception:
                ml_pred = None

        # 3. Calibrated Hybrid Score Fusion
        if rule_score >= 85.0:
            final_score = rule_score
        elif rule_score >= 40.0:
            final_score = max(rule_score, 70.0 if ml_pred in ["HIGH", "CRITICAL"] else rule_score)
        else:
            # When no strong regex triggered, evaluate ML semantic context
            if ml_pred == "LOW":
                final_score = round(15.0 * (1.0 - ml_probs.get("LOW", 0.5)), 2)
            elif ml_pred == "MEDIUM":
                final_score = round(35.0 + 15.0 * ml_probs.get("MEDIUM", 0.5), 2)
            elif ml_pred == "HIGH":
                final_score = round(65.0 + 15.0 * ml_probs.get("HIGH", 0.5), 2)
            elif ml_pred == "CRITICAL":
                final_score = round(85.0 + 10.0 * ml_probs.get("CRITICAL", 0.5), 2)
            else:
                final_score = rule_score

        final_score = round(float(np.clip(final_score, 0.0, 100.0)), 2)

        # 4. Map to Sensitivity Level Enum
        if final_score >= 85.0:
            final_level = SensitivityLevel.CRITICAL
        elif final_score >= 60.0:
            final_level = SensitivityLevel.HIGH
        elif final_score >= 30.0:
            final_level = SensitivityLevel.MEDIUM
        else:
            final_level = SensitivityLevel.LOW

        return final_score, final_level, detected_entities

    def evaluate_dataframe(self, df: pd.DataFrame, text_col: str = "text") -> pd.DataFrame:
        """Evaluates batch DataFrame of text entries."""
        scores = []
        levels = []
        entities = []

        for val in df[text_col]:
            s, l, e = self.analyze_content(str(val))
            scores.append(s)
            levels.append(l.value)
            entities.append("; ".join(e) if e else "None")

        res_df = df.copy()
        res_df["sensitivity_score"] = scores
        res_df["sensitivity_level"] = levels
        res_df["detected_entities"] = entities
        return res_df

    def detect(self, text: str) -> Any:
        """Convenience method returning structured DetectionResult."""
        score, level, entities = self.analyze_content(text)
        class DetectionResult:
            def __init__(self, s, l, e):
                self.sensitivity_score = float(s)
                self.sensitivity_level = l.value if hasattr(l, "value") else str(l)
                self.findings = list(e)
        return DetectionResult(score, level, entities)


# Facade aliases for backwards compatibility
DataSensitivityEngine = DataSensitivityClassifier
SensitiveDataDetector = DataSensitivityClassifier
SENSITIVITY_WEIGHTS = {
    SensitivityLevel.LOW: 5.0,
    SensitivityLevel.MEDIUM: 45.0,
    SensitivityLevel.HIGH: 75.0,
    SensitivityLevel.CRITICAL: 95.0
}

__all__ = [
    "DataSensitivityClassifier",
    "DataSensitivityEngine",
    "SensitiveDataDetector",
    "SensitiveRuleEngine",
    "SensitivityLevel",
    "SENSITIVITY_WEIGHTS",
    "luhn_checksum_is_valid"
]
