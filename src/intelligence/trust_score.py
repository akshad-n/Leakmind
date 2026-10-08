"""
Multi-Pillar Dynamic Trust Score Calculator
Synthesizes: Threat + Behavior + Content -> Dynamic Trust Score (0-100)
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from .classification import DataSensitivityClassifier, SensitivityLevel, SENSITIVITY_WEIGHTS
from .behavior import BehavioralProfiler
from .threat_intel import ThreatIntelligenceEngine


@dataclass
class TrustAssessment:
    user: str
    trust_score: float         # 0.0 (untrusted) to 100.0 (fully trusted)
    risk_score: float          # 0.0 (safe) to 100.0 (critical leak risk)
    threat_pillar: float       # 0.0 to 100.0
    behavior_pillar: float     # 0.0 to 100.0
    content_pillar: float      # 0.0 to 100.0
    indicators: List[str]


class TrustScoreEngine:
    """
    Computes holistic dynamic Zero Trust score based on the three fundamental AI reasoning pillars.
    """

    def __init__(
        self,
        weight_threat: float = 0.35,
        weight_behavior: float = 0.35,
        weight_content: float = 0.30
    ):
        self.w_threat = weight_threat
        self.w_behavior = weight_behavior
        self.w_content = weight_content

        self.classifier = DataSensitivityClassifier()
        self.profiler = BehavioralProfiler()
        self.threat_intel = ThreatIntelligenceEngine()

    def evaluate(
        self,
        user: str,
        features: Dict[str, float],
        content_samples: Optional[List[str]] = None,
        urls_visited: Optional[List[str]] = None,
        file_actions: Optional[List[str]] = None
    ) -> TrustAssessment:
        content_samples = content_samples or []
        urls_visited = urls_visited or []
        file_actions = file_actions or []

        # 1. Threat Pillar (0 - 100)
        threat_val, indicators = self.threat_intel.evaluate_threat_signals(
            user=user,
            features=features,
            urls_visited=urls_visited,
            file_actions=file_actions
        )

        # 2. Behavior Pillar (0 - 100)
        behavior_anomaly = self.profiler.compute_behavior_anomaly_score(features)
        behavior_val = round(behavior_anomaly * 100.0, 2)
        if behavior_val > 50:
            indicators.append(f"Behavioral Anomaly: Activity deviates by {behavior_val}% from peer baseline")

        # 3. Content Pillar (0 - 100)
        max_content_val = 0.0
        for sample in content_samples:
            sens = self.classifier.classify_text(sample)
            max_content_val = max(max_content_val, SENSITIVITY_WEIGHTS[sens])

        for fname in file_actions:
            sens = self.classifier.classify_filename(fname)
            max_content_val = max(max_content_val, SENSITIVITY_WEIGHTS[sens])

        content_val = max_content_val
        if content_val >= 60:
            indicators.append(f"High Content Sensitivity: Involved data marked as CONFIDENTIAL or RESTRICTED")

        # Composite Risk Calculation
        composite_risk = (
            (self.w_threat * threat_val) +
            (self.w_behavior * behavior_val) +
            (self.w_content * content_val)
        )
        composite_risk = min(100.0, max(0.0, composite_risk))
        trust_score = round(100.0 - composite_risk, 2)
        risk_score = round(composite_risk, 2)

        return TrustAssessment(
            user=user,
            trust_score=trust_score,
            risk_score=risk_score,
            threat_pillar=round(threat_val, 2),
            behavior_pillar=round(behavior_val, 2),
            content_pillar=round(content_val, 2),
            indicators=indicators
        )
