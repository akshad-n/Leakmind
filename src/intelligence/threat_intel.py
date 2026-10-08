"""
Threat Intelligence & Heuristic Scenario Matcher
Matches CERT r4.2 attack patterns (r4.2-1, r4.2-2, r4.2-3) and real-world IoCs.
"""

from typing import Dict, List, Optional, Tuple


class ThreatIntelligenceEngine:
    """
    Threat Intelligence rules and signatures modeled after insider threat archetypes.
    """

    SUSPICIOUS_DOMAINS = {
        "dropbox.com", "mega.nz", "wetransfer.com", "anonfiles.com",
        "pastebin.com", "sendspace.com", "mediafire.com", "rapidgator.net"
    }

    AI_SERVICES = {
        "chatgpt.com", "openai.com", "claude.ai", "anthropic.com", "gemini.google.com"
    }

    def evaluate_threat_signals(
        self,
        user: str,
        features: Dict[str, float],
        urls_visited: Optional[List[str]] = None,
        file_actions: Optional[List[str]] = None
    ) -> Tuple[float, List[str]]:
        """
        Evaluates threat intelligence rules.
        Returns: (threat_score: float 0.0-100.0, detected_indicators: List[str])
        """
        score = 0.0
        indicators: List[str] = []
        urls_visited = urls_visited or []
        file_actions = file_actions or []

        # Scenario 1 Archetype: After-hours USB removable device exfiltration
        if features.get("device_connect_count", 0) > 0 and features.get("after_hours_activity", 0) > 0:
            score += 45.0
            indicators.append("IoC-SCENARIO-1: After-hours USB mass storage connection detected")

        # Scenario 2 Archetype: Massive HTTP activity + cloud storage upload
        has_suspicious_url = any(
            any(dom in url.lower() for dom in self.SUSPICIOUS_DOMAINS)
            for url in urls_visited
        )
        if has_suspicious_url:
            score += 40.0
            indicators.append("IoC-SCENARIO-2: High-risk cloud storage or file-sharing domain contacted")

        # Scenario 3 Archetype: Elevated PC hopping (lateral movement indicator)
        if features.get("unique_pcs", 1) > 2:
            score += 35.0
            indicators.append("IoC-SCENARIO-3: Anomalous multi-workstation logon hopping detected")

        # Public AI Data Leakage heuristic
        has_ai_access = any(
            any(ai_dom in url.lower() for ai_dom in self.AI_SERVICES)
            for url in urls_visited
        )
        if has_ai_access and any("confidential" in f.lower() for f in file_actions):
            score += 50.0
            indicators.append("IoC-AI-LEAK: Potential confidential asset leakage via public AI service")

        return min(100.0, score), indicators
