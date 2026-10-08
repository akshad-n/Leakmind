"""
Risk Prioritization Engine
Adjusts and ranks security incidents based on asset criticality, blast radius, and actor clearance.
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class PrioritizedIncident:
    incident_id: str
    user: str
    base_risk: float
    priority_score: float
    severity_tier: str       # LOW, MEDIUM, HIGH, CRITICAL
    context_factors: List[str]


class RiskPrioritizer:
    """
    Ranks incidents so Security Operations Center (SOC) analysts
    triage the most dangerous insider events first.
    """

    def prioritize(
        self,
        incident_id: str,
        user: str,
        base_risk: float,
        is_watchlist: bool = False,
        asset_sensitivity: str = "INTERNAL",
        blast_radius_size: int = 1
    ) -> PrioritizedIncident:
        multiplier = 1.0
        factors = []

        if is_watchlist:
            multiplier += 0.25
            factors.append("User is on High-Risk Watchlist (+25%)")

        if asset_sensitivity == "RESTRICTED_SECRET":
            multiplier += 0.40
            factors.append("Crown Jewel Asset Target (+40%)")
        elif asset_sensitivity == "CONFIDENTIAL":
            multiplier += 0.20
            factors.append("Confidential Asset Target (+20%)")

        if blast_radius_size >= 5:
            multiplier += 0.20
            factors.append(f"Broad Lateral Access (Blast radius: {blast_radius_size}) (+20%)")

        final_score = min(100.0, round(base_risk * multiplier, 2))

        if final_score >= 85.0:
            tier = "CRITICAL"
        elif final_score >= 70.0:
            tier = "HIGH"
        elif final_score >= 40.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return PrioritizedIncident(
            incident_id=incident_id,
            user=user,
            base_risk=base_risk,
            priority_score=final_score,
            severity_tier=tier,
            context_factors=factors
        )
