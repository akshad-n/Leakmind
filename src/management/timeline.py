"""
Incident Forensic Chronological Timeline Reconstruction
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from ..acquisition.collectors import SecurityEvent


@dataclass
class TimelineEvent:
    timestamp: str
    channel: str
    activity: str
    risk_level: str
    description: str
    details: Dict[str, Any]


class IncidentTimelineGenerator:
    """
    Reconstructs the chronological kill-chain / exfiltration timeline for an incident.
    """

    def build_timeline(
        self,
        user: str,
        events: List[SecurityEvent],
        risk_score: float = 50.0
    ) -> List[TimelineEvent]:
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        timeline = []
        for e in sorted_events:
            # Determine step risk
            act_lower = e.activity.lower()
            if "usb" in str(e.source).lower() or "connect" in act_lower or "cloud" in act_lower:
                step_risk = "HIGH" if risk_score > 60 else "MEDIUM"
            elif "after_hours" in act_lower or "confidential" in str(e.details):
                step_risk = "CRITICAL" if risk_score > 80 else "HIGH"
            else:
                step_risk = "LOW"

            desc = f"User performed {e.activity} via {e.source.value} on {e.pc}"
            if e.details:
                desc += f" (Details: {e.details})"

            timeline.append(TimelineEvent(
                timestamp=e.timestamp,
                channel=e.source.value,
                activity=e.activity,
                risk_level=step_risk,
                description=desc,
                details=e.details
            ))

        return timeline
