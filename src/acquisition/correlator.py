"""
Multi-Source Event Correlation Engine
Correlates events across Windows, USB, Browser, AI Platforms, and Files
into aggregated behavioral session windows and threat signals.
"""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd
from .collectors import SecurityEvent, SourceType


class CorrelatedSession:
    def __init__(self, user: str, window_id: str):
        self.user = user
        self.window_id = window_id
        self.events: List[SecurityEvent] = []
        self.http_count: int = 0
        self.after_hours_activity: int = 0
        self.logon_count: int = 0
        self.logoff_count: int = 0
        self.after_hours_logon: int = 0
        self.pcs: set = set()
        self.device_connect_count: int = 0
        self.device_disconnect_count: int = 0
        self.total_device_events: int = 0
        self.ai_prompts_count: int = 0

    def add_event(self, event: SecurityEvent):
        self.events.append(event)
        self.pcs.add(event.pc)

        # Check hour
        try:
            dt = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            is_after_hours = dt.hour < 7 or dt.hour > 18
        except Exception:
            is_after_hours = False

        if is_after_hours:
            self.after_hours_activity += 1

        # Channel specific counting
        if event.source in (SourceType.BROWSER, SourceType.NETWORK):
            self.http_count += 1
        elif event.source == SourceType.WINDOWS:
            act_lower = event.activity.lower()
            if "logon" in act_lower:
                self.logon_count += 1
                if is_after_hours:
                    self.after_hours_logon += 1
            elif "logoff" in act_lower:
                self.logoff_count += 1
        elif event.source == SourceType.USB:
            self.total_device_events += 1
            act_lower = event.activity.lower()
            if "connect" in act_lower:
                self.device_connect_count += 1
            elif "disconnect" in act_lower:
                self.device_disconnect_count += 1
        elif event.source == SourceType.AI_PLATFORMS:
            self.ai_prompts_count += 1

    def to_feature_vector(self) -> Dict[str, float]:
        """
        Extracts the 9-dimensional supervised feature vector
        matching the exact trained LeakMind models.
        """
        return {
            "http_activity_count": float(self.http_count),
            "after_hours_activity": float(self.after_hours_activity),
            "logon_count": float(self.logon_count),
            "logoff_count": float(self.logoff_count),
            "after_hours_logon": float(self.after_hours_logon),
            "unique_pcs": float(len(self.pcs)),
            "device_connect_count": float(self.device_connect_count),
            "device_disconnect_count": float(self.device_disconnect_count),
            "total_device_events": float(self.total_device_events)
        }


class EventCorrelator:
    """
    Correlates continuous streams of events by User and time window.
    """

    def __init__(self):
        self._user_windows: Dict[str, CorrelatedSession] = {}

    def correlate(self, events: List[SecurityEvent], window_id: str = "current") -> List[CorrelatedSession]:
        sessions: Dict[str, CorrelatedSession] = {}
        for evt in events:
            user = evt.user
            if user not in sessions:
                sessions[user] = CorrelatedSession(user=user, window_id=window_id)
            sessions[user].add_event(evt)
        return list(sessions.values())

    def to_dataframe(self, sessions: List[CorrelatedSession]) -> pd.DataFrame:
        rows = []
        for s in sessions:
            row = s.to_feature_vector()
            row["user"] = s.user
            row["ai_prompts_count"] = s.ai_prompts_count
            rows.append(row)
        return pd.DataFrame(rows)
