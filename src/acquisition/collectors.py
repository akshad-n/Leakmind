"""
Local Agent Event Collectors for All 8 Architecture Sources
Sources: AI Platforms, Applications, USB, Files, Network, Cloud, Browser, Windows
"""

import enum
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional
import pandas as pd


class SourceType(str, enum.Enum):
    AI_PLATFORMS = "AI_PLATFORMS"
    APPLICATIONS = "APPLICATIONS"
    USB = "USB"
    FILES = "FILES"
    NETWORK = "NETWORK"
    CLOUD = "CLOUD"
    BROWSER = "BROWSER"
    WINDOWS = "WINDOWS"


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    user: str
    source: SourceType
    activity: str
    pc: str = "PC-UNKNOWN"
    details: Dict[str, Any] = field(default_factory=dict)
    raw_payload: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "user": self.user,
            "source": self.source.value,
            "activity": self.activity,
            "pc": self.pc,
            "details": self.details,
            "raw_payload": self.raw_payload
        }


class LocalAgentCollector:
    """
    Simulates and ingests telemetry directly from endpoints across the 8 architecture channels.
    """

    def __init__(self, agent_id: str = "AGENT-LEAKMIND-01"):
        self.agent_id = agent_id

    def capture_ai_prompt(self, user: str, platform: str, prompt_text: str, pc: str = "PC-001") -> SecurityEvent:
        """Monitors interactions with ChatGPT, Claude, Copilot, etc."""
        return SecurityEvent(
            event_id=f"EVT-AI-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            user=user,
            source=SourceType.AI_PLATFORMS,
            activity=f"PROMPT_SUBMISSION_{platform.upper()}",
            pc=pc,
            details={"platform": platform, "char_count": len(prompt_text)},
            raw_payload=prompt_text
        )

    def capture_usb_event(self, user: str, activity: str, device_id: str, pc: str = "PC-001") -> SecurityEvent:
        """Monitors USB connect, disconnect, and mass storage mounting."""
        return SecurityEvent(
            event_id=f"EVT-USB-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            user=user,
            source=SourceType.USB,
            activity=activity,
            pc=pc,
            details={"device_id": device_id}
        )

    def capture_file_event(self, user: str, filepath: str, action: str, file_size: int = 1024, pc: str = "PC-001") -> SecurityEvent:
        """Monitors read, write, copy, and deletion of local sensitive documents."""
        return SecurityEvent(
            event_id=f"EVT-FILE-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            user=user,
            source=SourceType.FILES,
            activity=action,
            pc=pc,
            details={"filepath": filepath, "file_size": file_size}
        )

    def capture_browser_event(self, user: str, url: str, action: str = "NAVIGATE", pc: str = "PC-001") -> SecurityEvent:
        """Monitors web visits, uploads to cloud storage, and file downloads."""
        return SecurityEvent(
            event_id=f"EVT-WEB-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            user=user,
            source=SourceType.BROWSER,
            activity=action,
            pc=pc,
            details={"url": url}
        )

    def capture_windows_logon(self, user: str, logon_type: str = "Logon", pc: str = "PC-001") -> SecurityEvent:
        """Monitors Windows Event ID 4624 (Logon) and 4634 (Logoff)."""
        return SecurityEvent(
            event_id=f"EVT-WIN-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            user=user,
            source=SourceType.WINDOWS,
            activity=logon_type,
            pc=pc,
            details={"logon_type": logon_type}
        )


def load_cert_events_as_stream(csv_path: str = "data/processed/r42_all_parsed_events.csv", limit: int = 100) -> List[SecurityEvent]:
    """
    Loads parsed CERT insider threat events and converts them into normalized SecurityEvent objects.
    """
    if not os.path.exists(csv_path):
        return []

    df = pd.read_csv(csv_path)
    if limit:
        df = df.head(limit)

    events: List[SecurityEvent] = []
    source_map = {
        "logon": SourceType.WINDOWS,
        "device": SourceType.USB,
        "http": SourceType.BROWSER,
        "file": SourceType.FILES
    }

    for _, row in df.iterrows():
        raw_evt = str(row.get("event_type", "windows")).lower()
        src = source_map.get(raw_evt, SourceType.WINDOWS)
        evt = SecurityEvent(
            event_id=str(row.get("event_id", f"CERT-{uuid.uuid4().hex[:6]}")),
            timestamp=str(row.get("timestamp", datetime.utcnow().isoformat())),
            user=str(row.get("user", "UNKNOWN")),
            source=src,
            activity=str(row.get("activity", "activity")),
            pc=str(row.get("pc", "PC-001")),
            details={
                "scenario": str(row.get("scenario", "UNKNOWN")),
                "details": str(row.get("details", ""))
            }
        )
        events.append(evt)

    return events
