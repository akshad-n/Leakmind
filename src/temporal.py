"""
LeakMind Phase 7: Temporal and Graph-Based Leakage-Event Correlation
Combines fragmented security events into consolidated leakage incidents using explainable rules.

Key Capabilities:
1. Explainable Rule-Based Correlation Engine (strictly NO GNN).
2. Multi-Stage Kill-Chain sequence matching:
   - Sensitive File Access
   - Removable Channel (USB) Connect within 10 minutes
   - Copy / Staging Activity
   - External Upload / Cloud Egress within 30 minutes
3. Graph-Derived Causal Entity Paths:
   - User -> Host -> Process -> Resource/File -> Egress Target
4. Incident Consolidation & Attribution:
   - incident_id
   - leakage_chain_score (calibrated 0.0 to 100.0)
   - incident_start
   - incident_end
   - incident_events
   - leakage_path

Strictly conforms to BaseTemporalCorrelator.
"""

import json
import os
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pandas as pd

from src.interfaces.temporal_interface import BaseTemporalCorrelator
from src.utils.logger import get_logger

logger = get_logger("leakmind.temporal")


class TemporalLeakageCorrelator(BaseTemporalCorrelator):
    """
    Explainable Temporal and Graph-based Incident Correlation Engine.
    Consolidates fragmented events into structured leakage incidents.
    """

    # Default correlation time window thresholds
    DEFAULT_USB_WINDOW_MINUTES = 10.0
    DEFAULT_COPY_WINDOW_MINUTES = 15.0
    DEFAULT_EGRESS_WINDOW_MINUTES = 30.0
    DEFAULT_SESSION_WINDOW_MINUTES = 60.0
    DEFAULT_ALERT_SCORE_THRESHOLD = 60.0

    # Sensitive asset keywords
    SENSITIVE_KEYWORDS = {
        "salary", "salaries", "crown_jewel", "key", "secret", "confidential",
        "restricted", "layoff", "layoffs", "payroll", "pii", "credential",
        "password", "classified", "financial", "dtaa", "tax", "keys.pem",
        "leak", "private", "confidential_layoffs"
    }

    # External cloud / leak site domains
    UNTRUSTED_EGRESS_DOMAINS = {
        "mega.nz", "dropbox.com", "wikileaks.org", "drive.google.com",
        "onedrive.live.com", "pastebin.com", "anonfiles.com", "wetransfer.com"
    }

    def __init__(
        self,
        usb_window_minutes: float = DEFAULT_USB_WINDOW_MINUTES,
        copy_window_minutes: float = DEFAULT_COPY_WINDOW_MINUTES,
        egress_window_minutes: float = DEFAULT_EGRESS_WINDOW_MINUTES,
        session_window_minutes: float = DEFAULT_SESSION_WINDOW_MINUTES,
        alert_score_threshold: float = DEFAULT_ALERT_SCORE_THRESHOLD,
        custom_rules: Optional[List[Dict[str, Any]]] = None
    ):
        """
        Initializes the correlator with temporal window constraints and explainable rules.
        """
        self.usb_window_minutes = usb_window_minutes
        self.copy_window_minutes = copy_window_minutes
        self.egress_window_minutes = egress_window_minutes
        self.session_window_minutes = session_window_minutes
        self.alert_score_threshold = alert_score_threshold
        self.custom_rules = custom_rules or self._get_default_rules()

    def _get_default_rules(self) -> List[Dict[str, Any]]:
        """Returns default explainable correlation rules."""
        return [
            {
                "rule_id": "RULE-FULL-4STAGE-EXFIL",
                "name": "Full 4-Stage Exfiltration Chain",
                "description": (
                    "Sensitive File Access -> USB Connect (<=10m) -> "
                    "Copy Activity (<=15m) -> External Upload (<=30m)"
                ),
                "base_score": 95.0,
                "severity": "CRITICAL",
                "stages_required": ["ACCESS", "USB_CONNECT", "COPY", "EGRESS"],
            },
            {
                "rule_id": "RULE-USB-REMOVABLE-EXFIL",
                "name": "Removable Media Exfiltration Chain",
                "description": (
                    "Sensitive File Access correlated with USB Connect (<=10m) "
                    "and Direct Transfer/Copy to Removable Device"
                ),
                "base_score": 85.0,
                "severity": "CRITICAL",
                "stages_required": ["ACCESS", "USB_CONNECT", "COPY"],
            },
            {
                "rule_id": "RULE-CLOUD-WEB-EXFIL",
                "name": "Cloud / Web Exfiltration Chain",
                "description": (
                    "Sensitive File Access followed by Browser/Network Preparation (<=10m) "
                    "and External Cloud/Web Upload (<=30m)"
                ),
                "base_score": 85.0,
                "severity": "CRITICAL",
                "stages_required": ["ACCESS", "CHANNEL_PREP", "EGRESS"],
            },
            {
                "rule_id": "RULE-CERT-AFTERHOURS-REMOVABLE-WEB",
                "name": "CERT Insider Exfiltration Pattern (Scenario 1)",
                "description": (
                    "Session Logon (After-Hours) -> Removable Drive Connect -> "
                    "External Leak Site / HTTP Upload (<=30m)"
                ),
                "base_score": 80.0,
                "severity": "HIGH",
                "stages_required": ["AUTH", "USB_CONNECT", "EGRESS"],
            },
            {
                "rule_id": "RULE-STAGING-RAPID-EGRESS",
                "name": "Rapid Data Staging and Direct Egress",
                "description": (
                    "Data Staging / Copy Activity followed directly by External Upload (<=30m)"
                ),
                "base_score": 70.0,
                "severity": "HIGH",
                "stages_required": ["COPY", "EGRESS"],
            }
        ]

    @staticmethod
    def _parse_timestamp(ts: Any) -> Optional[datetime]:
        """Safely parses timestamp strings or objects into Python datetime."""
        if ts is None or (isinstance(ts, float) and pd.isna(ts)):
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, pd.Timestamp):
            return ts.to_pydatetime()
        
        ts_str = str(ts).strip()
        # Common formats in cybersecurity datasets
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        try:
            return pd.to_datetime(ts_str).to_pydatetime()
        except Exception:
            return None

    @staticmethod
    def _is_valid_value(val: Any) -> bool:
        """Returns True if val is a non-empty, non-NaN string or object."""
        if val is None:
            return False
        if isinstance(val, float) and pd.isna(val):
            return False
        s = str(val).strip()
        return bool(s) and s.lower() != "nan" and s.lower() != "none"

    def _is_sensitive_asset(self, event: Dict[str, Any]) -> bool:
        """Determines if the event involves a sensitive file or content."""
        file_path = str(event.get("file_path", "")).lower()
        dst_entity = str(event.get("dst_entity_id", "")).lower()
        src_entity = str(event.get("src_entity_id", "")).lower()
        url = str(event.get("url", "")).lower()
        keywords = str(event.get("keywords", "")).lower()

        # Check explicit flags
        if event.get("is_sensitive", False) or event.get("sensitivity_level") in ["HIGH", "CRITICAL"]:
            return True

        text_to_check = f"{file_path} {dst_entity} {src_entity} {url} {keywords}"
        for kw in self.SENSITIVE_KEYWORDS:
            if kw in text_to_check:
                return True
        return False

    def _classify_event_stage(self, event: Dict[str, Any]) -> str:
        """
        Classifies an event into one of the canonical kill-chain stages:
        - ACCESS: Sensitive file read / access
        - USB_CONNECT: USB or removable drive mount / connection
        - CHANNEL_PREP: Process spawn / browser launch
        - COPY: File write, transfer to USB, staging
        - EGRESS: External cloud upload, HTTP post to leak site, untrusted IP connection
        - AUTH: Logon / Logoff
        - BENIGN: Normal non-suspicious background operation
        """
        event_type = str(event.get("event_type", "")).upper()
        action = str(event.get("action", "")).upper()
        rel = str(event.get("relationship", "")).upper()
        dst_type = str(event.get("dst_entity_type", "")).upper()
        url = str(event.get("url", "")).lower()
        ip = str(event.get("ip_address", "")).strip()
        cloud_dest = str(event.get("cloud_destination", "")).lower()
        has_usb_id = self._is_valid_value(event.get("usb_device_id"))

        # 1. COPY (Explicit Data Transfer / Staging to USB or Archive) - checked before general USB
        if (
            event_type in ["USB_COPY", "TRANSFERRED_TO_USB"] or
            rel == "TRANSFERRED_TO_USB" or
            (event_type == "FILE_WRITE" and (has_usb_id or self._is_sensitive_asset(event))) or
            (event_type == "FILE" and action in ["WRITE", "COPY"] and (has_usb_id or self._is_sensitive_asset(event)))
        ):
            return "COPY"

        # 2. ACCESS (Sensitive File Read / Access)
        if (
            event_type in ["FILE_READ", "READ_FILE"] or
            rel == "READ_FILE" or
            (event_type == "FILE" and action in ["READ", "OPEN"])
        ):
            if self._is_sensitive_asset(event):
                return "ACCESS"
            return "BENIGN"

        # 3. USB_CONNECT (Removable Storage Connection / Mount)
        if (
            event_type in ["USB_MOUNT", "CONNECTED_USB", "USB_CONNECT"] or
            rel == "CONNECTED_USB" or
            (event_type == "DEVICE" and action in ["CONNECT"]) or
            (dst_type == "USB" and action in ["CONNECT", "MOUNT", ""])
        ):
            return "USB_CONNECT"

        # 4. CHANNEL_PREP (Browser Launch / Shell Spawn)
        if (
            event_type in ["BROWSER_LAUNCH", "LAUNCHED_BROWSER", "PROCESS_SPAWN", "PROCESS_FORK"] or
            rel in ["LAUNCHED_BROWSER", "SPAWNED"]
        ):
            return "CHANNEL_PREP"

        # 5. EGRESS (External Cloud Upload / Network Exfiltration)
        if (
            event_type in ["CLOUD_UPLOAD", "UPLOADED_TO_CLOUD", "HTTP", "NET_CONNECT"] or
            rel in ["UPLOADED_TO_CLOUD", "CONNECTED_IP"] or
            dst_type in ["CLOUD", "IP"]
        ):
            is_untrusted_cloud = any(domain in cloud_dest or domain in url for domain in self.UNTRUSTED_EGRESS_DOMAINS)
            is_wikileaks_or_drop = "wikileaks" in url or "drop" in url or "mega.nz" in url or "dropbox" in url
            
            # Known trusted development/infrastructure destinations
            is_trusted = any(td in cloud_dest or td in url for td in ["github.com", "gitlab.com", "internal", "syslog"])

            is_external_ip = (
                self._is_valid_value(ip) and
                not ip.startswith("10.") and
                not ip.startswith("192.168.") and
                not ip.startswith("127.")
            )

            if is_trusted:
                return "BENIGN"

            if (
                rel == "UPLOADED_TO_CLOUD" or
                event_type == "CLOUD_UPLOAD" or
                is_untrusted_cloud or
                is_wikileaks_or_drop or
                (event_type == "NET_CONNECT" and is_external_ip)
            ):
                return "EGRESS"
            return "BENIGN"

        # 6. AUTH
        if event_type in ["LOGIN", "LOGON", "LOGOFF"] or rel == "LOGGED_INTO":
            return "AUTH"

        return "BENIGN"

    def _build_leakage_path(
        self,
        user: str,
        stage_events: Dict[str, Dict[str, Any]]
    ) -> str:
        """
        Builds a human-readable and graph-readable causality path representing the exfiltration chain:
        User -> Host -> Process -> Resource/File -> Channel -> Destination
        """
        hops = [f"User({user})"]

        # 1. Host / Device
        host = None
        for ev in stage_events.values():
            if self._is_valid_value(ev.get("device")):
                host = ev["device"]
                break
            elif self._is_valid_value(ev.get("pc")):
                host = ev["pc"]
                break
        if host:
            hops.append(f"Host({host})")

        # 2. Process Lineage
        proc = None
        for ev in stage_events.values():
            if self._is_valid_value(ev.get("process_name")):
                proc = ev["process_name"]
                break
        if proc:
            hops.append(f"Process({proc})")

        # 3. Sensitive Asset / File
        file_path = None
        for s in ["ACCESS", "COPY", "EGRESS"]:
            if s in stage_events:
                fp = stage_events[s].get("file_path") or stage_events[s].get("dst_entity_id")
                if self._is_valid_value(fp) and not str(fp).startswith("http"):
                    file_path = fp
                    break
        if file_path:
            hops.append(f"File({file_path})")

        # 4. Removable USB Channel
        usb_id = None
        for ev in stage_events.values():
            if self._is_valid_value(ev.get("usb_device_id")):
                usb_id = ev["usb_device_id"]
                break
            elif ev.get("dst_entity_type") == "USB" and self._is_valid_value(ev.get("dst_entity_id")):
                usb_id = ev["dst_entity_id"]
                break
            elif str(ev.get("event_type", "")).lower() == "device" and str(ev.get("action", "")).lower() == "connect":
                usb_id = "RemovableStorage"
                break
        if usb_id:
            hops.append(f"USB({usb_id})")

        # 5. External Egress Destination
        dest = None
        if "EGRESS" in stage_events:
            eg_ev = stage_events["EGRESS"]
            dest = (
                eg_ev.get("cloud_destination") or
                eg_ev.get("url") or
                eg_ev.get("ip_address") or
                eg_ev.get("dst_entity_id")
            )
        if self._is_valid_value(dest):
            hops.append(f"EgressDestination({dest})")

        return " -> ".join(hops)

    def _calculate_chain_score(
        self,
        base_score: float,
        stages: Dict[str, Dict[str, Any]],
        t_start: datetime,
        t_end: datetime,
        after_hours: bool = False
    ) -> Tuple[float, Dict[str, float]]:
        """
        Calculates calibrated leakage_chain_score (0.0 to 100.0) with an explainable point breakdown.
        """
        breakdown = {
            "base_rule_score": float(base_score),
            "temporal_proximity_bonus": 0.0,
            "graph_causality_bonus": 0.0,
            "after_hours_bonus": 0.0,
        }

        # 1. Temporal Proximity Bonus
        # Tighter execution windows (< 15 mins total) indicate scripted or deliberate exfiltration
        duration_minutes = max(0.1, (t_end - t_start).total_seconds() / 60.0)
        if duration_minutes <= 15.0:
            breakdown["temporal_proximity_bonus"] = 5.0
        elif duration_minutes <= 30.0:
            breakdown["temporal_proximity_bonus"] = 2.5

        # Inter-stage proximity: ACCESS and USB connect within 5 minutes
        if "ACCESS" in stages and "USB_CONNECT" in stages:
            t_acc = self._parse_timestamp(stages["ACCESS"].get("timestamp"))
            t_usb = self._parse_timestamp(stages["USB_CONNECT"].get("timestamp"))
            if t_acc and t_usb and abs((t_usb - t_acc).total_seconds() / 60.0) <= 5.0:
                breakdown["temporal_proximity_bonus"] += 2.5

        # 2. Graph Causality Bonus
        # Confirmed sensitive asset + direct multi-entity path
        has_file = any(bool(ev.get("file_path")) for ev in stages.values())
        has_usb = any(bool(ev.get("usb_device_id")) for ev in stages.values())
        has_ext_cloud = any(bool(ev.get("cloud_destination")) for ev in stages.values())

        if has_file and (has_usb or has_ext_cloud):
            breakdown["graph_causality_bonus"] = 5.0

        # 3. After-Hours Bonus (Night / Weekend)
        if after_hours or t_start.hour < 7 or t_start.hour >= 19 or t_start.weekday() >= 5:
            breakdown["after_hours_bonus"] = 5.0

        total_score = sum(breakdown.values())
        calibrated_score = round(float(min(100.0, max(0.0, total_score))), 2)
        return calibrated_score, breakdown

    def correlate_events(
        self,
        events: List[Dict[str, Any]],
        window_minutes: int = 60
    ) -> Dict[str, Any]:
        """
        Conforms to BaseTemporalCorrelator.
        Evaluates temporal chains within rolling time windows across input events.
        """
        incidents = self.detect_incidents(events, window_minutes=window_minutes)

        if not incidents:
            return {
                "leakage_chain_score": 0.0,
                "matched_sequences": [],
                "stages_completed": 0,
                "incidents": [],
                "total_incidents": 0
            }

        max_score = max(inc["leakage_chain_score"] for inc in incidents)
        all_rules = list({inc["rule_name"] for inc in incidents})
        max_stages = max(inc["stages_completed"] for inc in incidents)

        return {
            "leakage_chain_score": max_score,
            "matched_sequences": all_rules,
            "stages_completed": max_stages,
            "incidents": incidents,
            "total_incidents": len(incidents)
        }

    def detect_incidents(
        self,
        events: Union[List[Dict[str, Any]], pd.DataFrame],
        window_minutes: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Primary engine for combining fragmented security events into consolidated leakage incidents.
        """
        if window_minutes is None:
            window_minutes = int(self.session_window_minutes)

        if isinstance(events, pd.DataFrame):
            event_list = events.to_dict(orient="records")
        else:
            event_list = list(events)

        if not event_list:
            return []

        # Parse timestamps and group by user / host session
        parsed_events = []
        for ev in event_list:
            ev_copy = dict(ev)
            dt = self._parse_timestamp(ev_copy.get("timestamp"))
            if dt is None:
                continue
            ev_copy["_parsed_dt"] = dt
            ev_copy["_stage"] = self._classify_event_stage(ev_copy)
            parsed_events.append(ev_copy)

        if not parsed_events:
            return []

        # Sort chronologically
        parsed_events.sort(key=lambda x: x["_parsed_dt"])

        # Group by user (or PC if user missing)
        user_groups: Dict[str, List[Dict[str, Any]]] = {}
        for ev in parsed_events:
            usr = ev.get("user") or ev.get("pc") or "UNKNOWN_USER"
            user_groups.setdefault(str(usr), []).append(ev)

        detected_incidents = []
        incident_counter = 1

        for user, u_events in user_groups.items():
            # Correlate within rolling sliding windows for this user
            n_events = len(u_events)
            i = 0
            while i < n_events:
                window_start = u_events[i]["_parsed_dt"]
                window_end = window_start + timedelta(minutes=window_minutes)

                # Collect all events inside current window
                window_events = []
                j = i
                while j < n_events and u_events[j]["_parsed_dt"] <= window_end:
                    window_events.append(u_events[j])
                    j += 1

                # Evaluate rules on this window
                incident = self._evaluate_window_rules(user, window_events, incident_counter)
                if incident:
                    # Avoid duplicate overlapping alerts for the same events
                    if not any(
                        inc["user"] == user and inc["incident_start"] == incident["incident_start"]
                        for inc in detected_incidents
                    ):
                        detected_incidents.append(incident)
                        incident_counter += 1
                        # Advance past the triggering sequence to prevent duplicate sliding spam
                        i = j
                        continue
                i += 1

        return detected_incidents

    def _evaluate_window_rules(
        self,
        user: str,
        events: List[Dict[str, Any]],
        incident_num: int
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates explainable correlation rules against a chronologically sorted window of events.
        """
        if len(events) < 2:
            return None

        # Index events by stage
        stages_present: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            stg = ev["_stage"]
            stages_present.setdefault(stg, []).append(ev)

        # -------------------------------------------------------------
        # RULE 1: Full 4-Stage Exfiltration Chain
        # ACCESS -> USB_CONNECT (<=10m) -> COPY (<=15m) -> EGRESS (<=30m)
        # -------------------------------------------------------------
        if (
            "ACCESS" in stages_present and
            "USB_CONNECT" in stages_present and
            "COPY" in stages_present and
            "EGRESS" in stages_present
        ):
            ev_access = stages_present["ACCESS"][0]
            ev_usb = stages_present["USB_CONNECT"][0]
            ev_copy = stages_present["COPY"][0]
            ev_egress = stages_present["EGRESS"][0]

            t_acc = ev_access["_parsed_dt"]
            t_usb = ev_usb["_parsed_dt"]
            t_cpy = ev_copy["_parsed_dt"]
            t_egr = ev_egress["_parsed_dt"]

            # Check temporal ordering & proximity constraints
            # Sensitive file accessed + USB connected within 10 minutes
            if abs((t_usb - t_acc).total_seconds() / 60.0) <= self.usb_window_minutes:
                # Copy activity following USB or Access within 15 minutes
                t_ref = max(t_acc, t_usb)
                if 0 <= (t_cpy - t_ref).total_seconds() / 60.0 <= self.copy_window_minutes:
                    # External upload within 30 minutes of copy activity
                    if 0 <= (t_egr - t_cpy).total_seconds() / 60.0 <= self.egress_window_minutes:
                        participating = [ev_access, ev_usb, ev_copy, ev_egress]
                        matched_stages = {
                            "ACCESS": ev_access,
                            "USB_CONNECT": ev_usb,
                            "COPY": ev_copy,
                            "EGRESS": ev_egress
                        }
                        return self._create_incident_record(
                            rule_id="RULE-FULL-4STAGE-EXFIL",
                            rule_name="Full 4-Stage Exfiltration Chain",
                            user=user,
                            base_score=95.0,
                            severity="CRITICAL",
                            matched_stages=matched_stages,
                            participating_events=participating,
                            incident_num=incident_num,
                            explanation=(
                                f"Sensitive asset '{ev_access.get('file_path')}' accessed, "
                                f"correlated with USB connect ({round(abs((t_usb - t_acc).total_seconds()/60.0), 1)}m delta), "
                                f"copied to removable device, and exfiltrated to external egress within "
                                f"{round((t_egr - t_cpy).total_seconds()/60.0, 1)}m."
                            )
                        )

        # -------------------------------------------------------------
        # RULE 2: USB Removable Exfiltration Chain
        # ACCESS + USB_CONNECT (<=10m) + COPY to USB (<=15m)
        # -------------------------------------------------------------
        if (
            "ACCESS" in stages_present and
            "USB_CONNECT" in stages_present and
            "COPY" in stages_present
        ):
            ev_access = stages_present["ACCESS"][0]
            ev_usb = stages_present["USB_CONNECT"][0]
            ev_copy = stages_present["COPY"][0]

            t_acc = ev_access["_parsed_dt"]
            t_usb = ev_usb["_parsed_dt"]
            t_cpy = ev_copy["_parsed_dt"]

            if abs((t_usb - t_acc).total_seconds() / 60.0) <= self.usb_window_minutes:
                t_ref = min(t_acc, t_usb)
                if (t_cpy >= t_ref) and (t_cpy - t_ref).total_seconds() / 60.0 <= (self.usb_window_minutes + self.copy_window_minutes):
                    participating = [ev_access, ev_usb, ev_copy]
                    matched_stages = {
                        "ACCESS": ev_access,
                        "USB_CONNECT": ev_usb,
                        "COPY": ev_copy
                    }
                    return self._create_incident_record(
                        rule_id="RULE-USB-REMOVABLE-EXFIL",
                        rule_name="Removable Media Exfiltration Chain",
                        user=user,
                        base_score=85.0,
                        severity="CRITICAL",
                        matched_stages=matched_stages,
                        participating_events=participating,
                        incident_num=incident_num,
                        explanation=(
                            f"Restricted file '{ev_access.get('file_path')}' accessed and copied "
                            f"to removable USB device within "
                            f"{round(abs((t_cpy - t_acc).total_seconds()/60.0), 1)} minutes."
                        )
                    )

        # -------------------------------------------------------------
        # RULE 3: Cloud / Web Exfiltration Chain
        # ACCESS + (CHANNEL_PREP or direct) + EGRESS (<=30m)
        # -------------------------------------------------------------
        if "ACCESS" in stages_present and "EGRESS" in stages_present:
            ev_access = stages_present["ACCESS"][0]
            ev_egress = stages_present["EGRESS"][0]

            t_acc = ev_access["_parsed_dt"]
            t_egr = ev_egress["_parsed_dt"]

            if 0 <= (t_egr - t_acc).total_seconds() / 60.0 <= self.egress_window_minutes:
                participating = [ev_access]
                matched_stages = {"ACCESS": ev_access, "EGRESS": ev_egress}
                if "CHANNEL_PREP" in stages_present:
                    ev_prep = stages_present["CHANNEL_PREP"][0]
                    participating.append(ev_prep)
                    matched_stages["CHANNEL_PREP"] = ev_prep
                participating.append(ev_egress)

                dest = ev_egress.get("cloud_destination") or ev_egress.get("url") or ev_egress.get("ip_address")
                return self._create_incident_record(
                    rule_id="RULE-CLOUD-WEB-EXFIL",
                    rule_name="Cloud / Web Exfiltration Chain",
                    user=user,
                    base_score=85.0,
                    severity="CRITICAL",
                    matched_stages=matched_stages,
                    participating_events=participating,
                    incident_num=incident_num,
                    explanation=(
                        f"Sensitive asset '{ev_access.get('file_path')}' accessed and uploaded "
                        f"directly to external cloud/web destination '{dest}' within "
                        f"{round((t_egr - t_acc).total_seconds()/60.0, 1)} minutes."
                    )
                )

        # -------------------------------------------------------------
        # RULE 4: CERT Insider Exfiltration Pattern (Scenario 1)
        # USB_CONNECT + EGRESS (<=30m) [Optionally with AUTH]
        # -------------------------------------------------------------
        if "USB_CONNECT" in stages_present and "EGRESS" in stages_present:
            ev_usb = stages_present["USB_CONNECT"][0]
            ev_egress = stages_present["EGRESS"][0]

            t_usb = ev_usb["_parsed_dt"]
            t_egr = ev_egress["_parsed_dt"]

            delta_mins = (t_egr - t_usb).total_seconds() / 60.0
            if 0 <= delta_mins <= self.egress_window_minutes:
                participating = [ev_usb, ev_egress]
                matched_stages = {"USB_CONNECT": ev_usb, "EGRESS": ev_egress}
                if "AUTH" in stages_present:
                    ev_auth = stages_present["AUTH"][0]
                    participating.insert(0, ev_auth)
                    matched_stages["AUTH"] = ev_auth

                dest = ev_egress.get("url") or ev_egress.get("cloud_destination") or "External Drop"
                return self._create_incident_record(
                    rule_id="RULE-CERT-AFTERHOURS-REMOVABLE-WEB",
                    rule_name="CERT Insider Exfiltration Pattern",
                    user=user,
                    base_score=80.0,
                    severity="HIGH",
                    matched_stages=matched_stages,
                    participating_events=participating,
                    incident_num=incident_num,
                    explanation=(
                        f"Removable storage connected followed by external leak upload to "
                        f"'{dest}' within {round(delta_mins, 1)} minutes."
                    )
                )

        # -------------------------------------------------------------
        # RULE 5: Rapid Staging and Direct Egress
        # COPY + EGRESS (<=30m)
        # -------------------------------------------------------------
        if "COPY" in stages_present and "EGRESS" in stages_present:
            ev_copy = stages_present["COPY"][0]
            ev_egress = stages_present["EGRESS"][0]

            t_cpy = ev_copy["_parsed_dt"]
            t_egr = ev_egress["_parsed_dt"]

            delta_mins = (t_egr - t_cpy).total_seconds() / 60.0
            if 0 <= delta_mins <= self.egress_window_minutes:
                participating = [ev_copy, ev_egress]
                matched_stages = {"COPY": ev_copy, "EGRESS": ev_egress}
                return self._create_incident_record(
                    rule_id="RULE-STAGING-RAPID-EGRESS",
                    rule_name="Rapid Data Staging and Direct Egress",
                    user=user,
                    base_score=70.0,
                    severity="HIGH",
                    matched_stages=matched_stages,
                    participating_events=participating,
                    incident_num=incident_num,
                    explanation=(
                        f"Data copy/staging activity followed directly by external egress within "
                        f"{round(delta_mins, 1)} minutes."
                    )
                )

        return None

    def _create_incident_record(
        self,
        rule_id: str,
        rule_name: str,
        user: str,
        base_score: float,
        severity: str,
        matched_stages: Dict[str, Dict[str, Any]],
        participating_events: List[Dict[str, Any]],
        incident_num: int,
        explanation: str
    ) -> Dict[str, Any]:
        """
        Constructs the unified incident record containing all required output fields.
        """
        # Sort participating events chronologically
        participating_events.sort(key=lambda x: x["_parsed_dt"])

        t_start = participating_events[0]["_parsed_dt"]
        t_end = participating_events[-1]["_parsed_dt"]

        # Calculate calibrated score
        chain_score, score_breakdown = self._calculate_chain_score(
            base_score=base_score,
            stages=matched_stages,
            t_start=t_start,
            t_end=t_end
        )

        # Build causal graph path
        leakage_path = self._build_leakage_path(user, matched_stages)

        # Clean events to strip internal keys
        cleaned_events = []
        for ev in participating_events:
            clean = {k: v for k, v in ev.items() if not k.startswith("_")}
            cleaned_events.append(clean)

        incident_id = f"INC-{t_start.strftime('%Y%m%d')}-{user.upper()}-{incident_num:03d}"

        time_span = max(0.0, round((t_end - t_start).total_seconds() / 60.0, 2))

        return {
            "incident_id": incident_id,
            "leakage_chain_score": chain_score,
            "incident_start": t_start.strftime("%Y-%m-%d %H:%M:%S"),
            "incident_end": t_end.strftime("%Y-%m-%d %H:%M:%S"),
            "incident_events": cleaned_events,
            "leakage_path": leakage_path,
            "user": user,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity_tier": severity,
            "stages_completed": len(matched_stages),
            "stages_matched": list(matched_stages.keys()),
            "time_span_minutes": time_span,
            "explanation": explanation,
            "score_breakdown": score_breakdown
        }

    def save_rules(self, filepath: Union[str, Path]) -> None:
        """Saves current correlation configuration and rules to JSON."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {
            "engine": "TemporalLeakageCorrelator",
            "version": "1.0.0",
            "use_gnn": False,
            "windows": {
                "usb_window_minutes": self.usb_window_minutes,
                "copy_window_minutes": self.copy_window_minutes,
                "egress_window_minutes": self.egress_window_minutes,
                "session_window_minutes": self.session_window_minutes,
                "alert_score_threshold": self.alert_score_threshold,
            },
            "sensitive_keywords": list(sorted(self.SENSITIVE_KEYWORDS)),
            "untrusted_egress_domains": list(sorted(self.UNTRUSTED_EGRESS_DOMAINS)),
            "rules": self.custom_rules
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        logger.info(f"Saved temporal correlation rules to {path}")

    @classmethod
    def load_rules(cls, filepath: Union[str, Path]) -> "TemporalLeakageCorrelator":
        """Loads correlator from saved JSON configuration."""
        path = Path(filepath)
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        windows = cfg.get("windows", {})
        return cls(
            usb_window_minutes=windows.get("usb_window_minutes", cls.DEFAULT_USB_WINDOW_MINUTES),
            copy_window_minutes=windows.get("copy_window_minutes", cls.DEFAULT_COPY_WINDOW_MINUTES),
            egress_window_minutes=windows.get("egress_window_minutes", cls.DEFAULT_EGRESS_WINDOW_MINUTES),
            session_window_minutes=windows.get("session_window_minutes", cls.DEFAULT_SESSION_WINDOW_MINUTES),
            alert_score_threshold=windows.get("alert_score_threshold", cls.DEFAULT_ALERT_SCORE_THRESHOLD),
            custom_rules=cfg.get("rules")
        )


__all__ = ["TemporalLeakageCorrelator"]
