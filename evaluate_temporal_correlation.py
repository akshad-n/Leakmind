"""
LeakMind Phase 7: Temporal and Graph-Based Incident Correlation Evaluation
Evaluates explainable temporal correlation rules on empirical cybersecurity telemetry:
- DARPA Transparent Computing provenance events (malicious exfiltration chains + benign developer/sysadmin chains)
- CERT Insider Threat Scenario 1 exfiltration telemetry (30 malicious insiders)
- CERT Enterprise Benign Background User sessions (30 normal employees with USB and web activity)
- Controlled Edge-Case Benign Sessions (disjoint access, non-sensitive copy, documentation browsing)

Strict constraint: Strictly explainable rules - NO GNN.
Computes and reports:
- incident precision
- incident recall
- incident F1
- false alerts
Zero fabrication.
"""

import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.temporal import TemporalLeakageCorrelator
from src.utils.logger import get_logger

logger = get_logger("leakmind.evaluate_temporal")


def build_evaluation_sessions() -> List[Dict[str, Any]]:
    """
    Constructs a comprehensive, grounded evaluation suite containing both
    ground-truth malicious exfiltration sessions and ground-truth benign control sessions.
    """
    sessions = []

    # -------------------------------------------------------------
    # 1. DARPA Transparent Computing Sessions (Ground Truth)
    # -------------------------------------------------------------
    darpa_path = PROJECT_ROOT / "data" / "raw" / "darpa" / "darpa_tc_events.csv"
    if darpa_path.exists():
        df_darpa = pd.read_csv(darpa_path)
        for chain_id, group in df_darpa.groupby("provenance_chain_id"):
            is_suspicious = int(group["is_suspicious"].iloc[0])
            user = str(group["user"].iloc[0])
            sessions.append({
                "session_id": f"DARPA_{chain_id}",
                "source": "DARPA_TC",
                "user": user,
                "ground_truth_label": is_suspicious,  # 1 for exfil, 0 for benign
                "events": group.to_dict(orient="records"),
                "description": f"DARPA TC chain {chain_id} ({user})"
            })

    # -------------------------------------------------------------
    # 2. CERT Insider Threat Scenario 1 Sessions (Ground Truth Malicious)
    # -------------------------------------------------------------
    cert_path = PROJECT_ROOT / "data" / "processed" / "r42_all_parsed_events.csv"
    if cert_path.exists():
        df_cert = pd.read_csv(cert_path)
        sc1 = df_cert[df_cert["scenario"].str.contains("r4.2-1")].copy()
        for user, group in sc1.groupby("user"):
            sessions.append({
                "session_id": f"CERT_SC1_{user}",
                "source": "CERT_r4.2_Scenario1",
                "user": str(user),
                "ground_truth_label": 1,  # Ground truth malicious exfiltration
                "events": group.to_dict(orient="records"),
                "description": f"CERT Scenario 1 Insider Exfiltration ({user})"
            })

    # -------------------------------------------------------------
    # 3. CERT Benign Background Control Sessions (Ground Truth Normal)
    # Normal enterprise employees with legitimate USB connections and web browsing
    # -------------------------------------------------------------
    r1_dev_path = PROJECT_ROOT / "data" / "raw" / "r1" / "r1" / "device.csv"
    r1_log_path = PROJECT_ROOT / "data" / "raw" / "r1" / "r1" / "logon.csv"
    r1_http_path = PROJECT_ROOT / "data" / "raw" / "r1" / "r1" / "http.csv"

    if r1_dev_path.exists() and r1_log_path.exists() and r1_http_path.exists():
        df_dev = pd.read_csv(r1_dev_path, nrows=1000)
        df_dev = df_dev.rename(columns={"date": "timestamp", "activity": "action"})
        df_dev["event_type"] = "device"

        df_log = pd.read_csv(r1_log_path, nrows=1000)
        df_log = df_log.rename(columns={"date": "timestamp", "activity": "action"})
        df_log["event_type"] = "logon"

        df_http = pd.read_csv(r1_http_path, nrows=1000)
        df_http = df_http.rename(columns={"date": "timestamp", "activity": "action"})
        df_http["event_type"] = "http"

        df_r1_all = pd.concat([df_dev, df_log, df_http], ignore_index=True)
        r1_users = df_r1_all["user"].unique()
        # Select 30 distinct normal users
        selected_benign_users = r1_users[:30]
        for u in selected_benign_users:
            u_events = df_r1_all[df_r1_all["user"] == u].sort_values("timestamp")
            sessions.append({
                "session_id": f"CERT_BENIGN_{u}",
                "source": "CERT_r1_Enterprise_Normal",
                "user": str(u),
                "ground_truth_label": 0,  # Ground truth benign normal
                "events": u_events.to_dict(orient="records"),
                "description": f"CERT Normal Enterprise Employee Activity ({u})"
            })

    # -------------------------------------------------------------
    # 4. Controlled Edge-Case Benign Sessions (Ground Truth Normal)
    # Specific negative test cases to rigorously probe false positive resistance
    # -------------------------------------------------------------
    # Edge case 1: Disjoint sensitive access and USB connect (> 4 hours apart, no copy)
    sessions.append({
        "session_id": "EDGE_BENIGN_DISJOINT_TIME",
        "source": "Controlled_Edge_Case",
        "user": "frank_analyst",
        "ground_truth_label": 0,
        "events": [
            {
                "event_id": "EDG-001",
                "timestamp": "2026-06-01 09:00:00",
                "event_type": "FILE_READ",
                "user": "frank_analyst",
                "device": "WKSTN-101",
                "process_name": "excel.exe",
                "file_path": "C:/Finance/Restricted_Budgets.xlsx",
                "relationship": "READ_FILE"
            },
            {
                "event_id": "EDG-002",
                "timestamp": "2026-06-01 15:30:00",  # 6.5 hours later!
                "event_type": "USB_MOUNT",
                "user": "frank_analyst",
                "device": "WKSTN-101",
                "action": "Connect",
                "usb_device_id": "USB-PHONE-CHARGE",
                "relationship": "CONNECTED_USB"
            }
        ],
        "description": "Sensitive file read in morning, phone charger connected 6.5 hours later"
    })

    # Edge case 2: Benign file copied to USB (non-sensitive marketing slides)
    sessions.append({
        "session_id": "EDGE_BENIGN_MARKETING_COPY",
        "source": "Controlled_Edge_Case",
        "user": "grace_marketing",
        "ground_truth_label": 0,
        "events": [
            {
                "event_id": "EDG-010",
                "timestamp": "2026-06-01 10:00:00",
                "event_type": "USB_MOUNT",
                "user": "grace_marketing",
                "device": "MKT-LAPTOP-02",
                "action": "Connect",
                "usb_device_id": "USB-CONFERENCE-DRIVE",
                "relationship": "CONNECTED_USB"
            },
            {
                "event_id": "EDG-011",
                "timestamp": "2026-06-01 10:05:00",
                "event_type": "FILE_READ",
                "user": "grace_marketing",
                "device": "MKT-LAPTOP-02",
                "process_name": "powerpnt.exe",
                "file_path": "C:/Marketing/Public_Conference_Deck.pptx",
                "relationship": "READ_FILE"
            },
            {
                "event_id": "EDG-012",
                "timestamp": "2026-06-01 10:06:30",
                "event_type": "FILE_WRITE",
                "user": "grace_marketing",
                "device": "MKT-LAPTOP-02",
                "file_path": "E:/Public_Conference_Deck.pptx",
                "relationship": "WROTE_FILE"
            }
        ],
        "description": "Copying public conference slides to presentation USB"
    })

    # Edge case 3: Legitimate technical documentation surfing without file access
    sessions.append({
        "session_id": "EDGE_BENIGN_DEV_RESEARCH",
        "source": "Controlled_Edge_Case",
        "user": "heidi_researcher",
        "ground_truth_label": 0,
        "events": [
            {
                "event_id": "EDG-020",
                "timestamp": "2026-06-01 11:00:00",
                "event_type": "LOGIN",
                "user": "heidi_researcher",
                "device": "DEV-STATION-08",
                "relationship": "LOGGED_INTO"
            },
            {
                "event_id": "EDG-021",
                "timestamp": "2026-06-01 11:02:00",
                "event_type": "BROWSER_LAUNCH",
                "user": "heidi_researcher",
                "device": "DEV-STATION-08",
                "process_name": "firefox",
                "relationship": "LAUNCHED_BROWSER"
            },
            {
                "event_id": "EDG-022",
                "timestamp": "2026-06-01 11:05:00",
                "event_type": "HTTP",
                "user": "heidi_researcher",
                "device": "DEV-STATION-08",
                "url": "https://docs.python.org/3/library/multiprocessing.html",
                "cloud_destination": "python.org"
            }
        ],
        "description": "Legitimate technical documentation web browsing"
    })

    return sessions


def run_evaluation(
    save_dir: str = "saved_models/temporal",
    reports_dir: str = "reports"
) -> Dict[str, Any]:
    """
    Executes rigorous evaluation of TemporalLeakageCorrelator across all sessions.
    Computes empirical incident precision, recall, F1, and false alerts.
    """
    print("=" * 80)
    print("LEAKMIND PHASE 7: TEMPORAL & GRAPH-BASED LEAKAGE CORRELATION EVALUATION")
    print("=" * 80)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    rep_path = Path(reports_dir)
    rep_path.mkdir(parents=True, exist_ok=True)

    # 1. Initialize Correlator
    correlator = TemporalLeakageCorrelator(
        usb_window_minutes=10.0,
        copy_window_minutes=15.0,
        egress_window_minutes=75.0,
        session_window_minutes=120.0,
        alert_score_threshold=60.0
    )

    # 2. Build Evaluation Sessions
    print("[1/4] Constructing ground truth evaluation telemetry...")
    sessions = build_evaluation_sessions()
    print(f"      Total Evaluation Sessions: {len(sessions)}")

    malicious_count = sum(1 for s in sessions if s["ground_truth_label"] == 1)
    benign_count = sum(1 for s in sessions if s["ground_truth_label"] == 0)
    print(f"      - Ground Truth Malicious Exfiltration Sessions: {malicious_count}")
    print(f"      - Ground Truth Benign Control Sessions:         {benign_count}")

    # 3. Run Correlation & Compute Empirical Metrics
    print("\n[2/4] Executing Temporal & Graph-Based Correlation Engine...")

    tp = 0  # True Positives: Malicious session flagged as incident
    fp = 0  # False Positives: Benign session falsely flagged (False Alerts)
    fn = 0  # False Negatives: Malicious session missed
    tn = 0  # True Negatives: Benign session correctly ignored

    detected_incidents = []
    session_results = []

    for s in sessions:
        evs = s["events"]
        gt_label = s["ground_truth_label"]
        incidents = correlator.detect_incidents(evs)

        # Flag as incident if at least one incident with score >= threshold detected
        flagged_incidents = [i for i in incidents if i["leakage_chain_score"] >= correlator.alert_score_threshold]
        has_alert = len(flagged_incidents) > 0

        if gt_label == 1:
            if has_alert:
                tp += 1
                outcome = "TP (Hit)"
            else:
                fn += 1
                outcome = "FN (Miss)"
        else:
            if has_alert:
                fp += 1
                outcome = "FP (False Alert)"
            else:
                tn += 1
                outcome = "TN (Clean)"

        for inc in flagged_incidents:
            detected_incidents.append(inc)

        max_score = max([i["leakage_chain_score"] for i in flagged_incidents], default=0.0)
        session_results.append({
            "session_id": s["session_id"],
            "source": s["source"],
            "user": s["user"],
            "ground_truth": gt_label,
            "predicted_incident": int(has_alert),
            "outcome": outcome,
            "max_score": max_score,
            "incidents_count": len(flagged_incidents),
            "description": s["description"]
        })

    # 4. Compute Metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(sessions) if len(sessions) > 0 else 0.0
    false_alerts = fp

    print("\n[3/4] EMPIRICAL INCIDENT CORRELATION PERFORMANCE:")
    print("-" * 80)
    print(f"Total Evaluated Sessions : {len(sessions)}")
    print(f"True Positives  (TP)     : {tp:3d} (Exfiltration attacks successfully detected)")
    print(f"False Positives (FP)     : {fp:3d} (False alerts on benign traffic)")
    print(f"False Negatives (FN)     : {fn:3d} (Missed attacks)")
    print(f"True Negatives  (TN)     : {tn:3d} (Benign traffic correctly cleared)")
    print("-" * 80)
    print(f"Incident Precision       : {precision:.4f} ({precision * 100:.2f}%)")
    print(f"Incident Recall          : {recall:.4f} ({recall * 100:.2f}%)")
    print(f"Incident F1-Score        : {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"False Alerts (Count)     : {false_alerts:d}")
    print(f"Overall Accuracy         : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print("-" * 80)

    # 5. Display Representative Incidents
    print("\n[4/4] RECONSTRUCTED INCIDENT CORRELATION SAMPLES:")
    print("=" * 80)
    sample_display = detected_incidents[:5]
    for idx, inc in enumerate(sample_display, 1):
        print(f"\n[!] Sample Incident #{idx}: {inc['incident_id']}")
        print(f"    User            : {inc['user']}")
        print(f"    Risk Score      : {inc['leakage_chain_score']} ({inc['severity_tier']})")
        print(f"    Rule Triggered  : {inc['rule_name']} [{inc['rule_id']}]")
        print(f"    Time Range      : {inc['incident_start']} -> {inc['incident_end']} ({inc['time_span_minutes']} min)")
        print(f"    Leakage Path    : {inc['leakage_path']}")
        print(f"    Events Correlated: {len(inc['incident_events'])} events")
        print(f"    Explanation     : {inc['explanation']}")

    # 6. Export Artifacts and Reports
    metrics_summary = {
        "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "engine": "TemporalLeakageCorrelator",
        "gnn_used": False,
        "evaluation_method": "Empirical ground-truth telemetry (DARPA TC + CERT r4.2 Scenario 1 + CERT r1 Enterprise Control)",
        "total_sessions_evaluated": len(sessions),
        "ground_truth_breakdown": {
            "malicious_sessions": malicious_count,
            "benign_sessions": benign_count
        },
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn
        },
        "empirical_metrics": {
            "incident_precision": round(precision, 4),
            "incident_recall": round(recall, 4),
            "incident_f1": round(f1, 4),
            "false_alerts": false_alerts,
            "accuracy": round(accuracy, 4)
        },
        "windows_used": {
            "usb_window_minutes": correlator.usb_window_minutes,
            "copy_window_minutes": correlator.copy_window_minutes,
            "egress_window_minutes": correlator.egress_window_minutes,
            "session_window_minutes": correlator.session_window_minutes,
            "alert_score_threshold": correlator.alert_score_threshold
        },
        "sample_incidents": detected_incidents[:10],
        "session_evaluations": session_results
    }

    report_path1 = save_path / "temporal_correlation_report.json"
    report_path2 = rep_path / "temporal_correlation_report.json"

    with open(report_path1, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)
    with open(report_path2, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    # Save rules config
    correlator.save_rules(save_path / "correlation_rules.json")

    print(f"\n[+] Saved evaluation report to : {report_path1}")
    print(f"[+] Saved duplicate report to  : {report_path2}")
    print(f"[+] Saved correlation rules to : {save_path / 'correlation_rules.json'}")
    print("=" * 80)
    print("PHASE 7 TEMPORAL & GRAPH CORRELATION EVALUATION COMPLETE!")
    print("=" * 80)

    return metrics_summary


if __name__ == "__main__":
    run_evaluation()
