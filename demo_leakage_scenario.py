"""
LeakMind Phase 11: Controlled Multi-Stage Leakage Scenario Demo
Executes end-to-end integration across all 8 pipeline stages:

Raw Logs -> Preprocessing -> Feature Engineering -> Behavior AI ->
Sensitive Data AI -> Provenance Graph -> Temporal Correlator ->
XGBoost Risk Fusion -> SHAP Explainability -> Policy Engine -> Final Decision

Demonstrates:
1. Multi-Stage Insider Threat Exfiltration Scenario (INSIDER_ALICE) -> BLOCK
2. Clean Baseline Normal Employee Scenario (NORMAL_BOB) -> ALLOW

Produces structured academic demo output and saves forensic report.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import LeakMindPipeline, PipelineResult
from src.utils.logger import get_logger

logger = get_logger("leakmind.demo")


def run_controlled_demo():
    print("=" * 80)
    print(" LEAKMIND: EXPLAINABLE MULTI-EVIDENCE DATA-LEAKAGE DETECTION FRAMEWORK")
    print(" END-TO-END PIPELINE INTEGRATION & SCENARIO DEMONSTRATION")
    print("=" * 80)

    # Initialize master pipeline
    pipeline = LeakMindPipeline()

    # =========================================================================
    # SCENARIO 1: Controlled Multi-Stage Insider Threat Leakage Attack
    # =========================================================================
    print("\n" + "#" * 80)
    print(" SCENARIO 1: CONTROLLED MULTI-STAGE EXFILTRATION ATTACK (INSIDER_ALICE)")
    print("#" * 80)

    alice_events = [
        {
            "timestamp": "2026-10-08 22:45:00 UTC",
            "user": "INSIDER_ALICE",
            "pc": "PC-4029",
            "activity": "Logon",
            "type": "LOGON",
            "is_after_hours": True,
            "description": "After-hours interactive workstation logon"
        },
        {
            "timestamp": "2026-10-08 22:52:14 UTC",
            "user": "INSIDER_ALICE",
            "pc": "PC-4029",
            "activity": "READ_FILE",
            "type": "FILE",
            "file": "C:/Finance/Q4_Executive_Compensation_and_SSN.xlsx",
            "is_after_hours": True,
            "description": "Access to crown-jewel payroll and employee PII document"
        },
        {
            "timestamp": "2026-10-08 23:01:40 UTC",
            "user": "INSIDER_ALICE",
            "pc": "PC-4029",
            "activity": "CONNECTED_USB",
            "type": "DEVICE",
            "device": "USB-CORSAIR-EXTREME-64GB",
            "is_after_hours": True,
            "description": "Removable USB mass storage device connected"
        },
        {
            "timestamp": "2026-10-08 23:08:22 UTC",
            "user": "INSIDER_ALICE",
            "pc": "PC-4029",
            "activity": "FILE_COPY_STAGE",
            "type": "FILE",
            "file": "D:/Staged_Bundles/finance_dump.tar.gz",
            "is_after_hours": True,
            "description": "Staged compressed archive copy to removable mount"
        },
        {
            "timestamp": "2026-10-08 23:19:05 UTC",
            "user": "INSIDER_ALICE",
            "pc": "PC-4029",
            "activity": "UPLOAD_TO_CLOUD",
            "type": "HTTP",
            "destination": "https://drop-box-temp.cloud/api/v1/upload",
            "is_after_hours": True,
            "description": "External unauthorized egress to cloud drop via curl.exe"
        }
    ]

    alice_content_samples = [
        "CONFIDENTIAL EXECUTIVE PAYROLL & TAX RECORDS\n"
        "Employee: John Doe | SSN: 123-45-6789 | Salary: $285,000 | IBAN: GB29NWBK60161331926819\n"
        "Employee: Jane Smith | SSN: 987-65-4321 | Salary: $310,000 | Routing: 021000021\n"
        "API Secret: api_key=mock_internal_service_api_token_99182746\n"
        "STRICTLY CONFIDENTIAL TRADE SECRET MERGER ACQUISITION TERMS"
    ]

    alice_result: PipelineResult = pipeline.process_events(
        raw_events=alice_events,
        user_id="INSIDER_ALICE",
        content_samples=alice_content_samples,
        context_metadata={
            "role": "Financial Quantitative Analyst",
            "historical_user_risk": 55.0,
            "external_destination": True,
            "new_device": True
        }
    )

    print("\n--- [STAGE-BY-STAGE PIPELINE TRACE: INSIDER_ALICE] ---")
    print(f"1. Raw Telemetry Ingested    : {alice_result.total_events} raw events parsed & time-aligned")
    print(f"2. Preprocessing & Context   : After-Hours={alice_result.feature_vector['after_hours_activity']}, USB={alice_result.feature_vector['usb_activity']}, Dest={alice_result.feature_vector['external_destination']}")
    print(f"3. Behavior AI Engine        : Risk Score = {alice_result.behavior_risk:.1f}% (Anomaly Score = {alice_result.raw_anomaly_score:.3f})")
    print(f"4. Sensitive Data AI Engine  : Sensitivity Score = {alice_result.sensitivity_risk:.1f}% | Tier = {alice_result.sensitivity_level}")
    print(f"   -> Sensitive Findings     : {len(alice_result.sensitive_findings)} high-critical markers (SSN, IBAN, AWS Keys, Salaries)")
    print(f"5. Provenance Graph Engine   : Graph Risk = {alice_result.graph_risk:.1f}% | Paths = {alice_result.suspicious_paths_count} suspicious exfiltration vectors")
    print(f"6. Temporal Correlation      : Leakage Chain Score = {alice_result.leakage_chain_score:.1f}% (ID: {alice_result.incident_id})")
    print(f"   -> Causal Kill-Chain Path : {' -> '.join(alice_result.leakage_path)}")
    print(f"7. XGBoost Risk Fusion       : Final Risk Score = {alice_result.final_risk_score:.1f}% (Probability = {alice_result.final_risk_probability:.4f}, Tier = {alice_result.risk_tier})")
    print(f"\n8. SHAP Attribution Narrative (Phase 9 Format):\n")
    print(alice_result.explanation_narrative)
    print(f"\n9. Policy Engine Response (Phase 10):\n")
    print(f"   Rule Triggered : {alice_result.policy_rule_triggered}")
    print(f"   Policy Reason  : {alice_result.policy_reason}")
    print(f"   FINAL DECISION : [{alice_result.decision}]")

    # =========================================================================
    # SCENARIO 2: Clean Baseline Normal Employee Activity
    # =========================================================================
    print("\n" + "#" * 80)
    print(" SCENARIO 2: BENIGN BASELINE NORMAL EMPLOYEE (NORMAL_BOB)")
    print("#" * 80)

    bob_events = [
        {
            "timestamp": "2026-10-09 10:15:00 UTC",
            "user": "NORMAL_BOB",
            "pc": "PC-1082",
            "activity": "Logon",
            "type": "LOGON",
            "is_after_hours": False,
            "description": "Standard business hours workstation logon"
        },
        {
            "timestamp": "2026-10-09 10:22:10 UTC",
            "user": "NORMAL_BOB",
            "pc": "PC-1082",
            "activity": "READ_FILE",
            "type": "FILE",
            "file": "C:/Docs/Company_Onboarding_Handbook.pdf",
            "is_after_hours": False,
            "description": "Access to public employee onboarding guide"
        },
        {
            "timestamp": "2026-10-09 10:45:00 UTC",
            "user": "NORMAL_BOB",
            "pc": "PC-1082",
            "activity": "BROWSE_INTRANET",
            "type": "HTTP",
            "destination": "http://intranet.corp.local/wiki/home",
            "is_after_hours": False,
            "description": "Internal company intranet portal browsing"
        }
    ]

    bob_content_samples = [
        "Welcome to the Employee Handbook. Standard operating hours are 9 AM to 5 PM.\n"
        "Please submit expense reports via the internal portal. Have a great day!"
    ]

    bob_result: PipelineResult = pipeline.process_events(
        raw_events=bob_events,
        user_id="NORMAL_BOB",
        content_samples=bob_content_samples,
        context_metadata={
            "role": "Marketing Associate",
            "historical_user_risk": 5.0,
            "external_destination": False,
            "new_device": False
        }
    )

    print("\n--- [STAGE-BY-STAGE PIPELINE TRACE: NORMAL_BOB] ---")
    print(f"1. Raw Telemetry Ingested    : {bob_result.total_events} raw events parsed")
    print(f"2. Preprocessing & Context   : After-Hours={bob_result.feature_vector['after_hours_activity']}, USB={bob_result.feature_vector['usb_activity']}, Dest={bob_result.feature_vector['external_destination']}")
    print(f"3. Behavior AI Engine        : Risk Score = {bob_result.behavior_risk:.1f}% (Anomaly Score = {bob_result.raw_anomaly_score:.3f})")
    print(f"4. Sensitive Data AI Engine  : Sensitivity Score = {bob_result.sensitivity_risk:.1f}% | Tier = {bob_result.sensitivity_level}")
    print(f"5. Provenance Graph Engine   : Graph Risk = {bob_result.graph_risk:.1f}% | Paths = {bob_result.suspicious_paths_count}")
    print(f"6. Temporal Correlation      : Leakage Chain Score = {bob_result.leakage_chain_score:.1f}%")
    print(f"7. XGBoost Risk Fusion       : Final Risk Score = {bob_result.final_risk_score:.1f}% (Probability = {bob_result.final_risk_probability:.4f}, Tier = {bob_result.risk_tier})")
    print(f"\n8. Policy Engine Response (Phase 10):\n")
    print(f"   Rule Triggered : {bob_result.policy_rule_triggered}")
    print(f"   Policy Reason  : {bob_result.policy_reason}")
    print(f"   FINAL DECISION : [{bob_result.decision}]")

    # =========================================================================
    # Save Report
    # =========================================================================
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / "end_to_end_demo_report.json"

    demo_report = {
        "report_title": "LeakMind Phase 11 End-to-End Pipeline Demonstration Report",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scenario_1_insider_alice": alice_result.to_dict(),
        "scenario_2_benign_bob": bob_result.to_dict(),
        "academic_summary": {
            "pipeline_stages_verified": [
                "Raw Logs", "Preprocessing", "Feature Engineering", "Behavior AI",
                "Sensitive Data AI", "Neo4j Provenance Graph", "Temporal Correlation",
                "XGBoost Risk Fusion", "SHAP Explainability", "Policy Engine"
            ],
            "attack_scenario_decision": alice_result.decision,
            "benign_scenario_decision": bob_result.decision,
            "disclaimer": "Thresholds represent initial heuristic boundaries and are not claimed to be optimal."
        }
    }

    with open(report_file, "w") as f:
        json.dump(demo_report, f, indent=2)

    print("\n" + "=" * 80)
    print(f"[+] Saved complete forensic demonstration report to: {report_file}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_controlled_demo()
