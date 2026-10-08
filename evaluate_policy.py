"""
LeakMind Phase 10: Policy Engine CLI & Evaluation Runner
Evaluates risk, data sensitivity, destination risk, and context against configurable policy rules.

Supports:
- Single incident evaluation:
    python evaluate_policy.py --risk 94 --sensitivity CRITICAL --destination "External Cloud"
- Batch dataset evaluation:
    python evaluate_policy.py --batch
- Self-test verification:
    python evaluate_policy.py --test

Notice:
Thresholds represent initial heuristic boundaries and are NOT claimed to be optimal.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.decision.policy import PolicyEngine, PolicyResult, POLICY_OPTIMALITY_DISCLAIMER
from src.utils.logger import get_logger

logger = get_logger("leakmind.evaluate_policy")


def evaluate_single_incident(
    engine: PolicyEngine,
    risk: float,
    sensitivity: str,
    destination: str,
    context: Optional[Dict[str, Any]] = None
) -> PolicyResult:
    """Evaluates a single security incident against active policy engine rules."""
    context = context or {}
    result = engine.evaluate(
        final_risk=risk,
        sensitivity_level=sensitivity,
        destination_risk=destination,
        context=context
    )
    return result


def print_incident_result(result: PolicyResult):
    """Prints result in the exact format required by Phase 10 specification."""
    dest_str = str(result.destination_risk)
    print("\n" + "=" * 60)
    print("LEAKMIND POLICY ENGINE EVALUATION")
    print("=" * 60)
    print(f"Risk = {result.risk:g}")
    print(f"Sensitivity = {result.sensitivity_level}")
    print(f"Destination = {dest_str}\n")
    print(f"Decision = {result.decision}")
    print(f"\nRule Triggered : {result.policy_rule_triggered}")
    print(f"Reason         : {result.reason}")
    print("-" * 60)
    print(f"[*] {POLICY_OPTIMALITY_DISCLAIMER}")
    print("=" * 60 + "\n")


def run_batch_evaluation(
    engine: PolicyEngine,
    data_path: str = "data/processed/cert_context_supervised.csv",
    shap_report_path: str = "reports/shap_explainability_report.json",
    output_report_path: str = "reports/phase10_policy_report.json"
):
    """
    Evaluates policy decisions across dataset incidents and generates comprehensive Phase 10 report.
    """
    print("\n" + "=" * 60)
    print("LEAKMIND BATCH POLICY EVALUATION ACROSS MULTI-EVIDENCE DATASET")
    print("=" * 60)

    incidents_to_evaluate = []

    # Priority 1: Check SHAP high risk incidents report if available
    if os.path.exists(shap_report_path):
        with open(shap_report_path, "r") as f:
            shap_data = json.load(f)
        high_risk_list = shap_data.get("high_risk_incidents", [])
        for inc in high_risk_list:
            risk_val = inc.get("final_risk_score", 90.0)
            sens_val = inc.get("shap_values", {}).get("sensitivity_risk", {}).get("actual_value", 50.0)
            dest_val = inc.get("shap_values", {}).get("destination_risk", {}).get("actual_value", 50.0)
            is_after = inc.get("shap_values", {}).get("after_hours_activity", {}).get("actual_value", 0.0) > 0
            usb_act = inc.get("shap_values", {}).get("usb_activity", {}).get("actual_value", 0.0)

            # Determine sensitivity level string
            if sens_val >= 75.0:
                sens_str = "CRITICAL"
            elif sens_val >= 50.0:
                sens_str = "HIGH"
            elif sens_val >= 25.0:
                sens_str = "MEDIUM"
            else:
                sens_str = "LOW"

            # Determine destination string
            if dest_val >= 50.0:
                dest_str = "External Cloud"
            elif usb_act > 0:
                dest_str = "USB Removable Storage"
            else:
                dest_str = "Internal Corporate Network"

            incidents_to_evaluate.append({
                "user": inc.get("user", "UNKNOWN"),
                "risk": risk_val,
                "sensitivity": sens_str,
                "destination": dest_str,
                "context": {
                    "is_after_hours": is_after,
                    "usb_activity": usb_act,
                    "index": inc.get("index")
                }
            })

    # Priority 2: Also add supervised dataset samples if needed
    if os.path.exists(data_path):
        df = pd.read_csv(data_path)
        for _, row in df.head(70).iterrows():
            r_val = float(row.get("risk_score", 30.0 if row.get("insider_threat_label", 0) == 0 else 85.0))
            is_insider = int(row.get("insider_threat_label", 0)) == 1
            sens_str = "HIGH" if is_insider else "LOW"
            dest_str = "External Cloud" if (is_insider or row.get("destination_risk", 0) > 50) else "Internal Network"
            incidents_to_evaluate.append({
                "user": str(row.get("user", "USER")),
                "risk": r_val,
                "sensitivity": sens_str,
                "destination": dest_str,
                "context": {
                    "is_after_hours": row.get("after_hours_activity", 0) > 0,
                    "usb_activity": row.get("usb_activity", 0)
                }
            })

    print(f"[*] Total incidents collected for evaluation: {len(incidents_to_evaluate)}")

    results = []
    decision_counts = {"ALLOW": 0, "MONITOR": 0, "ALERT / APPROVAL": 0, "BLOCK": 0}
    rule_counts = {}

    for inc in incidents_to_evaluate:
        res = engine.evaluate(
            final_risk=inc["risk"],
            sensitivity_level=inc["sensitivity"],
            destination_risk=inc["destination"],
            context=inc["context"]
        )
        dec = res.decision
        decision_counts[dec] = decision_counts.get(dec, 0) + 1
        rule_counts[res.policy_rule_triggered] = rule_counts.get(res.policy_rule_triggered, 0) + 1

        results.append({
            "user": inc["user"],
            "risk": inc["risk"],
            "sensitivity": inc["sensitivity"],
            "destination": inc["destination"],
            "decision": res.decision,
            "policy_rule_triggered": res.policy_rule_triggered,
            "reason": res.reason
        })

    total = len(results)
    print("\nPolicy Decision Distribution:")
    print("-" * 45)
    for dec, count in decision_counts.items():
        pct = (count / total * 100.0) if total > 0 else 0.0
        print(f"  {dec:<18}: {count:>4} ({pct:>5.1f}%)")

    print("\nTop Policy Rules Triggered:")
    print("-" * 45)
    for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {rule:<32}: {count:>4}")

    os.makedirs(os.path.dirname(os.path.abspath(output_report_path)), exist_ok=True)
    report_data = {
        "report_title": "LeakMind Phase 10 Policy Engine Evaluation Report",
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "active_thresholds": engine.get_thresholds(),
        "disclaimer": POLICY_OPTIMALITY_DISCLAIMER,
        "total_evaluations": total,
        "decision_summary": decision_counts,
        "rule_summary": rule_counts,
        "sample_evaluations": results[:20]
    }

    with open(output_report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[+] Saved full policy evaluation report to: {output_report_path}")
    print(f"[*] {POLICY_OPTIMALITY_DISCLAIMER}\n")


def run_verification_test_suite():
    """
    Executes automated test cases across all boundary intervals and contextual rules.
    """
    print("\n" + "=" * 60)
    print("RUNNING PHASE 10 POLICY ENGINE VERIFICATION TEST SUITE")
    print("=" * 60)

    engine = PolicyEngine(
        allow_threshold=40.0,
        monitor_threshold=70.0,
        alert_threshold=90.0,
        block_threshold=90.0
    )

    # Test Case 1: The exact user prompt example
    # Risk = 94, Sensitivity = CRITICAL, Destination = External Cloud -> BLOCK
    res1 = engine.evaluate(
        final_risk=94.0,
        sensitivity_level="CRITICAL",
        destination_risk="External Cloud"
    )
    print(f"Test 1 (User Example: Risk=94, CRITICAL, External Cloud):")
    print(f"  Decision = {res1.decision} (Expected: BLOCK) -> {'PASS' if res1.decision == 'BLOCK' else 'FAIL'}")
    print(f"  Rule     = {res1.policy_rule_triggered}")
    assert res1.decision == "BLOCK", f"Expected BLOCK, got {res1.decision}"

    # Test Case 2: risk < 40 -> ALLOW
    res2 = engine.evaluate(final_risk=25.0, sensitivity_level="LOW", destination_risk="Internal")
    print(f"Test 2 (risk < 40: Risk=25):")
    print(f"  Decision = {res2.decision} (Expected: ALLOW) -> {'PASS' if res2.decision == 'ALLOW' else 'FAIL'}")
    assert res2.decision == "ALLOW", f"Expected ALLOW, got {res2.decision}"

    # Test Case 3: 40 <= risk < 70 -> MONITOR
    res3 = engine.evaluate(final_risk=55.0, sensitivity_level="MEDIUM", destination_risk="Internal")
    print(f"Test 3 (40 <= risk < 70: Risk=55):")
    print(f"  Decision = {res3.decision} (Expected: MONITOR) -> {'PASS' if res3.decision == 'MONITOR' else 'FAIL'}")
    assert res3.decision == "MONITOR", f"Expected MONITOR, got {res3.decision}"

    # Test Case 4: 70 <= risk <= 90 -> ALERT / APPROVAL
    res4 = engine.evaluate(final_risk=80.0, sensitivity_level="MEDIUM", destination_risk="Internal")
    print(f"Test 4 (70 <= risk <= 90: Risk=80):")
    print(f"  Decision = {res4.decision} (Expected: ALERT / APPROVAL) -> {'PASS' if res4.decision == 'ALERT / APPROVAL' else 'FAIL'}")
    assert res4.decision == "ALERT / APPROVAL", f"Expected ALERT / APPROVAL, got {res4.decision}"

    # Test Case 5: risk > 90 -> BLOCK
    res5 = engine.evaluate(final_risk=95.0, sensitivity_level="LOW", destination_risk="Internal")
    print(f"Test 5 (risk > 90: Risk=95):")
    print(f"  Decision = {res5.decision} (Expected: BLOCK) -> {'PASS' if res5.decision == 'BLOCK' else 'FAIL'}")
    assert res5.decision == "BLOCK", f"Expected BLOCK, got {res5.decision}"

    # Test Case 6: Dynamic threshold configuration update
    print("Test 6 (Configurable Threshold Updates):")
    engine.update_thresholds({
        "allow_threshold": 30.0,
        "monitor_threshold": 60.0,
        "alert_threshold": 80.0,
        "block_threshold": 80.0
    })
    res6 = engine.evaluate(final_risk=35.0, sensitivity_level="LOW", destination_risk="Internal")
    print(f"  Updated Allow=30 -> Risk=35 is now {res6.decision} (Expected: MONITOR) -> {'PASS' if res6.decision == 'MONITOR' else 'FAIL'}")
    assert res6.decision == "MONITOR", f"Expected MONITOR, got {res6.decision}"

    res7 = engine.evaluate(final_risk=85.0, sensitivity_level="LOW", destination_risk="Internal")
    print(f"  Updated Block=80 -> Risk=85 is now {res7.decision} (Expected: BLOCK) -> {'PASS' if res7.decision == 'BLOCK' else 'FAIL'}")
    assert res7.decision == "BLOCK", f"Expected BLOCK, got {res7.decision}"

    # Test Case 7: Return format inspection
    print("Test 7 (Return Format Inspection):")
    assert hasattr(res1, "decision"), "Missing 'decision' attribute"
    assert hasattr(res1, "reason"), "Missing 'reason' attribute"
    assert hasattr(res1, "risk"), "Missing 'risk' attribute"
    assert hasattr(res1, "policy_rule_triggered"), "Missing 'policy_rule_triggered' attribute"
    assert res1["decision"] == "BLOCK", "Missing dict-like access for 'decision'"
    print("  All 4 required return fields (decision, reason, risk, policy_rule_triggered) verified: PASS")

    print("=" * 60)
    print("ALL VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print(f"[*] {POLICY_OPTIMALITY_DISCLAIMER}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="LeakMind Phase 10: Policy Engine CLI & Evaluation Runner"
    )
    parser.add_argument("--risk", type=float, default=None, help="Final risk score (0.0 to 100.0)")
    parser.add_argument("--sensitivity", type=str, default="LOW", help="Sensitivity level (LOW, MEDIUM, HIGH, CRITICAL)")
    parser.add_argument("--destination", type=str, default="Internal", help="Destination (e.g. 'External Cloud', 'USB', 'Internal')")
    parser.add_argument("--after-hours", action="store_true", help="Flag indicating after-hours activity")
    parser.add_argument("--usb", action="store_true", help="Flag indicating USB removable storage vector")
    parser.add_argument("--user", type=str, default="ANALYST_USER", help="Target user id")
    parser.add_argument("--config", type=str, default="saved_models/policy/policy_config.json", help="Path to policy configuration file")
    parser.add_argument("--allow-threshold", type=float, default=None, help="Override allow threshold (default 40.0%%)")
    parser.add_argument("--monitor-threshold", type=float, default=None, help="Override monitor threshold (default 70.0%%)")
    parser.add_argument("--alert-threshold", type=float, default=None, help="Override alert threshold (default 90.0%%)")
    parser.add_argument("--block-threshold", type=float, default=None, help="Override block threshold (default 90.0%%)")
    parser.add_argument("--batch", action="store_true", help="Run batch evaluation over incident datasets")
    parser.add_argument("--test", action="store_true", help="Run automated policy verification test suite")

    args = parser.parse_args()

    engine = PolicyEngine(
        config_path=args.config if os.path.exists(args.config) else None
    )

    # Apply manual threshold overrides if provided
    overrides = {}
    if args.allow_threshold is not None:
        overrides["allow_threshold"] = args.allow_threshold
    if args.monitor_threshold is not None:
        overrides["monitor_threshold"] = args.monitor_threshold
    if args.alert_threshold is not None:
        overrides["alert_threshold"] = args.alert_threshold
    if args.block_threshold is not None:
        overrides["block_threshold"] = args.block_threshold

    if overrides:
        engine.update_thresholds(overrides)

    if args.test:
        run_verification_test_suite()
        return

    if args.batch:
        run_batch_evaluation(engine)
        return

    # If risk is specified or default run
    risk_val = args.risk if args.risk is not None else 94.0
    sens_val = args.sensitivity if args.risk is not None else "CRITICAL"
    dest_val = args.destination if args.risk is not None else "External Cloud"

    context = {
        "user": args.user,
        "is_after_hours": args.after_hours,
        "usb_activity": 1.0 if args.usb else 0.0
    }

    res = evaluate_single_incident(
        engine=engine,
        risk=risk_val,
        sensitivity=sens_val,
        destination=dest_val,
        context=context
    )
    print_incident_result(res)


if __name__ == "__main__":
    main()
