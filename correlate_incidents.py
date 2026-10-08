"""
LeakMind Phase 7: Standalone Incident Correlation Inference Tool
Loads saved explainable temporal rules (zero retraining required) and correlates
fragmented events into consolidated leakage incidents.

Usage:
  python correlate_incidents.py --input data/raw/darpa/darpa_tc_events.csv
  python correlate_incidents.py --input data/processed/r42_all_parsed_events.csv --window 120
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.temporal import TemporalLeakageCorrelator
from src.utils.logger import get_logger

logger = get_logger("leakmind.correlate_incidents")


def correlate_events_file(
    input_file: str,
    rules_file: str = "saved_models/temporal/correlation_rules.json",
    window_minutes: int = 120,
    threshold: float = 60.0,
    output_file: str = None
) -> List[Dict[str, Any]]:
    """
    Ingests event file, loads saved explainable rules, and detects consolidated leakage incidents.
    """
    print("=" * 80)
    print(" LEAKMIND: TEMPORAL & GRAPH-BASED LEAKAGE INCIDENT CORRELATION")
    print("=" * 80)

    # 1. Load Correlator
    if os.path.exists(rules_file):
        print(f" [+] Loading correlation rules from: {rules_file}")
        correlator = TemporalLeakageCorrelator.load_rules(rules_file)
    else:
        print(f" [!] Rules file not found at {rules_file}. Using default explainable rules.")
        correlator = TemporalLeakageCorrelator()

    correlator.session_window_minutes = float(window_minutes)
    correlator.alert_score_threshold = float(threshold)

    # 2. Ingest Data
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    print(f" [+] Ingesting event stream from: {input_file}")
    df = pd.read_csv(input_file)
    print(f"     Loaded {len(df):,} events across {df.shape[1]} columns")

    # 3. Detect Consolidated Incidents
    print(f" [+] Running sliding correlation window ({window_minutes} mins, threshold >= {threshold})...")
    incidents = correlator.detect_incidents(df, window_minutes=window_minutes)
    flagged = [i for i in incidents if i["leakage_chain_score"] >= threshold]

    print(f" [+] Analysis Complete: {len(flagged)} consolidated leakage incident(s) detected.\n")

    if not flagged:
        print(" [OK] No anomalous leakage chains detected. All event streams within normal limits.")
    else:
        print("=" * 80)
        print(" CONSOLIDATED LEAKAGE INCIDENTS:")
        print("=" * 80)
        for idx, inc in enumerate(flagged, 1):
            print(f"\n[INCIDENT #{idx}] ID: {inc['incident_id']}")
            print(f"  User / Entity     : {inc['user']}")
            print(f"  Risk Chain Score  : {inc['leakage_chain_score']:.1f} / 100.0 [{inc['severity_tier']}]")
            print(f"  Rule Triggered    : {inc['rule_name']} ({inc['rule_id']})")
            print(f"  Timeline          : {inc['incident_start']} -> {inc['incident_end']} ({inc['time_span_minutes']} min)")
            print(f"  Causal Attack Path: {inc['leakage_path']}")
            print(f"  Events Correlated : {len(inc['incident_events'])} events")
            print(f"  Reasoning         : {inc['explanation']}")
            print(f"  Points Breakdown  : {inc['score_breakdown']}")

    # 4. Optional Export
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(flagged, f, indent=2)
        print(f"\n [+] Exported {len(flagged)} incidents to: {output_file}")

    print("=" * 80)
    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="LeakMind Phase 7: Temporal and Graph-Based Incident Correlator"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="data/raw/darpa/darpa_tc_events.csv",
        help="Path to CSV containing security event logs"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="saved_models/temporal/correlation_rules.json",
        help="Path to saved rules configuration"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=120,
        help="Correlation sliding window in minutes"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=60.0,
        help="Minimum leakage_chain_score for raising an incident alert"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to export detected incidents JSON"
    )

    args = parser.parse_args()
    correlate_events_file(
        input_file=args.input,
        rules_file=args.config,
        window_minutes=args.window,
        threshold=args.threshold,
        output_file=args.output
    )


if __name__ == "__main__":
    main()
