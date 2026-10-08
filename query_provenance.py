"""
LeakMind Phase 6: Provenance Graph Query Tool
Interactive and CLI tool to query the Provenance Knowledge Graph for a given user or resource.
Outputs:
- graph_risk (0.0 to 100.0)
- connected_entities
- suspicious_paths
- USB-to-file relationships
- file-to-cloud relationships
- attack paths / causality hops

Operates completely independently from CERT.
"""

import argparse
import json
import os
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.provenance import ProvenanceKnowledgeGraph
from src.utils.logger import get_logger

logger = get_logger("leakmind.query_provenance")


def main():
    parser = argparse.ArgumentParser(description="LeakMind DARPA TC Provenance Graph Query Engine")
    parser.add_argument("--user", type=str, default=None, help="User ID to evaluate (e.g. bob_finance, charlie_admin, eve_insider)")
    parser.add_argument("--input", type=str, default="data/raw/darpa/darpa_tc_events.csv", help="Provenance events CSV")
    parser.add_argument("--neo4j-uri", type=str, default=None, help="Optional Neo4j URI (e.g. bolt://localhost:7687)")
    parser.add_argument("--output", type=str, default=None, help="Optional output JSON path")
    args = parser.parse_args()

    print("=" * 75)
    print("LEAKMIND PROVENANCE GRAPH QUERY ENGINE (NO GNN - CLASSICAL TRAVERSAL)")
    print("=" * 75)

    if not os.path.exists(args.input):
        print(f"[!] Provenance events file not found: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)
    pkg = ProvenanceKnowledgeGraph(neo4j_uri=args.neo4j_uri)
    pkg.ingest_dataframe(df)

    users_to_query = [args.user] if args.user else df["user"].unique().tolist()

    all_results = []
    for u in users_to_query:
        feats = pkg.extract_graph_features(u)
        all_results.append(feats)

        print(f"\n[+] User Investigation: {feats['user']}")
        print(f"    Graph Risk Score          : {feats['graph_risk']:.1f} / 100.0")
        print(f"    Risk Classification Tier  : {feats['risk_tier']}")
        print(f"    Connected Entities Count  : {feats['connected_entities_count']}")
        print(f"    Suspicious Paths Count    : {feats['suspicious_paths_count']}")
        print(f"    External Destinations     : {feats['external_destinations_count']}")
        print(f"    USB-to-File Relationships : {feats['usb_to_file_count']}")
        print(f"    File-to-Cloud Links       : {feats['file_to_cloud_count']}")

        if feats["attack_paths"]:
            print("    [!] Traversed Attack Paths:")
            for idx, p in enumerate(feats["attack_paths"], 1):
                print(f"        #{idx}: {' -> '.join(p)}")
        else:
            print("    [✓] No exfiltration paths detected. Activity consistent with benign baseline.")

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nSaved query output to: {out_p}")

    print("=" * 75)


if __name__ == "__main__":
    main()
