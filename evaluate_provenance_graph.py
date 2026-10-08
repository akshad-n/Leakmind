"""
LeakMind Phase 6: Provenance Graph Evaluation & Feature Extraction
Ingests DARPA Transparent Computing provenance events, constructs the knowledge graph,
extracts structural provenance features (connected entities, suspicious paths,
external destinations, USB-to-file links, file-to-cloud links),
calculates graph_risk (0-100), and exports provenance artifacts.

Strict constraint: Classical graph algorithms only - NO GNN.
Operates completely independently from CERT.
"""

import json
import os
import sys
import time
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.provenance import ProvenanceKnowledgeGraph
from src.utils.logger import get_logger

logger = get_logger("leakmind.evaluate_provenance")


def evaluate_darpa_provenance(
    data_path: str = "data/raw/darpa/darpa_tc_events.csv",
    save_dir: str = "saved_models/provenance",
    reports_dir: str = "reports"
):
    print("=" * 75)
    print("LEAKMIND PHASE 6: DARPA TC PROVENANCE KNOWLEDGE GRAPH EVALUATION")
    print("=" * 75)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    rep_path = Path(reports_dir)
    rep_path.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Raw DARPA TC Events
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"DARPA TC dataset not found at: {data_path}")

    print(f"[1/4] Ingesting DARPA TC events from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"      Loaded: {len(df):,} events across {df.shape[1]} columns")

    # 2. Construct Knowledge Graph
    print("\n[2/4] Constructing Provenance Knowledge Graph...")
    pkg = ProvenanceKnowledgeGraph()
    ingested_count = pkg.ingest_dataframe(df)

    print(f"      Graph Nodes: {len(pkg.graph.nodes):,} entities")
    print(f"      Graph Edges: {len(pkg.graph.edges):,} relationships")

    # Group entity types
    entity_types = {}
    for n, d in pkg.graph.nodes(data=True):
        t = d.get("entity_type", "Unknown")
        entity_types[t] = entity_types.get(t, 0) + 1
    print(f"      Entity Breakdown: {entity_types}")

    # 3. Query Graph-Derived Features per User
    print("\n[3/4] Extracting Graph-Derived Features & Computing graph_risk...")
    unique_users = df["user"].unique().tolist()

    results = []
    print("\n" + "-" * 75)
    print(f"{'User':16s} {'Connected':10s} {'SusPaths':9s} {'ExtDest':8s} {'USB->File':10s} {'File->Cloud':12s} {'Risk':8s} {'Tier':8s}")
    print("-" * 75)

    for u in unique_users:
        feats = pkg.extract_graph_features(u)
        results.append(feats)
        print(
            f"{feats['user']:16s} "
            f"{feats['connected_entities_count']:10d} "
            f"{feats['suspicious_paths_count']:9d} "
            f"{feats['external_destinations_count']:8d} "
            f"{feats['usb_to_file_count']:10d} "
            f"{feats['file_to_cloud_count']:12d} "
            f"{feats['graph_risk']:6.1f}%  "
            f"{feats['risk_tier']:8s}"
        )

    # Detailed path traces for exfiltrating users
    print("\n" + "=" * 75)
    print("RECONSTRUCTED MULTI-HOP ATTACK & EXFILTRATION PATHS:")
    print("=" * 75)
    for feats in results:
        if feats["attack_paths"]:
            print(f"\n[!] User: {feats['user']} (Risk: {feats['graph_risk']}%, Tier: {feats['risk_tier']})")
            for idx, chain in enumerate(feats["attack_paths"], 1):
                print(f"    Path #{idx}: {' -> '.join(chain)}")

    # 4. Export Artifacts and Report
    print("\n[4/4] Exporting Provenance Graph Artifacts...")
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "graph_nodes": len(pkg.graph.nodes),
        "graph_edges": len(pkg.graph.edges),
        "entity_types": entity_types,
        "users_evaluated": results
    }

    report_file1 = save_path / "provenance_graph_report.json"
    report_file2 = rep_path / "provenance_graph_report.json"

    with open(report_file1, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    with open(report_file2, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Export graph config
    graph_conf = {
        "engine": "ProvenanceKnowledgeGraph",
        "neo4j_supported": True,
        "gnn_used": False,
        "supported_entities": ["User", "Device", "File", "Process", "USB", "Browser", "Cloud", "IP", "Time"],
        "graph_features": [
            "connected_entities_count",
            "suspicious_paths_count",
            "external_destinations_count",
            "usb_to_file_count",
            "file_to_cloud_count",
            "graph_risk"
        ]
    }
    with open(save_path / "graph_config.json", "w", encoding="utf-8") as f:
        json.dump(graph_conf, f, indent=2)

    print(f"  [+] Saved report to: {report_file1}")
    print(f"  [+] Saved report to: {report_file2}")
    print(f"  [+] Saved config to: {save_path / 'graph_config.json'}")
    print("=" * 75)
    print("PHASE 6 PROVENANCE GRAPH EVALUATION COMPLETE!")
    print("=" * 75)


if __name__ == "__main__":
    evaluate_darpa_provenance()
