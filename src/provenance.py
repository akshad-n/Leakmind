"""
LeakMind Phase 6: Provenance Knowledge Graph Module (DARPA Transparent Computing)
Constructs heterogeneous knowledge graphs mapping system-level and data-level provenance:
- Nodes: User, Device, File, Process, USB, Browser, Cloud, IP, Time
- Relationships: LOGGED_INTO, SPAWNED, READ_FILE, WROTE_FILE, CONNECTED_USB, 
                 TRANSFERRED_TO_USB, LAUNCHED_BROWSER, UPLOADED_TO_CLOUD, CONNECTED_IP

Extracts graph-derived features (strictly classical graph traversal - NO GNN):
- number of connected entities
- suspicious paths
- external destinations
- USB-to-file relationships
- file-to-cloud relationships
- graph_risk (0.0 to 100.0)

Provides dual backend:
1. Native Neo4j Cypher graph database (when connection configured/running)
2. In-memory NetworkX provenance graph engine (zero-dependency standalone fallback)

Operates completely independently from CERT.
"""

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import networkx as nx
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.interfaces.provenance_interface import BaseProvenanceGraph
from src.utils.logger import get_logger

logger = get_logger("leakmind.provenance")


class ProvenanceKnowledgeGraph(BaseProvenanceGraph):
    """
    Provenance Knowledge Graph engine conforming to BaseProvenanceGraph.
    Tracks causality chains from User through Devices, Processes, and Files to Egress Channels.
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None
    ):
        self.graph = nx.MultiDiGraph()
        self.neo4j_driver = None
        self.use_neo4j = False

        # Attempt Neo4j driver connection if credentials provided
        if neo4j_uri:
            try:
                from neo4j import GraphDatabase
                self.neo4j_driver = GraphDatabase.driver(
                    neo4j_uri,
                    auth=(neo4j_user or "neo4j", neo4j_password or "password")
                )
                self.neo4j_driver.verify_connectivity()
                self.use_neo4j = True
                logger.info(f"Connected to Neo4j database at {neo4j_uri}")
            except Exception as e:
                logger.warning(f"Neo4j unavailable ({e}). Operating in resilient in-memory mode.")
                self.use_neo4j = False

    def is_available(self) -> bool:
        """Module is active and ready."""
        return True

    def clear(self):
        """Clears graph nodes and edges."""
        self.graph.clear()
        if self.use_neo4j and self.neo4j_driver:
            try:
                with self.neo4j_driver.session() as session:
                    session.run("MATCH (n) DETACH DELETE n")
            except Exception as e:
                logger.warning(f"Neo4j clear error: {e}")

    def add_entity(
        self,
        entity_id: str,
        entity_type: str,
        properties: Optional[Dict[str, Any]] = None
    ):
        """Adds a typed entity node to the knowledge graph."""
        props = properties or {}
        props["entity_type"] = entity_type
        self.graph.add_node(entity_id, **props)

        if self.use_neo4j and self.neo4j_driver:
            query = f"MERGE (n:{entity_type} {{id: $id}}) SET n += $props"
            try:
                with self.neo4j_driver.session() as session:
                    session.run(query, id=entity_id, props=props)
            except Exception as e:
                logger.warning(f"Neo4j add_entity error: {e}")

    def add_provenance_relation(
        self,
        source_id: str,
        source_type: str,
        relationship: str,
        target_id: str,
        target_type: str,
        timestamp: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Links two entities with a directed provenance relationship."""
        # Ensure nodes exist
        if source_id not in self.graph:
            self.add_entity(source_id, source_type)
        if target_id not in self.graph:
            self.add_entity(target_id, target_type)

        props = metadata or {}
        props["relationship"] = relationship
        props["timestamp"] = timestamp

        self.graph.add_edge(source_id, target_id, **props)

        if self.use_neo4j and self.neo4j_driver:
            cypher = f"""
            MERGE (a:{source_type} {{id: $src}})
            MERGE (b:{target_type} {{id: $dst}})
            MERGE (a)-[r:{relationship} {{timestamp: $ts}}]->(b)
            SET r += $props
            """
            try:
                with self.neo4j_driver.session() as session:
                    session.run(cypher, src=source_id, dst=target_id, ts=timestamp, props=props)
            except Exception as e:
                logger.warning(f"Neo4j relationship error: {e}")

    def ingest_provenance_event(
        self,
        subject: str,
        relation: str,
        target: str,
        timestamp: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Conforms to BaseProvenanceGraph contract."""
        meta = metadata or {}
        src_type = meta.get("src_type", "Entity")
        dst_type = meta.get("dst_type", "Entity")
        self.add_provenance_relation(
            source_id=subject,
            source_type=src_type,
            relationship=relation,
            target_id=target,
            target_type=dst_type,
            timestamp=timestamp,
            metadata=meta
        )
        return True

    def ingest_dataframe(self, df: pd.DataFrame) -> int:
        """
        Parses DARPA TC events dataframe and constructs the complete knowledge graph.
        """
        count = 0
        for _, row in df.iterrows():
            src_id = str(row["src_entity_id"])
            src_type = str(row["src_entity_type"])
            rel = str(row["relationship"])
            dst_id = str(row["dst_entity_id"])
            dst_type = str(row["dst_entity_type"])
            ts = str(row.get("timestamp", ""))

            meta = {
                "user": str(row.get("user", "")),
                "device": str(row.get("device", "")),
                "event_type": str(row.get("event_type", "")),
                "file_path": str(row.get("file_path", "")),
                "ip_address": str(row.get("ip_address", "")),
                "cloud_destination": str(row.get("cloud_destination", "")),
                "usb_device_id": str(row.get("usb_device_id", "")),
                "is_suspicious": int(row.get("is_suspicious", 0)),
                "chain_id": str(row.get("provenance_chain_id", ""))
            }

            self.add_provenance_relation(
                source_id=src_id,
                source_type=src_type,
                relationship=rel,
                target_id=dst_id,
                target_type=dst_type,
                timestamp=ts,
                metadata=meta
            )
            count += 1
        logger.info(f"Ingested {count} provenance events into Knowledge Graph ({len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges).")
        return count

    def find_suspicious_exfiltration_paths(
        self,
        user_id: str,
        max_hops: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Traverses provenance graph to find multi-hop paths from user to egress channels:
        Egress nodes: USB, Cloud, External IP.
        """
        if user_id not in self.graph:
            return []

        egress_types = {"USB", "Cloud", "IP"}
        paths_found = []

        # Find candidate target nodes
        target_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("entity_type") in egress_types
        ]

        for target in target_nodes:
            try:
                for path in nx.all_simple_paths(self.graph, source=user_id, target=target, cutoff=max_hops):
                    hop_chain = []
                    has_file = False
                    has_usb = False
                    has_cloud = False

                    for i in range(len(path) - 1):
                        u, v = path[i], path[i+1]
                        edge_data = self.graph.get_edge_data(u, v)
                        rel = "RELATED"
                        if edge_data:
                            first_k = list(edge_data.keys())[0]
                            rel = edge_data[first_k].get("relationship", "RELATED")
                        hop_chain.append(f"{u} -[:{rel}]-> {v}")

                        if self.graph.nodes[u].get("entity_type") == "File" or self.graph.nodes[v].get("entity_type") == "File":
                            has_file = True
                        if self.graph.nodes[v].get("entity_type") == "USB":
                            has_usb = True
                        if self.graph.nodes[v].get("entity_type") == "Cloud":
                            has_cloud = True

                    paths_found.append({
                        "user": user_id,
                        "target": target,
                        "target_type": self.graph.nodes[target].get("entity_type", "Egress"),
                        "hops_count": len(path) - 1,
                        "path_nodes": path,
                        "hop_chain": hop_chain,
                        "involves_file_and_usb": (has_file and has_usb),
                        "involves_file_and_cloud": (has_file and has_cloud)
                    })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return paths_found

    def extract_graph_features(self, user_id: str) -> Dict[str, Any]:
        """
        Extracts structural, graph-derived provenance features:
        - number of connected entities
        - suspicious paths
        - external destinations
        - USB-to-file relationships
        - file-to-cloud relationships
        - graph_risk (0.0 to 100.0)
        """
        if user_id not in self.graph:
            return {
                "user": user_id,
                "connected_entities_count": 0,
                "suspicious_paths_count": 0,
                "external_destinations_count": 0,
                "usb_to_file_count": 0,
                "file_to_cloud_count": 0,
                "graph_risk": 0.0,
                "risk_tier": "LOW",
                "attack_paths": []
            }

        # 1. Connected Entities (Transitive Reachability Neighborhood)
        reachable_nodes = nx.descendants(self.graph, user_id)
        reachable_nodes.add(user_id)
        connected_entities_count = len(reachable_nodes)

        # 2. Suspicious Exfiltration Paths
        paths = self.find_suspicious_exfiltration_paths(user_id)
        suspicious_paths_count = len(paths)

        # 3. External Destinations (Reachable Cloud & External IPs)
        external_destinations = set()
        for n in reachable_nodes:
            t = self.graph.nodes[n].get("entity_type")
            if t in ("Cloud", "IP"):
                # Exclude internal loopback/syslog
                if not n.startswith("10.") and not n.startswith("192.168."):
                    external_destinations.add(n)
        external_destinations_count = len(external_destinations)

        # 4. USB-to-file Relationships
        usb_to_file_count = 0
        file_to_cloud_count = 0

        for u, v, data in self.graph.edges(data=True):
            if u in reachable_nodes and v in reachable_nodes:
                rel = data.get("relationship", "")
                if rel == "TRANSFERRED_TO_USB":
                    usb_to_file_count += 1
                elif rel == "UPLOADED_TO_CLOUD":
                    file_to_cloud_count += 1

        # 5. Composite Graph Risk Scoring (0.0 to 100.0)
        # Structural exfiltration weighting:
        # USB exfiltration link: +35.0
        # Cloud exfiltration link: +35.0
        # Multi-hop exfiltration path: +15.0 per path
        # External untrusted destination: +15.0 per destination
        # Connected blast radius factor: +0.5 per node
        risk_calc = 0.0
        risk_calc += usb_to_file_count * 35.0
        risk_calc += file_to_cloud_count * 35.0
        risk_calc += min(30.0, suspicious_paths_count * 15.0)
        risk_calc += min(20.0, external_destinations_count * 10.0)
        risk_calc += min(10.0, connected_entities_count * 1.5)

        graph_risk = round(float(np.clip(risk_calc, 0.0, 100.0)), 2)

        # Determine risk tier
        if graph_risk >= 80.0:
            risk_tier = "CRITICAL"
        elif graph_risk >= 60.0:
            risk_tier = "HIGH"
        elif graph_risk >= 30.0:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        return {
            "user": user_id,
            "connected_entities_count": connected_entities_count,
            "suspicious_paths_count": suspicious_paths_count,
            "external_destinations_count": external_destinations_count,
            "usb_to_file_count": usb_to_file_count,
            "file_to_cloud_count": file_to_cloud_count,
            "graph_risk": graph_risk,
            "risk_tier": risk_tier,
            "attack_paths": [p["hop_chain"] for p in paths]
        }

    def evaluate_graph_risk(
        self,
        user: str,
        target_resource: Optional[str] = None
    ) -> Dict[str, Any]:
        """Conforms to BaseProvenanceGraph contract."""
        features = self.extract_graph_features(user)
        return {
            "graph_risk": features["graph_risk"],
            "attack_path": features["attack_paths"],
            "blast_radius": features["connected_entities_count"],
            "risk_tier": features["risk_tier"],
            "provenance_features": features
        }


__all__ = ["ProvenanceKnowledgeGraph"]
