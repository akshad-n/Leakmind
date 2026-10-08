"""
Attack Path Analysis: Graph Traversal for Lateral Movement & Exfiltration
Identifies multi-hop paths from compromised accounts to crown-jewel assets.
"""

from typing import Any, Dict, List, Optional
import networkx as nx
from .graph import LeakMindKnowledgeGraph


class AttackPathAnalyzer:
    """
    Analyzes attack vectors, blast radius, and lateral movement paths
    connecting insider accounts to sensitive assets and egress targets.
    """

    def __init__(self, knowledge_graph: LeakMindKnowledgeGraph):
        self.kg = knowledge_graph

    def find_exfiltration_paths(self, start_user: str, max_depth: int = 4) -> List[Dict[str, Any]]:
        """
        Finds all paths from a user to any EgressTarget or RESTRICTED_SECRET resource.
        """
        G = self.kg.graph
        if start_user not in G:
            return []

        paths_found = []
        # Target nodes
        target_nodes = [
            n for n, d in G.nodes(data=True)
            if d.get("node_type") in ("EgressTarget", "Resource") and d.get("sensitivity") in ("RESTRICTED_SECRET", "CONFIDENTIAL") or d.get("node_type") == "EgressTarget"
        ]

        for target in target_nodes:
            try:
                for path in nx.all_simple_paths(G, source=start_user, target=target, cutoff=max_depth):
                    hop_details = []
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i+1]
                        edge_data = G.get_edge_data(u, v)
                        rel = "CONNECTED"
                        if edge_data:
                            # MultiDiGraph returns dict of keys
                            first_key = list(edge_data.keys())[0]
                            rel = edge_data[first_key].get("relationship", "CONNECTED")
                        hop_details.append(f"{u} --[{rel}]--> {v}")

                    paths_found.append({
                        "source": start_user,
                        "destination": target,
                        "path_length": len(path) - 1,
                        "path_nodes": path,
                        "hops": hop_details
                    })
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return paths_found

    def compute_blast_radius(self, user: str) -> Dict[str, Any]:
        """
        Computes the reachable assets and devices if this user account is abused.
        """
        G = self.kg.graph
        if user not in G:
            return {"reachable_nodes": 0, "accessible_resources": [], "devices": []}

        reachable = nx.descendants(G, user)
        resources = [
            n for n in reachable if G.nodes[n].get("node_type") == "Resource"
        ]
        devices = [
            n for n in reachable if G.nodes[n].get("node_type") == "Device"
        ]

        return {
            "reachable_nodes": len(reachable),
            "accessible_resources": resources,
            "devices": devices
        }
