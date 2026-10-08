"""
Entity Knowledge Graph for Multi-Modal Threat Correlation
Builds and maintains relationships between Users, PCs, Files, External Cloud/IPs, and AI Services.
"""

from typing import Any, Dict, List, Optional
import networkx as nx


class LeakMindKnowledgeGraph:
    """
    Heterogeneous Security Knowledge Graph mapping interactions:
    User -> Host (PC) -> Resource (File/Database) -> Egress (USB/Cloud/AI)
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def add_user(self, user_id: str, department: str = "General", risk_tier: str = "Standard"):
        self.graph.add_node(
            user_id,
            node_type="User",
            department=department,
            risk_tier=risk_tier
        )

    def add_device(self, pc_id: str, ip: str = "10.0.0.1"):
        self.graph.add_node(
            pc_id,
            node_type="Device",
            ip=ip
        )

    def add_resource(self, resource_id: str, sensitivity: str = "INTERNAL"):
        self.graph.add_node(
            resource_id,
            node_type="Resource",
            sensitivity=sensitivity
        )

    def add_egress_target(self, target_id: str, target_type: str = "Cloud"):
        self.graph.add_node(
            target_id,
            node_type="EgressTarget",
            target_type=target_type
        )

    def link(self, source: str, target: str, relationship: str, timestamp: str = "", metadata: Optional[dict] = None):
        self.graph.add_edge(
            source,
            target,
            relationship=relationship,
            timestamp=timestamp,
            **(metadata or {})
        )

    def get_user_subgraph(self, user_id: str) -> Dict[str, Any]:
        """Extracts ego-network of a specific user for visualization."""
        if user_id not in self.graph:
            return {"nodes": [], "edges": []}

        subgraph_nodes = set([user_id])
        # Successors and predecessors
        subgraph_nodes.update(self.graph.successors(user_id))
        subgraph_nodes.update(self.graph.predecessors(user_id))

        nodes_data = []
        for n in subgraph_nodes:
            d = dict(self.graph.nodes[n])
            d["id"] = n
            nodes_data.append(d)

        edges_data = []
        for u, v, k, d in self.graph.edges(subgraph_nodes, keys=True, data=True):
            if u in subgraph_nodes and v in subgraph_nodes:
                edges_data.append({
                    "from": u,
                    "to": v,
                    "relationship": d.get("relationship", "CONNECTED"),
                    "details": {k: v for k, v in d.items() if k != "relationship"}
                })

        return {"nodes": nodes_data, "edges": edges_data}

    def compute_centrality(self) -> Dict[str, float]:
        """Calculates degree centrality to identify highly connected/pivoting nodes."""
        if len(self.graph) == 0:
            return {}
        return nx.degree_centrality(self.graph)
