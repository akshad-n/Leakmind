"""
Provenance Knowledge Graph Interface (Phase 6)
Defines abstract contract for Neo4j / Graph-based provenance reconstruction.
Maps: User -> Sensitive File -> USB -> Browser -> External Cloud.
Output: graph_risk (0–100).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseProvenanceGraph(ABC):
    """
    Abstract interface for system and data provenance graph tracking.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """Indicates whether Neo4j / DARPA dataset is connected."""
        pass

    @abstractmethod
    def ingest_provenance_event(
        self,
        subject: str,
        relation: str,
        target: str,
        timestamp: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Ingests provenance triplet into knowledge graph."""
        pass

    @abstractmethod
    def evaluate_graph_risk(
        self,
        user: str,
        target_resource: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculates graph structural risk and multi-hop exfiltration paths.
        Returns:
            graph_risk: float 0.0 to 100.0
            attack_path: List of traversed nodes and relations
            blast_radius: Reachable sensitive nodes count
        """
        pass
