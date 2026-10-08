"""
Graph Module Facade
Integrates Provenance Knowledge Graph (DARPA TC) and Legacy Knowledge Graph components.
"""

from .provenance import ProvenanceKnowledgeGraph
from .intelligence.graph import LeakMindKnowledgeGraph
from .intelligence.attack_path import AttackPathAnalyzer

__all__ = [
    "ProvenanceKnowledgeGraph",
    "LeakMindKnowledgeGraph",
    "AttackPathAnalyzer"
]
