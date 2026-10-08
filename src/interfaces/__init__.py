"""
LeakMind Architecture Interfaces
Provides modular abstract contracts for all 11 phases.
"""

from .dataset_interface import (
    BaseDatasetConnector,
    CERTDatasetConnector,
    SensitiveDataPIIConnector,
    DARPABigDataConnector,
    DatasetRegistry,
    DatasetStatus
)
from .behavior_interface import BaseBehaviorDetector
from .sensitivity_interface import BaseSensitivityDetector, SensitivityLevel
from .provenance_interface import BaseProvenanceGraph
from .temporal_interface import BaseTemporalCorrelator
from .fusion_interface import BaseRiskFusion
from .explainer_interface import BaseExplainer
from .policy_interface import BasePolicyEngine, PolicyDecision

__all__ = [
    "BaseDatasetConnector",
    "CERTDatasetConnector",
    "SensitiveDataPIIConnector",
    "DARPABigDataConnector",
    "DatasetRegistry",
    "DatasetStatus",
    "BaseBehaviorDetector",
    "BaseSensitivityDetector",
    "SensitivityLevel",
    "BaseProvenanceGraph",
    "BaseTemporalCorrelator",
    "BaseRiskFusion",
    "BaseExplainer",
    "BasePolicyEngine",
    "PolicyDecision"
]
