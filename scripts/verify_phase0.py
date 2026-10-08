"""
LeakMind Phase 0 Verification Script
Validates project setup, configuration, logging, dataset discovery,
model portability contracts, and modular interfaces.
"""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.config import config, ConfigManager
from src.utils.logger import get_logger
from src.utils.model_registry import ModelRegistry, save_model, load_model
from src.interfaces import (
    DatasetRegistry,
    DatasetStatus,
    BaseBehaviorDetector,
    BaseSensitivityDetector,
    BaseProvenanceGraph,
    BaseTemporalCorrelator,
    BaseRiskFusion,
    BaseExplainer,
    BasePolicyEngine,
    PolicyDecision
)

logger = get_logger("leakmind.verify_phase0")

def run_phase0_verification():
    print("=" * 70)
    print("LEAKMIND PHASE 0: SETUP & ARCHITECTURE VERIFICATION")
    print("=" * 70)

    # 1. Config Manager Verification
    print("\n[CHECK 1] Centralized Configuration System...")
    assert config.project_title is not None, "Failed to retrieve project title"
    print(f"  [+] Project Title: '{config.project_title}'")
    print(f"  [+] Project Root: '{config.project_root}'")
    policy_th = config.policy_thresholds
    print(f"  [+] Active Policy Thresholds: ALLOW<{policy_th['allow_max']}, MONITOR<{policy_th['monitor_max']}, ALERT<{policy_th['alert_max']}, BLOCK>{policy_th['block_min']}")
    print("  -> Configuration System: OK")

    # 2. Centralized Logger Verification
    print("\n[CHECK 2] Centralized Logging System...")
    logger.info("Verifying logger execution for Phase 0.")
    log_file = PROJECT_ROOT / "logs" / "leakmind.log"
    assert log_file.exists(), f"Log file not created at {log_file}"
    print(f"  [+] Log file confirmed at: {log_file} ({log_file.stat().st_size} bytes)")
    print("  -> Logging System: OK")

    # 3. Dataset Discovery & Graceful Degradation Check
    print("\n[CHECK 3] Dataset Ingestion & Discovery Registry...")
    registry = DatasetRegistry()
    ds_status = registry.discover_all()
    
    cert_st = ds_status["cert"]["status"]
    pii_st = ds_status["sensitive_data_pii"]["status"]
    darpa_st = ds_status["darpa_tc"]["status"]

    print(f"  [+] CERT Dataset (Primary)   : [{cert_st}] -> Path: {ds_status['cert']['path']}")
    if "files" in ds_status["cert"]:
        for fn, fmeta in ds_status["cert"]["files"].items():
            print(f"      - {fn}: {fmeta.get('size_mb', 0)} MB")
            
    print(f"  [+] Sensitive PII Dataset     : [{pii_st}] (Gracefully bypassed for Phase 5)")
    print(f"  [+] DARPA Provenance Dataset : [{darpa_st}] (Gracefully bypassed for Phase 6)")
    
    assert cert_st in (DatasetStatus.AVAILABLE.value, DatasetStatus.PARTIAL.value), "CERT dataset should be accessible on disk"
    assert pii_st == DatasetStatus.NOT_AVAILABLE_YET.value, "PII dataset should be marked NOT_AVAILABLE_YET"
    assert darpa_st == DatasetStatus.NOT_AVAILABLE_YET.value, "DARPA dataset should be marked NOT_AVAILABLE_YET"
    print("  -> Dataset Registry & Graceful Degradation: OK")

    # 4. Model Portability Directories & Registry Verification
    print("\n[CHECK 4] Cross-Laptop Model Portability Registry...")
    behavior_dir = config.get_model_save_dir("behavior")
    sensitivity_dir = config.get_model_save_dir("sensitivity")
    risk_dir = config.get_model_save_dir("risk")

    print(f"  [+] Target Portable Directories:")
    print(f"      - Behavior   : {behavior_dir}")
    print(f"      - Sensitivity: {sensitivity_dir}")
    print(f"      - Risk       : {risk_dir}")

    # Test dummy save and load cycle to prove portability contract
    from sklearn.preprocessing import StandardScaler
    from sklearn.dummy import DummyClassifier

    dummy_model = DummyClassifier(strategy="most_frequent")
    dummy_model.fit([[0, 0], [1, 1]], [0, 1])
    dummy_scaler = StandardScaler()
    dummy_scaler.fit([[0, 0], [1, 1]])

    test_bundle_dir = PROJECT_ROOT / "saved_models" / "_test_bundle"
    saved_paths = ModelRegistry.save_model(
        model=dummy_model,
        preprocessor=dummy_scaler,
        feature_columns=["feat_1", "feat_2"],
        config={"test_param": 42},
        model_dir=str(test_bundle_dir),
        model_filename="test_model.joblib"
    )

    loaded_m, loaded_p, loaded_feats, loaded_conf = ModelRegistry.load_model(
        model_dir=str(test_bundle_dir),
        model_filename="test_model.joblib"
    )

    assert loaded_feats == ["feat_1", "feat_2"], "Loaded features do not match saved features"
    assert loaded_conf.get("test_param") == 42, "Loaded configuration mismatch"
    
    # Cleanup test bundle
    import shutil
    shutil.rmtree(test_bundle_dir, ignore_errors=True)
    print("  [+] Portability Contract Verified: Model + Preprocessor + Schema + Config packaged cleanly")
    print("  -> Model Registry: OK")

    # 5. Future Phases Modular Interface Contracts
    print("\n[CHECK 5] Architecture Interface Contracts...")
    interfaces = [
        ("Phase 2 Behavior Interface", BaseBehaviorDetector),
        ("Phase 5 Sensitivity Interface", BaseSensitivityDetector),
        ("Phase 6 Provenance Graph Interface", BaseProvenanceGraph),
        ("Phase 7 Temporal Interface", BaseTemporalCorrelator),
        ("Phase 8 Risk Fusion Interface", BaseRiskFusion),
        ("Phase 9 Explainability Interface", BaseExplainer),
        ("Phase 10 Policy Interface", BasePolicyEngine),
    ]

    for name, iface in interfaces:
        print(f"  [+] {name}: Loaded abstract contract ({iface.__name__})")

    print("  -> Modular Architecture Interfaces: OK")

    print("\n" + "=" * 70)
    print("PHASE 0 SETUP VERIFIED SUCCESSFULLY! READY FOR PHASE 1.")
    print("=" * 70)

if __name__ == "__main__":
    run_phase0_verification()
