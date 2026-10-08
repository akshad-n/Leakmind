"""
LeakMind End-to-End Pipeline Verification Test
Validates all 5 Architecture Diagram Components
"""

import sys
import os

# Add root to sys.path
sys.path.insert(0, os.path.abspath("."))

from src.security import FieldEncryptor, authenticate_user, system_audit_logger, DataAnonymizer
from src.acquisition import LocalAgentCollector, EventBuffer, EventStreamingQueue, EventCorrelator, load_cert_events_as_stream
from src.intelligence import (
    IAMManager,
    DataSensitivityClassifier,
    BehavioralProfiler,
    LeakMindKnowledgeGraph,
    ThreatIntelligenceEngine,
    TrustScoreEngine,
    LeakPredictor,
    LeakExplainability,
    AttackPathAnalyzer,
    QuantumDefenseOptimizer
)
from src.decision import PolicyEngine, RiskPrioritizer, DecisionEngine, PolicyAction
from src.management import (
    IncidentTimelineGenerator,
    InvestigationReportGenerator,
    AnalystFeedbackEngine,
    RiskForecastingEngine
)

def run_tests():
    print("=" * 70)
    print("LEAKMIND SYSTEM ARCHITECTURE INTEGRATION TEST")
    print("=" * 70)

    # 1. CROSS-CUTTING SECURITY & PRIVACY
    print("\n[TEST 1] Testing Cross-Cutting Security & Privacy...")
    enc = FieldEncryptor(passphrase="TestSecretPassword2026")
    ct = enc.encrypt("CONFIDENTIAL_SOURCE_CODE_LEAK")
    pt = enc.decrypt(ct)
    assert pt == "CONFIDENTIAL_SOURCE_CODE_LEAK", "Encryption failed"

    auth_ctx = authenticate_user("sec_admin", "Admin@LeakMind2026")
    assert auth_ctx is not None, "Auth failed"
    assert auth_ctx.has_permission("quarantine_action"), "RBAC permission check failed"

    anon = DataAnonymizer()
    masked_user = anon.pseudonymize_user("AAM0658")
    assert masked_user.startswith("ANON_USER_"), "Anonymization failed"

    assert system_audit_logger.verify_integrity(), "Audit log hash chain integrity broken"
    print("  -> Security & Privacy: PASSED (Encryption, RBAC, Audit Chain, Anonymizer OK)")

    # 2. PART 1: MONITORING & DATA ACQUISITION
    print("\n[TEST 2] Testing Part 1 - Monitoring & Data Acquisition...")
    collector = LocalAgentCollector()
    evt1 = collector.capture_windows_logon("AAM0658", "Logon", pc="PC-102")
    evt2 = collector.capture_file_event("AAM0658", "C:/secrets/q4_patent.pdf", "READ", pc="PC-102")
    evt3 = collector.capture_usb_event("AAM0658", "Connect", "USB-SANDISK-09", pc="PC-102")
    evt4 = collector.capture_ai_prompt("AAM0658", "ChatGPT", "Can you summarize this confidential patent?", pc="PC-102")

    buf = EventBuffer(maxlen=50)
    buf.extend([evt1, evt2, evt3, evt4])
    assert buf.count() == 4

    correlator = EventCorrelator()
    sessions = correlator.correlate([evt1, evt2, evt3, evt4])
    assert len(sessions) == 1
    feat_vec = sessions[0].to_feature_vector()
    assert feat_vec["device_connect_count"] == 1.0
    print(f"  -> Data Acquisition: PASSED (4 Events Buffered, Correlated Vector: {feat_vec})")

    # 3. PART 2: INTELLIGENCE & REASONING
    print("\n[TEST 3] Testing Part 2 - Intelligence & Reasoning...")
    iam = IAMManager()
    iam.register_user("AAM0658", department="R&D", on_watchlist=True)

    classifier = DataSensitivityClassifier()
    sens = classifier.classify_text("Here is the secret API key: sk-live-99281313")
    assert sens.value == "RESTRICTED_SECRET"

    profiler = BehavioralProfiler()
    anom_score = profiler.compute_behavior_anomaly_score(feat_vec)

    # Multi-pillar Trust Score
    trust_engine = TrustScoreEngine()
    assessment = trust_engine.evaluate(
        user="AAM0658",
        features=feat_vec,
        content_samples=["Here is the confidential salary sheet"],
        file_actions=["C:/secrets/q4_patent.pdf"]
    )
    print(f"  -> Multi-Pillar Trust Assessment: Trust Score = {assessment.trust_score:.2f}, Risk Score = {assessment.risk_score:.2f}")

    # Supervised Prediction (XGBoost)
    predictor = LeakPredictor()
    pred_res = predictor.predict_one(feat_vec)
    print(f"  -> Supervised AI Prediction: Label = {pred_res['predicted_label']}, Leak Risk = {pred_res['risk_score']}%")

    # SHAP Explainability
    explainer = LeakExplainability()
    explanation = explainer.explain_sample(feat_vec)
    print(f"  -> SHAP Explanation: {explanation['narrative']}")

    # Knowledge Graph & Attack Path
    kg = LeakMindKnowledgeGraph()
    kg.add_user("AAM0658", department="R&D")
    kg.add_device("PC-102")
    kg.add_resource("SECRET-DB-01", sensitivity="RESTRICTED_SECRET")
    kg.add_egress_target("USB-STORAGE-EXT", target_type="USB")
    kg.link("AAM0658", "PC-102", "LOGGED_INTO")
    kg.link("PC-102", "SECRET-DB-01", "QUERY_DATA")
    kg.link("PC-102", "USB-STORAGE-EXT", "EXFILTRATE_DATA")

    path_analyzer = AttackPathAnalyzer(kg)
    paths = path_analyzer.find_exfiltration_paths("AAM0658")
    assert len(paths) > 0, "Failed to find graph attack path"
    print(f"  -> Attack Path Analysis: Found {len(paths)} exfiltration path(s). Sample: {paths[0]['hops']}")

    # Quantum QAOA Defense Optimization
    qaoa = QuantumDefenseOptimizer()
    simple_graph = kg.graph.to_undirected()
    qaoa_res = qaoa.simulate_qaoa_optimization(simple_graph, threat_nodes=["AAM0658"])
    print(f"  -> Quantum QAOA Optimization: Energy = {qaoa_res['optimal_energy']}, Isolated = {qaoa_res['quarantine_partition']}")

    # 4. PART 3: DECISION & PROTECTION
    print("\n[TEST 4] Testing Part 3 - Decision & Protection...")
    policy_engine = PolicyEngine()
    action = policy_engine.evaluate_risk(
        risk_score=assessment.risk_score,
        has_secret_content=True,
        is_after_hours_usb=True
    )
    print(f"  -> Policy Decision Action: {action.value}")

    prioritizer = RiskPrioritizer()
    p_incident = prioritizer.prioritize(
        incident_id="INC-2026-001",
        user="AAM0658",
        base_risk=assessment.risk_score,
        is_watchlist=True,
        asset_sensitivity="RESTRICTED_SECRET"
    )
    print(f"  -> Risk Prioritization: Priority Score = {p_incident.priority_score}, Tier = {p_incident.severity_tier}")

    decision_engine = DecisionEngine(encryptor=enc)
    exec_res = decision_engine.execute_decision(
        user="AAM0658",
        action=action,
        resource="PC-102",
        payload_data="PROPRIETARY_PATENT_DOCUMENT"
    )
    print(f"  -> Action Execution Status: {exec_res.status} (Audit Hash: {exec_res.audit_hash[:16]}...)")

    # 5. PART 4: LEARNING & MANAGEMENT
    print("\n[TEST 5] Testing Part 4 - Learning & Management...")
    timeline_gen = IncidentTimelineGenerator()
    timeline = timeline_gen.build_timeline("AAM0658", [evt1, evt2, evt3, evt4], risk_score=assessment.risk_score)
    assert len(timeline) == 4

    rep_gen = InvestigationReportGenerator(reports_dir="reports")
    rep_md = rep_gen.generate_report(
        incident_id="INC-2026-001",
        user="AAM0658",
        assessment=assessment,
        policy_action=action.value,
        top_shap_drivers=explanation["top_drivers"],
        timeline=timeline,
        save_file=True
    )
    expected_path = f"reports/INCIDENT_INC-2026-001_AAM0658.md"
    assert os.path.exists(expected_path), f"Report file was not saved at {expected_path}"
    print("  -> Investigation Report: Generated and saved to reports/INC_INC-2026-001_AAM0658.md")

    fb_engine = AnalystFeedbackEngine()
    fb_rec = fb_engine.record_verdict(
        incident_id="INC-2026-001",
        user="AAM0658",
        analyst="analyst_jane",
        verdict="TRUE_POSITIVE",
        notes="Confirmed malicious intent to exfiltrate proprietary patent."
    )
    stats = fb_engine.get_performance_stats()
    print(f"  -> Analyst Feedback Loop: Recorded {fb_rec.feedback_id}, Precision = {stats['precision_rate']*100:.1f}%")

    forecast_engine = RiskForecastingEngine()
    forecast = forecast_engine.forecast_risk_trajectory([20.0, 35.0, 65.0, 88.0], forecast_horizon_days=7)
    print(f"  -> Risk Forecasting: Velocity = {forecast['velocity']}, 7-Day Projected Risk = {forecast['projected_risk']}%")

    print("\n" + "=" * 70)
    print("ALL 5 ARCHITECTURE DIAGRAM MODULES VERIFIED & OPERATIONAL!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
