"""
LeakMind Quick Smoke Test Runner
"""

import sys
import os

sys.path.insert(0, os.path.abspath("."))

from src.security import authenticate_user, system_audit_logger
from src.intelligence import LeakPredictor, TrustScoreEngine
from src.decision import PolicyEngine

def main():
    print("=" * 60)
    print(" LEAKMIND SYSTEM ARCHITECTURE - STATUS CHECK")
    print("=" * 60)
    
    # 1. Security Check
    ctx = authenticate_user("sec_admin", "Admin@LeakMind2026")
    print(f" [+] Security & Auth: Authenticated as {ctx.username} ({ctx.role.value})")
    
    # 2. Intelligence Check
    predictor = LeakPredictor()
    trust_engine = TrustScoreEngine()
    test_vec = {
        "http_activity_count": 12.0,
        "after_hours_activity": 8.0,
        "device_connect_count": 1.0,
        "unique_pcs": 2.0
    }
    assessment = trust_engine.evaluate("TEST_USER", test_vec, content_samples=["confidential key sk-live"])
    pred = predictor.predict_one(test_vec)
    print(f" [+] Intelligence & Reasoning: Trust={assessment.trust_score:.1f}, Risk={pred['risk_score']:.1f}%")
    
    # 3. Decision Check
    policy = PolicyEngine()
    action = policy.evaluate_risk(pred['risk_score'], has_secret_content=True)
    print(f" [+] Policy & Decision: Action={action.value}")
    
    # 4. Audit Trail
    print(f" [+] Cryptographic Audit Log: {len(system_audit_logger.get_records())} chained hashes (Verified: {system_audit_logger.verify_integrity()})")
    print("=" * 60)
    print(" All systems operational! Ready to launch dashboard:")
    print(" Run: streamlit run dashboard/app.py")
    print("=" * 60)

if __name__ == "__main__":
    main()