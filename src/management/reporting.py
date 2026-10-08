"""
Automated Security Incident Investigation Report Generator
Produces formal technical and executive investigation reports.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from ..intelligence.trust_score import TrustAssessment
from .timeline import TimelineEvent


class InvestigationReportGenerator:
    """
    Generates structured incident reports compliant with SOC forensic guidelines.
    """

    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    def generate_report(
        self,
        incident_id: str,
        user: str,
        assessment: TrustAssessment,
        policy_action: str,
        top_shap_drivers: List[Dict[str, Any]],
        timeline: List[TimelineEvent],
        save_file: bool = True
    ) -> str:
        timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        report_md = f"""# LEAKMIND INCIDENT INVESTIGATION REPORT
**Incident ID:** `{incident_id}`  
**Date/Time:** {timestamp_str}  
**Classification:** HIGH / CONFIDENTIAL  
**Subject User:** `{user}`  

---

## 1. Executive Summary
During automated behavioral monitoring, LeakMind identified high-probability data leakage activity associated with user `{user}`.
* **Risk Score:** **{assessment.risk_score:.2f}%**
* **Trust Score:** **{assessment.trust_score:.2f}/100**
* **Enforced Policy Action:** `{policy_action}`

---

## 2. Multi-Pillar AI Intelligence Assessment
LeakMind evaluated this incident across three fundamental intelligence pillars:
* **Threat Pillar (IoC & Attack Signatures):** `{assessment.threat_pillar:.1f}/100`
* **Behavior Pillar (Isolation Baseline Deviation):** `{assessment.behavior_pillar:.1f}/100`
* **Content Pillar (Data Sensitivity Classification):** `{assessment.content_pillar:.1f}/100`

### Detected Key Indicators
"""
        for ind in assessment.indicators:
            report_md += f"- ⚠️ {ind}\n"

        report_md += """
---

## 3. Explainable Risk (SHAP Feature Attribution)
The following behavioral features were identified by TreeSHAP as the primary quantitative drivers of the threat score:
"""
        for driver in top_shap_drivers[:5]:
            f_name = driver.get("feature", "feature").replace("_", " ").title()
            val = driver.get("observed_value", 0)
            impact = driver.get("shap_impact", 0)
            report_md += f"- **{f_name}**: Observed = `{val}`, Marginal Risk Impact = `+{impact:.4f}`\n"

        report_md += """
---

## 4. Forensic Chronological Timeline
"""
        if timeline:
            report_md += "| Timestamp | Channel | Activity | Severity |\n|---|---|---|---|\n"
            for t in timeline[:15]:
                report_md += f"| `{t.timestamp}` | `{t.channel}` | {t.activity} | **{t.risk_level}** |\n"
        else:
            report_md += "*No discrete timeline events recorded.*\n"

        report_md += f"""
---

## 5. Recommended Containment & Remediation Actions
1. **Endpoint Quarantine:** Maintain restriction on external mass storage devices for `{user}`.
2. **Access Revocation:** Temporarily suspend access to confidential repositories until cleared by SecOps.
3. **Analyst Interview:** Conduct debriefing interview regarding anomalous after-hours transfers.

*Report automatically compiled by LeakMind Autonomous Defense System.*
"""

        if save_file:
            filename = f"INCIDENT_{incident_id}_{user}.md"
            filepath = os.path.join(self.reports_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_md)

        return report_md
