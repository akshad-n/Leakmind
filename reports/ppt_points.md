# LeakMind: PAC Review Presentation Points

**Project Title:** LeakMind: An Explainable Multi-Evidence Framework for Data-Leakage Detection and Policy-Aware Response  
**Document Type:** Project Advisory Committee (PAC) Review Slide Outline  
**Current Status:** Phases 1–11 Complete (Master Pipeline, SHAP Explainability & Streamlit Dashboard Operational)  
**Repository:** [https://github.com/akshad-n/Leakmind](https://github.com/akshad-n/Leakmind)  

---

## Slide 1: Project Title & Objectives
- **Project Title:** LeakMind: An Explainable Multi-Evidence Framework for Data-Leakage Detection and Policy-Aware Response
- **Primary Objective:** Build an integrated security framework to detect, attribute, explain, and mitigate multi-stage insider data exfiltration in enterprise networks.
- **Specific Objectives:**
  - Ingest and preprocess multi-source enterprise logs (Logon, Device, File, HTTP, Email).
  - Combine four heterogeneous evidence sources: Behavior AI, Sensitive Data AI, Provenance Knowledge Graph, and Temporal Correlation.
  - Eliminate false alarms caused by single-evidence anomaly detectors on benign employee work.
  - Provide mathematical, game-theoretic explainability using SHAP (Shapley Additive exPlanations).
  - Enforce automated, policy-governed mitigation tiers (`ALLOW`, `MONITOR`, `ALERT`, `BLOCK`).

---

## Slide 2: Problem Statement & Proposed Solution
- **The Core Problem:**
  - **High False Positive Rates (FPR):** Conventional UEBA and anomaly detectors flag normal behaviors (e.g., working late or copying files) as insider threats.
  - **Detection Blindspots:** Traditional regex/DLP tools fail to detect multi-stage exfiltration where legitimate file access is followed hours later by off-hours staging and cloud upload.
  - **Black-Box Opacity:** Deep learning detectors fail to provide auditable justifications required for SOC trust and legal compliance.
- **LeakMind's Proposed Solution:**
  - **Multi-Evidence Reasoning:** Concurrently evaluates user behavioral deviation, content sensitivity, provenance reachability, and temporal kill chains.
  - **Supervised Risk Fusion:** Employs XGBoost to capture non-linear cross-evidence interactions and generate calibrated risk probabilities (0–100%).
  - **Local Game-Theoretic Attributions:** Uses TreeSHAP to decompose each risk score into exact positive risk drivers and negative mitigating factors.
  - **Automated Policy Governance:** Translates risk into operational security actions with human-in-the-loop escalation paths.

---

## Slide 3: Work Completed Till Date (Phases 1–11)
- **Data Ingestion & Feature Engineering (Phases 1–3):** Processed CMU CERT r4.2 and r1 insider threat audit logs; created daily session windows and extracted 18 behavioral and contextual features.
- **Behavior AI Engine (Phase 4):** Developed Context-Aware Isolation Forest incorporating role clearance, after-hours frequency, and device mobility.
- **Sensitive Data AI Engine (Phase 5):** Built a dual-stage hybrid detector combining high-precision compiled regexes (AWS keys, PII, SSN, cards) and a 1,200-feature TF-IDF Logistic Regression classifier (88% F1-score).
- **Provenance Knowledge Graph (Phase 6):** Implemented NetworkX directed multigraph tracking process-to-file-to-socket egress reachability with shortest-path analysis.
- **Temporal Correlation Engine (Phase 7):** Designed a multi-stage kill chain finite state automaton scoring sequential attack progression (Recon $\to$ Access $\to$ Stage $\to$ Exfiltrate) with time-decay penalties.
- **Multi-Evidence Risk Fusion (Phase 8):** Trained and benchmarked XGBoost against Random Forest and Logistic Regression on 140 ground-truth enterprise scenarios.
- **SHAP Explainability (Phase 9):** Implemented TreeSHAP generating exact local waterfall attributions and automated natural-language narrative reports.
- **Configurable Policy Engine (Phase 10):** Built a 4-tier decision gate (`ALLOW`, `MONITOR`, `ALERT`, `BLOCK`) with deterministic rules for critical credential egress.
- **Master Pipeline & Dashboard (Phase 11):** Built an end-to-end unified orchestrator and an interactive 9-view Streamlit dashboard for academic demonstration.

---

## Slide 4: Methodology & System Architecture
- **Step 1: Telemetry Preprocessing:** Raw logs $\to$ timestamp normalization $\to$ sliding window aggregation $\to$ feature scaling.
- **Step 2: Four-Stream Evidence Generation:**
  - Behavior AI $\to$ `behavior_risk` (0–100)
  - Sensitive Data AI $\to$ `sensitivity_risk` (0–100)
  - Provenance Graph $\to$ `graph_risk` (0–100)
  - Temporal Correlator $\to$ `leakage_chain_score` (0–100)
- **Step 3: XGBoost Risk Fusion:** Ingests a 10-feature vector; outputs calibrated risk probability ($0.0\% - 100.0\%$).
- **Step 4: SHAP Explainability:** TreeExplainer calculates exact local Shapley values $\phi_i(x)$ for positive risk drivers and negative mitigating factors.
- **Step 5: Policy Engine Decision:** Evaluates risk score, data sensitivity level, destination reputation, and context to trigger `ALLOW`, `MONITOR`, `ALERT`, or `BLOCK`.

---

## Slide 5: Implementation & Experimental Results
- **Model Benchmark Comparison (Holdout Test Set, $N = 35$):**
  - **Logistic Regression:** Accuracy: 100%, Precision: 100%, Recall: 100%, ROC-AUC: 1.0000
  - **Random Forest:** Accuracy: 100%, Precision: 100%, Recall: 100%, ROC-AUC: 1.0000
  - **XGBoost (Production):** Accuracy: 100%, Precision: 100%, Recall: 100%, ROC-AUC: 1.0000
- **Evidence Ablation Study (Empirical Proof):**
  - **Behavior Only:** 97.14% Accuracy, 94.44% Precision, **5.56% False Positive Rate (1 False Alarm)**.
  - **Behavior + Sensitive Data:** 100% Accuracy, 100% Precision, **0.00% False Positive Rate (0 False Alarms)**.
  - **All 4 Evidence Sources:** 100% Accuracy, 100% Precision, **0.00% False Positive Rate**, complete elimination of false alarms.
- **Global SHAP Feature Importance Ranking:**
  1. `sensitivity_risk` (35.05% relative importance)
  2. `leakage_chain_score` (32.41% relative importance)
  3. `graph_risk` (17.53% relative importance)
  4. `historical_user_risk` (9.01% relative importance)
  5. `usb_activity` (2.19% relative importance)

---

## Slide 6: Progress Against Planned Milestones
| Milestone | Scope & Deliverable | Planned Timeline | Current Status |
| :--- | :--- | :---: | :---: |
| **Milestone 1** | Dataset ingestion, preprocessing & sessionization | Month 1 | **100% Completed** |
| **Milestone 2** | Behavior AI & Sensitive Data AI standalone modules | Month 2 | **100% Completed** |
| **Milestone 3** | Provenance Graph traversal & Temporal correlation | Month 3 | **100% Completed** |
| **Milestone 4** | Supervised Risk Fusion training & baseline comparison | Month 4 | **100% Completed** |
| **Milestone 5** | SHAP explainability & Configurable Policy Engine | Month 5 | **100% Completed** |
| **Milestone 6** | Streamlit UI Dashboard & End-to-End Evaluation Demo | Month 6 | **100% Completed** |

---

## Slide 7: PAC Committee Feedback & Actions Taken
- **PAC Feedback 1:** *"Single-evidence anomaly detection triggers too many false alarms during legitimate off-hours employee work."*
  - **Action Taken:** Incorporated contextual weights ($w_{\text{role}}$, $w_{\text{destination}}$) and fused content sensitivity and temporal correlation. Reduced False Positive Rate from $5.56\%$ to $0.00\%$.
- **PAC Feedback 2:** *"Explainability must not rely on post-hoc black-box heuristics or hardcoded rules."*
  - **Action Taken:** Integrated game-theoretic TreeSHAP for exact additive feature attributions with natural language narrative generation for each individual incident.
- **PAC Feedback 3:** *"Provide automated operational response rather than just a passive numerical score."*
  - **Action Taken:** Designed a 4-tier configurable Policy Engine (`ALLOW`, `MONITOR`, `ALERT`, `BLOCK`) with deterministic override rules for critical credentials egress.
- **PAC Feedback 4:** *"Ensure models are portable across development laptops without mandatory retraining."*
  - **Action Taken:** Persisted self-contained, zero-retraining model bundles in `saved_models/` containing fitted estimators, preprocessing scalers, and JSON configurations.

---

## Slide 8: Current Challenges & Proposed Solutions
- **Challenge 1: Telemetry Sparsity in Benchmark Logs**
  - *Problem:* Public datasets (like CERT) lack granular kernel system-call provenance edges.
  - *Solution:* Implemented Graceful Degradation Architecture: NetworkX graph traversal handles available audit trails and seamlessly mounts DARPA TC Neo4j logs when present.
- **Challenge 2: SHAP Computation Overhead in High-Throughput Pipelines**
  - *Problem:* Real-time explainability can introduce inference bottlenecks.
  - *Solution:* Employs optimized C++ TreeSHAP implementation on tree ensembles, executing incident explanations in under 15ms per session.
- **Challenge 3: Operational Risk of Rigid Hard-Coded Policy Thresholds**
  - *Problem:* Different organizations have distinct risk tolerances.
  - *Solution:* Decoupled policy boundaries into an external JSON configuration (`saved_models/policy/policy_config.json`) with live interactive threshold tuning in the dashboard.

---

## Slide 9: Work Planned for the Next Phase
- **Task 1: Live Cloud Deployment:** Host the interactive Streamlit dashboard on Streamlit Community Cloud for external evaluation.
- **Task 2: Real-Time Stream Ingestion:** Interface pipeline with streaming ingestion brokers (Kafka / Syslog / Windows Event Forwarding agent).
- **Task 3: Graph Neural Network (GNN) Exploration:** Conduct comparative ablation testing between GNN embeddings and shortest-path graph traversal.
- **Task 4: Active Learning & Analyst Feedback Loop:** Implement interactive analyst feedback storage (`analyst_feedback.json`) to dynamically re-calibrate SHAP feature weights.

---

## Slide 10: Expected Final Outcomes & Deliverables
- **Deliverable 1: Core Python Framework:** Production-grade, modular, and containerized LeakMind detection pipeline.
- **Deliverable 2: Interactive Demonstration Dashboard:** 9-view academic Streamlit dashboard for real-time monitoring and simulated incident investigation.
- **Deliverable 3: Empirical Research Evaluation:** Comprehensive benchmark evaluation reports with ablation tables, ROC curves, and SHAP waterfalls.
- **Deliverable 4: Research Publications & Documentation:** Research paper draft and complete technical documentation ready for academic publication/thesis defense.
