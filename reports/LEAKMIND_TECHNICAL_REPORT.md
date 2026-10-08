# LeakMind: Comprehensive Technical Architecture & Evaluation Report

**Document Version:** 1.0.0 (Phases 1–11 Complete)  
**Author/Project:** LeakMind Academic Research Project  
**Repository:** [https://github.com/akshad-n/Leakmind](https://github.com/akshad-n/Leakmind)  

---

## 1. Executive Summary & Research Positioning

### 1.1 Project Objective
**LeakMind** is an explainable, multi-evidence cybersecurity framework designed to detect, attribute, explain, and mitigate complex, multi-stage enterprise data-leakage incidents. 

Traditional Data Loss Prevention (DLP) systems rely on rigid regular-expression keywords or single-point anomaly detection. Such systems suffer from two major flaws:
1. **High False Positive Rates (FPR):** Routine employee behavior (e.g., working late, copying large files) is flagged as malicious.
2. **Detection Blindspots:** Sophisticated insiders disguise exfiltration over multiple temporal stages (e.g., legitimate read $\to$ off-hours staging $\to$ encrypted transfer via removable media or cloud egress).

### 1.2 Academic Research Contribution
LeakMind does **not** claim to invent new foundational ML algorithms (such as Isolation Forest, XGBoost, or SHAP). Rather, LeakMind's **primary scientific contribution** is:
> The **holistic fusion and empirical evaluation of four heterogeneous evidence sources** (user behavior, data sensitivity, graph provenance, and temporal correlation) into a unified risk scoring pipeline with local game-theoretic (SHAP) explanations and policy-aware automated response.

### 1.3 Core Research Question
> *"Does fusing behavioral, sensitive-data, provenance, and temporal evidence improve detection and explainability of multi-stage data-leakage incidents compared with isolated single-evidence baselines?"*

---

## 2. End-to-End System Architecture

```text
                           RAW ENTERPRISE TELEMETRY
            (CERT Insider Threat Logs: Logon, Device, File, HTTP, Email)
                                      │
                                      ▼
                        PREPROCESSING & SESSIONIZATION
            (Time parsing, User window aggregation, Context extraction)
                                      │
                                      ▼
                             FEATURE ENGINEERING
              (Activity counts, After-hours flags, Velocity ratios)
                                      │
        ┌─────────────────────────────┴─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  1. BEHAVIOR AI  │          │2. SENSITIVE DATA │          │  3. PROVENANCE   │
│ Isolation Forest │          │ Hybrid: RegEx +  │          │  KNOWLEDGE GRAPH │
│ + Context Scaling│          │ TF-IDF LogReg    │          │ Traversal & Risk │
└────────┬─────────┘          └────────┬─────────┘          └────────┬─────────┘
         │                             │                             │
         │ Behavior Risk (0-100)       │ Sensitivity Risk (0-100)    │ Graph Risk (0-100)
         └───────────────────────┬─────┴─────────────────────────────┘
                                 │
                                 ▼
                    ┌───────────────────────────┐
                    │  4. TEMPORAL CORRELATION  │
                    │ Multi-Stage Kill Chain    │
                    │ Finite State Matcher      │
                    └────────────┬──────────────┘
                                 │ Leakage Chain Score (0-100)
                                 ▼
                    ┌───────────────────────────┐
                    │  5. XGBOOST RISK FUSION   │
                    │ 10-Feature Vector Input   │
                    │ Log-loss Calibrated Prob  │
                    └────────────┬──────────────┘
                                 │ Final Risk Score (0–100%)
                                 ▼
                    ┌───────────────────────────┐
                    │   6. SHAP EXPLAINABILITY  │
                    │ TreeExplainer Attributions│
                    │ Positive & Negative Drivers│
                    └────────────┬──────────────┘
                                 │ Attributed Narrative
                                 ▼
                    ┌───────────────────────────┐
                    │     7. POLICY ENGINE      │
                    │ Multi-Factor Decision Gate│
                    └────────────┬──────────────┘
                                 │
         ┌───────────────┬───────┴───────┬───────────────┐
         ▼               ▼               ▼               ▼
     [ ALLOW ]     [ MONITOR ]      [ ALERT ]       [ BLOCK ]
     (Risk < 40)   (40 <= R < 70)  (70 <= R < 90)   (Risk >= 90)
```

---

## 3. Telemetry & Datasets Used

### 3.1 Dataset Inventory
| Dataset Name | Source / Version | Purpose in LeakMind | Volume & Characteristics |
| :--- | :--- | :--- | :--- |
| **CERT Insider Threat** | Carnegie Mellon SEI (v4.2 & r1) | Primary training & evaluation baseline | Hundreds of thousands of audit events: `logon.csv`, `device.csv`, `file.csv`, `http.csv`, `email.csv`, `psychometric.csv`. |
| **CERT Answer Keys** | SEI r4.2 / r5.2 / r6.2 ground truth | Supervised model evaluation & benchmark validation | 140 ground-truth enterprise evaluation instances (70 confirmed malicious exfiltration scenarios, 70 benign baselines). |
| **Sensitive Data Corpus** | Curated PII, PCI-DSS, credentials corpus | Sensitive Data AI training & evaluation | 50 multi-class text samples covering PII (SSN, IBAN), credentials (keys, tokens), corporate financials, and benign text. |
| **Synthetic Kill Chain Telemetry** | Controlled attack simulation | End-to-end integration & live demonstration | Multi-stage insider exfiltration scenario (Insider Alice) vs. normal daily worker baseline (Bob). |

### 3.2 Preprocessing & Data Transformation
- **Sessionization:** Individual log entries are grouped by `(user_id, date)` and sliding 24-hour windows.
- **After-Hours Normalization:** Timestamps are evaluated against enterprise core hours (08:00–18:00 local time Monday–Friday). Weekend and nocturnal activity is parsed into dedicated after-hours frequency counters.
- **Missing Value Imputation:** Missing device IDs, URLs, and file paths are imputed with dedicated categorical tokens (`UNKNOWN_DEVICE`, `INTERNAL_NET`).

---

## 4. Machine Learning & Analytical Models

LeakMind uses four specialized machine learning and analytical models across its pipeline:

### 4.1 Module 1: Behavior AI (Unsupervised Anomaly Detection)
- **Algorithm:** **Isolation Forest** (`sklearn.ensemble.IsolationForest`)
- **Mathematical Principle:** Tree ensemble that isolates anomalies by randomly selecting a feature and splitting value. Anomalies require fewer recursive partitions to isolate than normal cluster points.
- **Hyperparameters:**
  - `n_estimators`: 100 trees
  - `contamination`: 0.01 (assumes top 1% extreme outliers)
  - `max_samples`: `'auto'` ($\min(256, n)$)
  - `random_state`: 42
- **Preprocessor:** `StandardScaler` (zero mean, unit variance)
- **Context-Aware Scaling Function:**
  $$\text{Context Score} = \sum_{k} w_k \cdot \text{Factor}_k$$
  $$\text{Behavior Risk} = \text{Clip}\left(\frac{1 - \text{Raw Score}}{2} \times 100 \times (1 + \text{Context Score}), 0, 100\right)$$
  - Weights: $w_{\text{after\_hours}}=0.5$, $w_{\text{usb}}=1.2$, $w_{\text{destination}}=1.5$, $w_{\text{role}}=0.8$.

### 4.2 Module 2: Sensitive Data AI (Hybrid NLP + Rule Classifier)
- **Architecture:** Dual-stage hybrid engine.
  1. **Deterministic Rule Engine:** High-precision compiled regular expressions (`re.Pattern`) matching:
     - Private RSA/DSA keys (`-----BEGIN PRIVATE KEY-----`)
     - Cloud credentials (AWS access keys `AKIA[0-9A-Z]{16}`, generic API keys)
     - Financial indicators (Credit card numbers, IBANs, payroll compensation)
     - Personal Identifiable Information (SSN `\d{3}-\d{2}-\d{4}`)
  2. **Machine Learning Classifier:**
     - **Algorithm:** Multiclass Logistic Regression (`sklearn.linear_model.LogisticRegression`)
     - **Feature Extractor:** TF-IDF Vectorizer (`ngram_range=(1, 2)`, `max_features=1200`, `sublinear_tf=True`)
     - **Regularization:** $C=1.5$, `max_iter=300`, `random_state=42`
- **Output:** Categorical sensitivity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and continuous `sensitivity_risk` $\in [0, 100]$.

### 4.3 Module 3: Provenance Knowledge Graph (Graph Traversal Engine)
- **Graph Library:** `NetworkX` (with architectural abstraction for `Neo4j` Bolt driver).
- **Graph Topology:**
  - **Node Types:** `User`, `Process`, `File`, `Socket/Destination`, `Device`
  - **Edge Types:** `LOGGED_INTO`, `SPAWNED`, `READ`, `WRITTEN_TO`, `MOUNTED`, `EGRESSED_TO`
- **Analytical Graph Traversal:**
  - Shortest path search from sensitive source entities to external egress nodes.
  - Cycle detection for file staging loops.
  - Reachability analysis:
    $$\text{Graph Risk} = \min(100, 40 \times N_{\text{attack\_paths}} + 25 \times N_{\text{untrusted\_egress}})$$

### 4.4 Module 4: Temporal Correlation (Kill Chain Automaton)
- **Algorithm:** Deterministic Finite State Automaton (FSA) with time-window decay.
- **Target Attack Stages:**
  1. `RECON` (Sensitive file search / off-hours login)
  2. `ACCESS` (High-volume file read operations)
  3. `STAGING` (Compression / archive creation / directory movement)
  4. `EXFILTRATION` (USB copy / cloud upload)
- **Mathematical Formula:**
  $$\text{Leakage Chain Score} = \min\left(100.0, \sum_{s \in \text{Stages}} W_s \cdot e^{-\lambda \Delta t_s}\right)$$
  Where $W_{\text{recon}}=15$, $W_{\text{access}}=25$, $W_{\text{staging}}=25$, $W_{\text{exfil}}=35$, and $\Delta t$ represents inter-stage latency.

### 4.5 Module 5: Risk Fusion Engine (Supervised Classifier)
- **Primary Model:** **XGBoost Classifier** (`xgboost.XGBClassifier`)
- **Comparative Baselines:**
  - Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`)
  - Regularized Logistic Regression (`sklearn.linear_model.LogisticRegression`)
- **XGBoost Hyperparameters:**
  - `n_estimators`: 100
  - `max_depth`: 4
  - `learning_rate`: 0.05
  - `subsample`: 0.8
  - `colsample_bytree`: 0.6
  - `colsample_bynode`: 0.6
  - `eval_metric`: `'logloss'`
  - `random_state`: 42
- **Output:** Calibrated continuous risk probability $P(\text{Malicious} \mid X) \in [0.0, 1.0]$ mapped to Risk Score $0.0\% - 100.0\%$.

---

## 5. Comprehensive Feature Inventory

The Risk Fusion engine evaluates a curated 10-feature vector representing the four distinct dimensions of evidence:

| Feature Name | Evidence Dimension | Data Type | Range | Description & Source |
| :--- | :--- | :--- | :--- | :--- |
| `behavior_risk` | Behavior AI | Float | $[0.0, 100.0]$ | Inverted and normalized Isolation Forest anomaly score scaled by contextual weight. |
| `sensitivity_risk` | Sensitive Data AI | Float | $[0.0, 100.0]$ | Highest sensitivity score across accessed file content and transmission metadata. |
| `graph_risk` | Provenance Graph | Float | $[0.0, 100.0]$ | Structural risk calculated from process-to-file-to-network reachability graph paths. |
| `leakage_chain_score` | Temporal Correlator | Float | $[0.0, 100.0]$ | Multi-stage kill chain progression score within sliding time windows. |
| `destination_risk` | Contextual Telemetry | Float | $[0.0, 100.0]$ | Reputation risk score of destination URL, domain, or IP address. |
| `historical_user_risk` | Baseline Behavior | Float | $[0.0, 100.0]$ | Historical moving average anomaly score for the specific user account. |
| `after_hours_activity` | Temporal Telemetry | Integer | $[0, \infty)$ | Total event count occurring outside enterprise operating hours (18:00–08:00 / weekends). |
| `usb_activity` | Device Telemetry | Integer | $[0, \infty)$ | Number of removable storage drive connections or file copies to USB media. |
| `new_device` | Device Telemetry | Binary | $\{0, 1\}$ | Indicator flag: device ID has not been previously registered to this user. |
| `external_destination` | Network Telemetry | Binary | $\{0, 1\}$ | Indicator flag: egress network traffic is directed to an external or untrusted endpoint. |

---

## 6. Explainable AI (SHAP) Implementation

### 6.1 Game-Theoretic Formulation
To prevent "black box" decisions, LeakMind applies **SHAP (SHapley Additive exPlanations)** based on cooperative game theory. For any incident feature vector $x$:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
- $f(x)$: Model prediction in log-odds space.
- $\phi_0$: Base value (expected prediction over training dataset, evaluated at $0.0186$).
- $\phi_i(x)$: Local attribution value of feature $i$ for this specific incident.

### 6.2 Empirical Global Feature Importance Ranking
Calculated across the complete enterprise evaluation cohort ($N = 140$ samples):

| Rank | Feature | Meaning | Mean \|SHAP\| | Relative Importance | Primary Direction |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **1** | `sensitivity_risk` | Sensitive file access | **1.3584** | **35.05%** | Risk Mitigator / Driver |
| **2** | `leakage_chain_score` | Multi-stage kill chain | **1.2558** | **32.41%** | Risk Mitigator / Driver |
| **3** | `graph_risk` | Provenance graph risk | **0.6793** | **17.53%** | Risk Mitigator / Driver |
| **4** | `historical_user_risk` | Activity deviation | **0.3492** | **9.01%** | Risk Driver |
| **5** | `usb_activity` | Removable storage use | **0.0847** | **2.19%** | Risk Driver |
| **6** | `behavior_risk` | Behavioral anomaly | **0.0793** | **2.05%** | Risk Driver |
| **7** | `after_hours_activity` | After-hours behavior | **0.0380** | **0.98%** | Risk Driver |
| **8** | `external_destination` | External network drop | **0.0275** | **0.71%** | Risk Driver |
| **9** | `destination_risk` | Untrusted destination | **0.0035** | **0.09%** | Risk Driver |
| **10** | `new_device` | Unregistered device | **0.0000** | **0.00%** | Contextual |

### 6.3 Automated Natural-Language Explanation Example
For a high-risk incident:
```text
Final Risk: 97.9% [TIER: CRITICAL]
Top Positive Risk Contributors (Drivers):
  [+] Sensitive file access: high contribution (+1.42 SHAP)
  [+] Multi-stage leakage chain: high contribution (+1.28 SHAP)
  [+] Provenance graph reachability: moderate contribution (+0.65 SHAP)
  [+] Removable USB media connected: moderate contribution (+0.12 SHAP)

Top Negative Risk Contributors (Mitigators):
  [-] Normal daytime workstation logon (-0.04 SHAP)
```

---

## 7. Configurable Policy Engine

### 7.1 Decision Tiers & Default Governance Boundaries
The policy engine translates continuous risk scores and contextual factors into discrete operational actions:

| Risk Tier | Risk Range | Default Decision | Operational Security Action |
| :--- | :---: | :---: | :--- |
| **Low Risk** | $0.0\% \le \text{Risk} < 40.0\%$ | **`ALLOW`** | Permit operation; routine passive audit log retained. |
| **Medium Risk** | $40.0\% \le \text{Risk} < 70.0\%$ | **`MONITOR`** | Enable continuous session recording, increase telemetry verbosity. |
| **High Risk** | $70.0\% \le \text{Risk} < 90.0\%$ | **`ALERT / APPROVAL`** | Dispatch SOC alert; require manager/analyst 2-factor sign-off. |
| **Critical Risk** | $\text{Risk} \ge 90.0\%$ | **`BLOCK`** | Terminate process, revoke network access, isolate workstation. |

*Disclaimer: Policy thresholds (40, 70, 90) represent initial heuristic baseline boundaries and are fully configurable via [`saved_models/policy/policy_config.json`](file:///c:/Users/USER/OneDrive/Desktop/leakmind%20project/saved_models/policy/policy_config.json).*

### 7.2 Multi-Factor Policy Rules
In addition to threshold evaluation, the policy engine enforces deterministic governance overrides:
1. **Rule 1 (`RULE_CRITICAL_EGRESS_BLOCK`):** If $\text{Risk} \ge 90\%$ **AND** Sensitivity is `CRITICAL` **AND** Destination is External $\to$ `BLOCK`.
2. **Rule 2 (`RULE_MASS_EXFIL_BLOCK`):** If $\text{Risk} \ge 85\%$ **AND** USB activity detected with sensitive files $\to$ `BLOCK`.
3. **Rule 3 (`RULE_AFTER_HOURS_ELEVATION`):** If $60\% \le \text{Risk} < 70\%$ **AND** Activity is After-Hours $\to$ Escalate from `MONITOR` to `ALERT / APPROVAL`.

---

## 8. Empirical Evaluation & Ablation Results

### 8.1 Model Benchmark Comparison (Test Set: $N=35$)
| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.00% |
| **Random Forest** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.00% |
| **XGBoost (Selected)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.00%** |

### 8.2 Incremental Evidence Ablation Study
The ablation study validates the central scientific thesis: **Does combining heterogeneous evidence sources outperform isolated approaches?**

| Ablation Configuration | Features Included | Accuracy | Precision | Recall | F1-Score | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Behavior AI Only** | 5 features | 0.9714 | 0.9444 | 1.0000 | 0.9714 | 1 false alarm (5.56% FPR) |
| **2. Behavior + Sensitivity** | 6 features | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 false alarms (0.00% FPR) |
| **3. Behavior + Sensitivity + Provenance** | 9 features | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 false alarms (0.00% FPR) |
| **4. All Evidence + Temporal Kill Chain** | 10 features | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 false alarms (0.00% FPR) |
| **5. Full XGBoost Fusion Pipeline** | 10 features | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0 false alarms (0.00% FPR)** |

**Key Academic Takeaway:** Single-evidence anomaly detection (Behavior only) produced a false positive alarm when confronted with routine after-hours worker activity. Adding Data Sensitivity, Graph Provenance, and Temporal Correlation completely eliminated the false positive, achieving 100% precision with zero false alarms.

---

## 9. Technical Q&A / Viva Reference Guide

### Q1: Why did you choose Isolation Forest for Behavior AI instead of Autoencoders or One-Class SVM?
> **Answer:** Isolation Forest scales linearly with large datasets ($O(n \log n)$), requires significantly less compute than neural autoencoders, and does not require complex hyperparameter tuning. Most importantly, Isolation Forest isolates anomalies explicitly rather than profiling normal data density, making it less susceptible to the "curse of dimensionality" and data drift in enterprise telemetry.

### Q2: Why is XGBoost used for Risk Fusion rather than simple weighted averaging?
> **Answer:** Weighted averaging assumes independent, linear contributions from each evidence source. In reality, data leakage involves non-linear interactions: for example, after-hours activity alone is harmless, and accessing sensitive data alone is routine, but the *joint presence* of sensitive data + after-hours logon + USB staging indicates malicious intent. XGBoost captures high-order feature interactions, produces calibrated probabilities, and directly interfaces with TreeSHAP for exact local explainability.

### Q3: What is the difference between Graph Risk and Temporal Chain Score?
> **Answer:** 
> - **Graph Risk (Structural):** Captures *spatial provenance*—which processes touched which files and connected to which sockets, traversing the chain of custody across system entities.
> - **Temporal Chain Score (Sequential):** Captures *time-ordered causality*—verifying that events followed a multi-stage attack lifecycle (Recon $\to$ Access $\to$ Stage $\to$ Exfiltrate) within bounded time intervals, decaying if steps occurred months apart.

### Q4: How does SHAP guarantee fair feature attribution?
> **Answer:** SHAP is uniquely grounded in cooperative game theory (Shapley values). It is the only attribution method that mathematically satisfies four essential properties: **Efficiency** (sum of attributions equals difference from base value), **Symmetry** (identical contributors receive identical credit), **Dummy** (features with no impact receive zero attribution), and **Additivity** (attributions can be summed across ensemble trees).

### Q5: How does LeakMind handle missing telemetry or datasets?
> **Answer:** LeakMind incorporates a **Graceful Degradation Architecture**. If an optional telemetry source (such as DARPA provenance logs or deep PII corpus) is absent, the corresponding interface reports status `NOT_AVAILABLE`, and downstream fusion modules automatically apply default baseline priors without throwing unhandled exceptions.

---

## 10. Summary File Map

```text
Leakmind/
├── dashboard/
│   └── app.py                     # 9-View Streamlit Academic Dashboard
├── src/
│   ├── pipeline.py                # End-to-End Master Pipeline Orchestrator
│   ├── context_behavior.py        # Context-Aware Isolation Forest (Behavior AI)
│   ├── sensitivity.py             # Hybrid Regex + TF-IDF Classifier (Sensitive Data AI)
│   ├── provenance.py              # Provenance Knowledge Graph Traversal Engine
│   ├── temporal.py                # Multi-Stage Kill Chain Temporal Correlator
│   ├── fusion.py                  # XGBoost Multi-Evidence Risk Fusion Engine
│   ├── explainability.py          # TreeSHAP Risk Explainer & Narrative Generator
│   ├── policy.py                  # Configurable 4-Tier Automated Policy Engine
│   ├── preprocessing.py           # CERT Telemetry Extraction & Normalization
│   └── feature_engineering.py     # Session & Context Feature Aggregation
├── saved_models/                  # Zero-retraining portable model bundles (JSON & joblib)
├── reports/                       # Empirical evaluation & ablation benchmark reports
└── demo_leakage_scenario.py       # Controlled insider attack vs. benign baseline demo
```
