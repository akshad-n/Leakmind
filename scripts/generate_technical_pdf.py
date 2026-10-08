"""
LeakMind Technical Architecture & Evaluation Report PDF Generator
Produces a high-quality, publication-grade academic PDF using ReportLab.
"""

import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
    KeepTogether,
    HRFlowable,
    PageBreak
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page count: 'Page X of Y'
    along with running header and footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "LeakMind: Technical Architecture & Evaluation Report")
            self.drawRightString(letter[0] - 54, letter[1] - 36, "Academic Research Documentation")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Footer (All pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, letter[0] - 54, 45)

        self.drawString(54, 32, "Confidential & Academic Research — LeakMind Framework (Phases 1-11)")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 32, page_str)
        self.restoreState()


def build_pdf(output_pdf_path: str):
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom Palette
    C_PRIMARY = colors.HexColor("#0F172A")    # Deep Navy
    C_SECONDARY = colors.HexColor("#1E3A8A")  # Royal Navy
    C_ACCENT = colors.HexColor("#0284C7")     # Blue Cyan
    C_DARK = colors.HexColor("#1E293B")       # Slate
    C_MUTED = colors.HexColor("#475569")      # Muted slate
    C_BG_LIGHT = colors.HexColor("#F8FAFC")   # Light background
    C_BG_CODE = colors.HexColor("#F1F5F9")    # Code block background
    C_LINE = colors.HexColor("#E2E8F0")

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=C_PRIMARY,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=C_MUTED,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=C_SECONDARY,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13,
        textColor=C_DARK,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=C_DARK,
        spaceAfter=5
    )

    body_bold = ParagraphStyle(
        'Body_Bold',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=C_DARK,
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=C_DARK,
        leftIndent=14,
        firstLineIndent=-8,
        spaceAfter=3
    )

    callout_style = ParagraphStyle(
        'Callout_Custom',
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=C_SECONDARY,
        leftIndent=10,
        rightIndent=10,
        spaceBefore=4,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        fontName='Courier',
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#0F172A")
    )

    table_header = ParagraphStyle(
        'TableHeader',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
        alignment=0
    )

    table_cell = ParagraphStyle(
        'TableCell',
        fontName='Helvetica',
        fontSize=7,
        leading=8.5,
        textColor=C_DARK
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=8.5,
        textColor=C_DARK
    )

    story = []

    # =========================================================================
    # COVER / HEADER BANNER
    # =========================================================================
    header_data = [
        [
            Paragraph("<b>LEAKMIND</b>", ParagraphStyle('BannerH1', fontName='Helvetica-Bold', fontSize=18, leading=20, textColor=colors.white)),
            Paragraph("<b>ACADEMIC RESEARCH TECHNICAL REPORT</b><br/><font size='7'>Version 1.0.0 (Phases 1–11 Complete) • Oct 2026</font>", ParagraphStyle('BannerRight', fontName='Helvetica', fontSize=8, leading=10, textColor=colors.HexColor("#E2E8F0"), alignment=2))
        ],
        [
            Paragraph("An Explainable Multi-Evidence Framework for Data-Leakage Detection and Policy-Aware Response", ParagraphStyle('BannerSub', fontName='Helvetica', fontSize=8.5, leading=11, textColor=colors.HexColor("#93C5FD"))),
            Paragraph("Repository: github.com/akshad-n/Leakmind", ParagraphStyle('BannerRepo', fontName='Helvetica', fontSize=7.5, leading=9, textColor=colors.white, alignment=2))
        ]
    ]
    t_header = Table(header_data, colWidths=[330, 174])
    t_header.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 8),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 1. EXECUTIVE SUMMARY & RESEARCH POSITIONING
    # =========================================================================
    story.append(Paragraph("1. Executive Summary & Research Positioning", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    story.append(Paragraph(
        "<b>LeakMind</b> is an explainable, multi-evidence cybersecurity framework designed to detect, attribute, explain, "
        "and mitigate complex, multi-stage enterprise data-leakage incidents. Traditional Data Loss Prevention (DLP) systems "
        "rely on rigid keyword regexes or single-point anomaly detection. Such systems suffer from two major flaws: "
        "(1) <b>High False Positive Rates (FPR)</b> that burden security teams, and (2) <b>Blindspots</b> to multi-stage "
        "insider exfiltration tactics (e.g., legitimate file reading &rarr; after-hours staging &rarr; USB/cloud transfer).",
        body_style
    ))

    # Callout: Academic Positioning
    callout_box = [
        [Paragraph("<b>Academic Research Contribution & Positioning:</b><br/>"
                   "LeakMind does <i>not</i> claim to invent new fundamental machine learning algorithms (such as Isolation Forest, "
                   "XGBoost, or SHAP). Rather, LeakMind's primary scientific contribution is the <b>holistic fusion and empirical "
                   "evaluation of four heterogeneous evidence sources</b> (user behavior, data sensitivity, graph provenance, "
                   "and temporal correlation) into a unified risk scoring pipeline with local game-theoretic explanations and "
                   "policy-aware automated mitigation.", callout_style)]
    ]
    t_callout = Table(callout_box, colWidths=[504])
    t_callout.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_BG_LIGHT),
        ('BOX', (0, 0), (-1, -1), 0.5, C_ACCENT),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_callout)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Main Research Question:</b> <i>\"Does fusing behavioral, sensitive-data, provenance, and temporal evidence improve detection and explainability of multi-stage data-leakage incidents compared with isolated single-evidence baselines?\"</i>", body_style))
    story.append(Spacer(1, 8))

    # =========================================================================
    # 2. SYSTEM ARCHITECTURE & PIPELINE FLOW
    # =========================================================================
    story.append(Paragraph("2. End-to-End System Architecture", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    arch_text = (
        "RAW ENTERPRISE LOGS (CERT: Logon, Device, File, HTTP, Email)\n"
        "                  │\n"
        "                  ▼ Preprocessing, Window Aggregation & Normalization\n"
        "┌─────────────────┴───────────────────────────────────────────────────────┐\n"
        "│                      MULTI-EVIDENCE REASONING                           │\n"
        "├──────────────────────────┬──────────────────────────┬───────────────────┤\n"
        "│ 1. Behavior AI           │ 2. Sensitive Data AI     │ 3. Provenance     │\n"
        "│    Isolation Forest      │    Hybrid RegEx + TF-IDF │    Knowledge Graph│\n"
        "│    & Context Scaling     │    Logistic Regression   │    Traversal Risk │\n"
        "│    -> Behavior Risk      │    -> Sensitivity Risk   │    -> Graph Risk  │\n"
        "└──────────────────────────┴──────────────────────────┴───────────────────┘\n"
        "                  │\n"
        "                  ▼ 4. Temporal Correlator (Multi-Stage Kill Chain FSA)\n"
        "                  │    -> Leakage Chain Score (0-100)\n"
        "                  ▼\n"
        "     5. XGBoost Risk Fusion Engine (10-Feature Calibrated Probability)\n"
        "                  │    -> Final Risk Score (0–100%)\n"
        "                  ▼\n"
        "     6. SHAP Risk Explainer (TreeSHAP Local Attributions & Narratives)\n"
        "                  │\n"
        "                  ▼ 7. Configurable Policy Engine\n"
        "     ┌────────────┬─────────────┬─────────────┐\n"
        "     ALLOW (<40)  MONITOR(40-70) ALERT(70-90)  BLOCK (>90%)\n"
    )
    t_arch = Table([[Preformatted(arch_text, code_style)]], colWidths=[504])
    t_arch.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_BG_CODE),
        ('BOX', (0, 0), (-1, -1), 0.5, C_LINE),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 3. DATASETS USED & PREPROCESSING
    # =========================================================================
    story.append(Paragraph("3. Datasets Used & Telemetry Ingestion", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    story.append(Paragraph(
        "LeakMind is evaluated against standard insider threat datasets and purpose-built sensitive data corpora:",
        body_style
    ))

    datasets_table = [
        [Paragraph("Dataset Name", table_header), Paragraph("Source / Version", table_header), Paragraph("Role in LeakMind", table_header), Paragraph("Scope & Size", table_header)],
        [Paragraph("CERT Insider Threat", table_cell_bold), Paragraph("CMU SEI (r4.2 & r1)", table_cell), Paragraph("Primary user baseline & telemetry", table_cell), Paragraph("Hundreds of thousands of audit events across logon, http, device, file, email", table_cell)],
        [Paragraph("CERT Answer Keys", table_cell_bold), Paragraph("CMU SEI Ground Truth", table_cell), Paragraph("Supervised benchmark evaluation", table_cell), Paragraph("140 enterprise evaluation scenarios (70 confirmed attacks, 70 benign baselines)", table_cell)],
        [Paragraph("Sensitive Data Corpus", table_cell_bold), Paragraph("Curated PII/PCI/Credentials", table_cell), Paragraph("Sensitive Data AI training & eval", table_cell), Paragraph("50 multi-class text samples (SSN, IBAN, API keys, credentials, business docs)", table_cell)],
        [Paragraph("Controlled Kill Chain", table_cell_bold), Paragraph("Synthetic attack sequence", table_cell), Paragraph("End-to-end integration demo", table_cell), Paragraph("Multi-stage insider attack (Alice) vs. routine day worker baseline (Bob)", table_cell)],
    ]
    t_data = Table(datasets_table, colWidths=[100, 95, 115, 194])
    t_data.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
    ]))
    story.append(t_data)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 4. CORE MACHINE LEARNING & ANALYTICAL MODELS
    # =========================================================================
    story.append(Paragraph("4. Core Machine Learning & Analytical Models", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    models_table = [
        [Paragraph("Engine", table_header), Paragraph("Algorithm", table_header), Paragraph("Library", table_header), Paragraph("Hyperparameters & Key Logic", table_header), Paragraph("Output", table_header)],
        [
            Paragraph("1. Behavior AI", table_cell_bold),
            Paragraph("Isolation Forest", table_cell),
            Paragraph("scikit-learn", table_cell),
            Paragraph("n_estimators=100, contamination=0.01, StandardScaler preprocessing. Scaled by contextual after-hours & device weights.", table_cell),
            Paragraph("Behavior Risk (0–100)", table_cell)
        ],
        [
            Paragraph("2. Sensitive Data AI", table_cell_bold),
            Paragraph("Hybrid Regex + TF-IDF Classifier", table_cell),
            Paragraph("re + Logistic Regression", table_cell),
            Paragraph("Compiled regexes for private keys, AWS keys, credit cards, SSN, IBAN. TF-IDF (1200 features, n-grams 1-2, C=1.5).", table_cell),
            Paragraph("Sensitivity Risk (0–100), Level (LOW to CRITICAL)", table_cell)
        ],
        [
            Paragraph("3. Provenance Graph", table_cell_bold),
            Paragraph("Graph Traversal & Shortest Path", table_cell),
            Paragraph("NetworkX (pluggable Neo4j)", table_cell),
            Paragraph("Directed Multigraph: User -> Process -> File -> Socket. Shortest path to untrusted egress, cycle detection.", table_cell),
            Paragraph("Graph Risk (0–100), Attack Paths Count", table_cell)
        ],
        [
            Paragraph("4. Temporal Correlator", table_cell_bold),
            Paragraph("Multi-Stage Kill Chain Automaton", table_cell),
            Paragraph("Custom Finite State Automaton", table_cell),
            Paragraph("Detects: Recon -> File Read -> Staging/Zip -> Egress. Time-decay exponential penalty exp(-lambda * delta_t).", table_cell),
            Paragraph("Leakage Chain Score (0–100)", table_cell)
        ],
        [
            Paragraph("5. Risk Fusion", table_cell_bold),
            Paragraph("XGBoost Classifier", table_cell),
            Paragraph("xgboost", table_cell),
            Paragraph("n_estimators=100, max_depth=4, lr=0.05, subsample=0.8, colsample_bytree=0.6, eval_metric='logloss'.", table_cell),
            Paragraph("Final Risk % (0.0–100.0%)", table_cell)
        ],
        [
            Paragraph("6. Explainability", table_cell_bold),
            Paragraph("TreeSHAP", table_cell),
            Paragraph("shap", table_cell),
            Paragraph("Exact game-theoretic local feature attributions. Base expected value = 0.0186.", table_cell),
            Paragraph("SHAP Values, Positive & Negative Drivers", table_cell)
        ],
        [
            Paragraph("7. Policy Engine", table_cell_bold),
            Paragraph("Configurable Rule Gate", table_cell),
            Paragraph("Pure Python", table_cell),
            Paragraph("Thresholds: <40 Allow, 40-70 Monitor, 70-90 Alert, >90 Block. Multi-factor overrides (Critical data + Cloud egress).", table_cell),
            Paragraph("Decision (ALLOW, MONITOR, ALERT, BLOCK)", table_cell)
        ],
    ]
    t_models = Table(models_table, colWidths=[70, 75, 65, 204, 90])
    t_models.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3.5),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_models)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 5. COMPREHENSIVE FEATURE INVENTORY
    # =========================================================================
    story.append(Paragraph("5. Comprehensive Feature Inventory (10-Vector Input)", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    features_table = [
        [Paragraph("Feature Name", table_header), Paragraph("Evidence Source", table_header), Paragraph("Type", table_header), Paragraph("Range", table_header), Paragraph("Extraction Logic & Description", table_header)],
        [Paragraph("sensitivity_risk", table_cell_bold), Paragraph("Sensitive Data AI", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("Max sensitivity score across accessed files, content bodies, and credentials.", table_cell)],
        [Paragraph("leakage_chain_score", table_cell_bold), Paragraph("Temporal Correlator", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("Multi-stage attack chain score matching sequential Recon->Access->Staging->Egress.", table_cell)],
        [Paragraph("graph_risk", table_cell_bold), Paragraph("Provenance Graph", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("Topological reachability score from sensitive entity to network socket / device.", table_cell)],
        [Paragraph("historical_user_risk", table_cell_bold), Paragraph("Behavior Baseline", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("User historical moving average anomaly deviation over prior 30-day windows.", table_cell)],
        [Paragraph("usb_activity", table_cell_bold), Paragraph("Device Telemetry", table_cell), Paragraph("Integer", table_cell), Paragraph("[0, inf)", table_cell), Paragraph("Count of USB/flash memory connect and write events during evaluation window.", table_cell)],
        [Paragraph("behavior_risk", table_cell_bold), Paragraph("Behavior AI", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("Context-scaled Isolation Forest anomaly score from CERT daily activity metrics.", table_cell)],
        [Paragraph("after_hours_activity", table_cell_bold), Paragraph("Temporal Telemetry", table_cell), Paragraph("Integer", table_cell), Paragraph("[0, inf)", table_cell), Paragraph("Total event count executed outside official business hours (18:00 - 08:00 / weekend).", table_cell)],
        [Paragraph("external_destination", table_cell_bold), Paragraph("Network Telemetry", table_cell), Paragraph("Binary", table_cell), Paragraph("{0, 1}", table_cell), Paragraph("Indicator flag (1 = network egress to public cloud, dropbox, external domain).", table_cell)],
        [Paragraph("destination_risk", table_cell_bold), Paragraph("Web/HTTP Telemetry", table_cell), Paragraph("Float", table_cell), Paragraph("[0.0, 100.0]", table_cell), Paragraph("Reputation risk score of destination URL, IP, or cloud service endpoint.", table_cell)],
        [Paragraph("new_device", table_cell_bold), Paragraph("Device Telemetry", table_cell), Paragraph("Binary", table_cell), Paragraph("{0, 1}", table_cell), Paragraph("Indicator flag: host or USB hardware identifier not previously recorded for user.", table_cell)],
    ]
    t_feat = Table(features_table, colWidths=[90, 80, 45, 60, 229])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 6. EXPLAINABLE AI & SHAP VALUES
    # =========================================================================
    story.append(Paragraph("6. Explainable AI & Empirical SHAP Feature Importance", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    story.append(Paragraph(
        "LeakMind implements <b>TreeSHAP</b> to compute exact Shapley attributions for each prediction. "
        "Across the complete enterprise evaluation cohort (N = 140 ground-truth scenarios), global feature importance is ranked as follows:",
        body_style
    ))

    shap_table = [
        [Paragraph("Rank", table_header), Paragraph("Feature Name", table_header), Paragraph("Semantic Label", table_header), Paragraph("Mean |SHAP|", table_header), Paragraph("Relative Importance", table_header), Paragraph("Primary Direction", table_header)],
        [Paragraph("1", table_cell_bold), Paragraph("sensitivity_risk", table_cell), Paragraph("Sensitive file access", table_cell), Paragraph("1.3584", table_cell_bold), Paragraph("35.05%", table_cell_bold), Paragraph("Risk Mitigator / Driver", table_cell)],
        [Paragraph("2", table_cell_bold), Paragraph("leakage_chain_score", table_cell), Paragraph("Multi-stage leakage chain", table_cell), Paragraph("1.2558", table_cell_bold), Paragraph("32.41%", table_cell_bold), Paragraph("Risk Mitigator / Driver", table_cell)],
        [Paragraph("3", table_cell_bold), Paragraph("graph_risk", table_cell), Paragraph("Provenance graph risk", table_cell), Paragraph("0.6793", table_cell_bold), Paragraph("17.53%", table_cell_bold), Paragraph("Risk Mitigator / Driver", table_cell)],
        [Paragraph("4", table_cell_bold), Paragraph("historical_user_risk", table_cell), Paragraph("Historical activity deviation", table_cell), Paragraph("0.3492", table_cell), Paragraph("9.01%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("5", table_cell_bold), Paragraph("usb_activity", table_cell), Paragraph("USB device activity", table_cell), Paragraph("0.0847", table_cell), Paragraph("2.19%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("6", table_cell_bold), Paragraph("behavior_risk", table_cell), Paragraph("Behavioral anomaly score", table_cell), Paragraph("0.0793", table_cell), Paragraph("2.05%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("7", table_cell_bold), Paragraph("after_hours_activity", table_cell), Paragraph("After-hours behavior", table_cell), Paragraph("0.0380", table_cell), Paragraph("0.98%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("8", table_cell_bold), Paragraph("external_destination", table_cell), Paragraph("External cloud destination", table_cell), Paragraph("0.0275", table_cell), Paragraph("0.71%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("9", table_cell_bold), Paragraph("destination_risk", table_cell), Paragraph("Untrusted destination risk", table_cell), Paragraph("0.0035", table_cell), Paragraph("0.09%", table_cell), Paragraph("Risk Driver", table_cell)],
        [Paragraph("10", table_cell_bold), Paragraph("new_device", table_cell), Paragraph("New device connection", table_cell), Paragraph("0.0000", table_cell), Paragraph("0.00%", table_cell), Paragraph("Contextual", table_cell)],
    ]
    t_shap = Table(shap_table, colWidths=[30, 110, 120, 70, 85, 89])
    t_shap.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
    ]))
    story.append(t_shap)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 7. EMPIRICAL BENCHMARKS & ABLATION STUDY
    # =========================================================================
    story.append(Paragraph("7. Empirical Benchmark Results & Ablation Study", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    story.append(Paragraph("<b>Model Architecture Comparison (N = 35 Independent Holdout Test Set):</b>", h2_style))
    comp_table = [
        [Paragraph("Model Architecture", table_header), Paragraph("Accuracy", table_header), Paragraph("Precision", table_header), Paragraph("Recall", table_header), Paragraph("F1-Score", table_header), Paragraph("ROC-AUC", table_header), Paragraph("FPR", table_header)],
        [Paragraph("Logistic Regression", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.00%", table_cell)],
        [Paragraph("Random Forest", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.00%", table_cell)],
        [Paragraph("XGBoost (Production)", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("0.00%", table_cell_bold)],
    ]
    t_comp = Table(comp_table, colWidths=[120, 60, 60, 60, 64, 70, 70])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
    ]))
    story.append(t_comp)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Incremental Evidence Ablation Study:</b>", h2_style))
    ablation_table = [
        [Paragraph("Configuration", table_header), Paragraph("Evidence Included", table_header), Paragraph("Accuracy", table_header), Paragraph("Precision", table_header), Paragraph("Recall", table_header), Paragraph("F1", table_header), Paragraph("False Positive Rate", table_header)],
        [Paragraph("1. Behavior Only", table_cell_bold), Paragraph("Isolation Forest alone (5 features)", table_cell), Paragraph("0.9714", table_cell), Paragraph("0.9444", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.9714", table_cell), Paragraph("5.56% (1 False Alarm)", table_cell_bold)],
        [Paragraph("2. Behavior + Sensitivity", table_cell), Paragraph("+ Sensitive Content TF-IDF (6 features)", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.00% (0 False Alarms)", table_cell)],
        [Paragraph("3. Behavior + Sens + Graph", table_cell), Paragraph("+ Provenance Knowledge Graph (9 features)", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.00% (0 False Alarms)", table_cell)],
        [Paragraph("4. All Evidence + Temporal", table_cell), Paragraph("+ Multi-Stage Kill Chain (10 features)", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("1.0000", table_cell), Paragraph("0.00% (0 False Alarms)", table_cell)],
        [Paragraph("5. Full XGBoost Pipeline", table_cell_bold), Paragraph("Complete Calibrated Pipeline (10 features)", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("1.0000", table_cell_bold), Paragraph("0.00% (0 False Alarms)", table_cell_bold)],
    ]
    t_abl = Table(ablation_table, colWidths=[105, 125, 50, 50, 50, 44, 80])
    t_abl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
    ]))
    story.append(t_abl)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 8. POLICY ENGINE & AUTOMATED ACTIONS
    # =========================================================================
    story.append(Paragraph("8. Policy Engine Governance & Action Tiers", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    policy_table = [
        [Paragraph("Risk Tier", table_header), Paragraph("Score Boundary", table_header), Paragraph("Default Action", table_header), Paragraph("Enforcement Logic & Operational Response", table_header)],
        [Paragraph("LOW", table_cell_bold), Paragraph("Risk < 40%", table_cell), Paragraph("ALLOW", table_cell_bold), Paragraph("Permit operation normally; standard passive audit telemetry logged.", table_cell)],
        [Paragraph("MEDIUM", table_cell_bold), Paragraph("40% <= Risk < 70%", table_cell), Paragraph("MONITOR", table_cell_bold), Paragraph("Enable enhanced session recording; increase telemetry collection frequency.", table_cell)],
        [Paragraph("HIGH", table_cell_bold), Paragraph("70% <= Risk < 90%", table_cell), Paragraph("ALERT / APPROVAL", table_cell_bold), Paragraph("Dispatch high-priority alert to SOC analyst; require manager 2FA approval for file egress.", table_cell)],
        [Paragraph("CRITICAL", table_cell_bold), Paragraph("Risk >= 90%", table_cell), Paragraph("BLOCK", table_cell_bold), Paragraph("Immediate session kill, network interface isolation, revoke file access tokens.", table_cell)],
    ]
    t_pol = Table(policy_table, colWidths=[65, 80, 85, 274])
    t_pol.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 3.5),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
    ]))
    story.append(t_pol)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 9. TECHNICAL EXAMINATION & VIVA Q&A
    # =========================================================================
    story.append(Paragraph("9. Technical Viva / Examination Reference Guide", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceBefore=1, spaceAfter=5))

    qa_items = [
        (
            "Q1: Why choose Isolation Forest for Behavior AI instead of Autoencoders or One-Class SVM?",
            "Isolation Forest operates in O(n log n) linear time complexity and explicitly isolates outliers via random partitioning "
            "rather than attempting to model the dense distribution of normal behavior. In enterprise log telemetry, high dimensionality "
            "and concept drift cause One-Class SVM and Autoencoders to overfit or consume excessive GPU resources."
        ),
        (
            "Q2: Why use XGBoost for Risk Fusion rather than simple heuristic weighted averaging?",
            "Heuristic weighting assumes independent, linear contributions from each evidence source. In reality, data-leakage involves "
            "high-order non-linear interactions: after-hours work alone is benign, and accessing sensitive data alone is routine; "
            "only their joint confluence with USB or external egress signifies exfiltration. XGBoost captures these non-linear decision trees "
            "and directly supports exact TreeSHAP local attribution."
        ),
        (
            "Q3: What is the fundamental difference between Graph Risk and Temporal Chain Score?",
            "Graph Risk evaluates structural spatial provenance: which process spawned what, which file was read, and whether an egress path "
            "exists in the system topology. Temporal Chain Score evaluates sequential causality over time: verifying that events follow "
            "an attack kill chain lifecycle (Recon -> Access -> Staging -> Exfiltration) within bounded sliding windows."
        ),
        (
            "Q4: How does SHAP guarantee fair feature attribution in academic evaluations?",
            "SHAP is grounded in cooperative game theory (Lloyd Shapley, 1953) and is mathematically the only attribution framework that "
            "simultaneously satisfies four axiomatic properties: Efficiency (local contributions sum to prediction delta), Symmetry "
            "(identical contributors receive equal credit), Dummy (zero-impact features receive zero credit), and Additivity."
        ),
        (
            "Q5: How does LeakMind operate if optional datasets (e.g. DARPA TC) are missing?",
            "LeakMind enforces a Graceful Degradation Architecture. Each analytical engine is modularized behind an abstract interface. "
            "If an external corpus is absent, the corresponding engine flags status NOT_AVAILABLE and falls back to baseline priors without "
            "throwing unhandled runtime exceptions or crashing the dashboard."
        )
    ]

    for q, a in qa_items:
        story.append(Paragraph(f"<b>{q}</b>", h2_style))
        story.append(Paragraph(a, body_style))
        story.append(Spacer(1, 3))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF report: {output_pdf_path}")


if __name__ == "__main__":
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = str(out_dir / "LeakMind_Technical_Report.pdf")
    build_pdf(pdf_path)
