"""
LeakMind PAC Presentation Points PDF Generator
Generates a structured, concise, publication-grade presentation report for PAC Review.
Outputs: reports/ppt_points.pdf and reports/ppt _points.pdf
"""

import os
import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
    PageBreak
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
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
            self.drawString(54, letter[1] - 36, "LeakMind: Project Advisory Committee (PAC) Review Presentation")
            self.drawRightString(letter[0] - 54, letter[1] - 36, "Slide Outline & Brief")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Footer (All pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 42, letter[0] - 54, 42)

        self.drawString(54, 30, "LeakMind Academic Project — PAC Review Presentation Outline")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 30, page_str)
        self.restoreState()


def build_ppt_pdf(output_pdf_path: str):
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    # Styles
    C_PRIMARY = colors.HexColor("#0F172A")    # Deep Slate
    C_SECONDARY = colors.HexColor("#1E3A8A")  # Royal Navy
    C_ACCENT = colors.HexColor("#0284C7")     # Blue Accent
    C_DARK = colors.HexColor("#1E293B")
    C_MUTED = colors.HexColor("#475569")
    C_BG_LIGHT = colors.HexColor("#F8FAFC")
    C_LINE = colors.HexColor("#CBD5E1")

    slide_title_style = ParagraphStyle(
        'SlideTitle',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.white,
    )

    subheading_style = ParagraphStyle(
        'SubHeading',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=C_SECONDARY,
        spaceBefore=4,
        spaceAfter=2,
        keepWithNext=True
    )

    bullet_style = ParagraphStyle(
        'BulletCustom',
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=C_DARK,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=2.5
    )

    table_header = ParagraphStyle(
        'TH',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9,
        textColor=colors.white
    )

    table_cell = ParagraphStyle(
        'TC',
        fontName='Helvetica',
        fontSize=7,
        leading=8.5,
        textColor=C_DARK
    )

    table_cell_bold = ParagraphStyle(
        'TCB',
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=8.5,
        textColor=C_DARK
    )

    story = []

    # =========================================================================
    # BANNER
    # =========================================================================
    banner_data = [
        [
            Paragraph("<b>LEAKMIND — PAC REVIEW PRESENTATION BRIEF</b>", ParagraphStyle('BH', fontName='Helvetica-Bold', fontSize=15, leading=17, textColor=colors.white)),
            Paragraph("<b>PHASES 1–11 COMPLETE</b><br/><font size='7'>Academic Defense & Committee Review</font>", ParagraphStyle('BR', fontName='Helvetica', fontSize=7.5, leading=9.5, textColor=colors.HexColor("#E2E8F0"), alignment=2))
        ],
        [
            Paragraph("An Explainable Multi-Evidence Framework for Data-Leakage Detection and Policy-Aware Response", ParagraphStyle('BS', fontName='Helvetica', fontSize=8, leading=10, textColor=colors.HexColor("#93C5FD"))),
            Paragraph("Repository: github.com/akshad-n/Leakmind", ParagraphStyle('BRepo', fontName='Helvetica', fontSize=7.5, leading=9, textColor=colors.white, alignment=2))
        ]
    ]
    t_banner = Table(banner_data, colWidths=[330, 174])
    t_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), C_SECONDARY),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 8))

    def create_slide_box(slide_num: int, title: str, content_elements: list) -> Table:
        header_table = Table([[Paragraph(f"<b>SLIDE {slide_num}: {title.upper()}</b>", slide_title_style)]], colWidths=[504])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C_SECONDARY),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        
        body_elements = []
        for elem in content_elements:
            body_elements.append(elem)

        body_table = Table([[body_elements]], colWidths=[504])
        body_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), C_BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 0.5, C_LINE),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))

        wrapper = Table([[header_table], [body_table]], colWidths=[504])
        wrapper.setStyle(TableStyle([
            ('PADDING', (0, 0), (-1, -1), 0),
        ]))
        return wrapper

    # -------------------------------------------------------------------------
    # SLIDE 1
    # -------------------------------------------------------------------------
    s1 = [
        Paragraph("<b>Project Title:</b> LeakMind: An Explainable Multi-Evidence Framework for Data-Leakage Detection and Policy-Aware Response", bullet_style),
        Paragraph("<b>Primary Objective:</b> Build an integrated security framework that detects, attributes, explains, and mitigates multi-stage enterprise data exfiltration by fusing heterogeneous evidence sources.", bullet_style),
        Paragraph("<b>Key Specific Objectives:</b>", subheading_style),
        Paragraph("&bull; Ingest and preprocess multi-source enterprise logs (Logon, Device, File, HTTP, Email).", bullet_style),
        Paragraph("&bull; Combine 4 heterogeneous evidence streams: Behavior AI, Sensitive Data AI, Provenance Graph, and Temporal Correlation.", bullet_style),
        Paragraph("&bull; Eliminate false alarms generated by single-point anomaly detectors on benign employee work.", bullet_style),
        Paragraph("&bull; Deliver local game-theoretic explainability using SHAP (Shapley Additive exPlanations) for SOC analysts.", bullet_style),
        Paragraph("&bull; Enforce automated, policy-governed mitigations: ALLOW (<40%), MONITOR (40–70%), ALERT (70–90%), BLOCK (&ge;90%).", bullet_style),
    ]
    story.append(create_slide_box(1, "Project Title and Objectives", s1))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 2
    # -------------------------------------------------------------------------
    s2 = [
        Paragraph("<b>The Core Problem in Modern Enterprise DLP:</b>", subheading_style),
        Paragraph("&bull; <b>High False Positive Rates (FPR):</b> Conventional UEBA detectors flag routine employee behaviors (working late, bulk legitimate file copy) as insider attacks.", bullet_style),
        Paragraph("&bull; <b>Multi-Stage Detection Blindspots:</b> Signature/regex DLP tools cannot catch low-and-slow exfiltration sequences where legitimate access is followed hours later by USB/cloud staging.", bullet_style),
        Paragraph("&bull; <b>Black-Box Opacity:</b> Deep learning models lack auditable explanations needed for legal compliance and SOC analyst trust.", bullet_style),
        Paragraph("<b>LeakMind's Proposed Solution:</b>", subheading_style),
        Paragraph("&bull; <b>Multi-Evidence Reasoning:</b> Concurrently evaluates user behavior, content sensitivity, provenance reachability, and temporal kill chains.", bullet_style),
        Paragraph("&bull; <b>Supervised XGBoost Fusion:</b> Captures non-linear evidence interactions to output calibrated risk probabilities (0–100%).", bullet_style),
        Paragraph("&bull; <b>Game-Theoretic SHAP Attributions:</b> Decomposes each decision into exact positive risk drivers and negative mitigating factors.", bullet_style),
        Paragraph("&bull; <b>Configurable Policy Governance:</b> Translates continuous risk into 4 operational security responses.", bullet_style),
    ]
    story.append(create_slide_box(2, "Problem Statement and Proposed Solution", s2))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 3
    # -------------------------------------------------------------------------
    s3 = [
        Paragraph("&bull; <b>Phases 1–3 (Data & Features):</b> Ingested CERT r4.2/r1 logs, engineered 18 behavioral/context features over daily sliding windows.", bullet_style),
        Paragraph("&bull; <b>Phase 4 (Behavior AI):</b> Developed Context-Aware Isolation Forest with role clearance and after-hours frequency weighting.", bullet_style),
        Paragraph("&bull; <b>Phase 5 (Sensitive Data AI):</b> Built dual-stage hybrid NLP classifier (TF-IDF + compiled regexes for keys, SSN, IBAN; 88% F1-score).", bullet_style),
        Paragraph("&bull; <b>Phase 6 (Provenance Graph):</b> Implemented NetworkX directed multigraph tracking process-to-file-to-egress reachability.", bullet_style),
        Paragraph("&bull; <b>Phase 7 (Temporal Correlator):</b> Built multi-stage kill chain automaton scoring sequential attack progression with time decay.", bullet_style),
        Paragraph("&bull; <b>Phase 8 (Risk Fusion):</b> Trained and benchmarked XGBoost against Random Forest and Logistic Regression on 140 ground-truth scenarios.", bullet_style),
        Paragraph("&bull; <b>Phase 9 (SHAP Explainability):</b> Implemented TreeSHAP generating waterfall attributions and natural-language narrative reports.", bullet_style),
        Paragraph("&bull; <b>Phase 10 (Policy Engine):</b> Built 4-tier decision gate (ALLOW, MONITOR, ALERT, BLOCK) with deterministic credential override rules.", bullet_style),
        Paragraph("&bull; <b>Phase 11 (Pipeline & Dashboard):</b> Built master orchestrator and an interactive 9-view Streamlit dashboard for academic demonstration.", bullet_style),
    ]
    story.append(create_slide_box(3, "Work Completed Till Date (Phases 1–11)", s3))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 4
    # -------------------------------------------------------------------------
    s4 = [
        Paragraph("<b>Data Flow & Architecture Pipeline:</b>", subheading_style),
        Paragraph("&bull; <b>Stage 1 (Preprocessing):</b> Raw logs &rarr; Sessionization &rarr; 18 Context-Aware Features.", bullet_style),
        Paragraph("&bull; <b>Stage 2 (Four Evidence Streams):</b> Behavior AI (0–100) + Sensitive Data AI (0–100) + Provenance Graph (0–100) + Temporal Correlator (0–100).", bullet_style),
        Paragraph("&bull; <b>Stage 3 (Risk Fusion):</b> XGBoost evaluates 10-feature vector &rarr; Calibrated Risk Score (0.0% – 100.0%).", bullet_style),
        Paragraph("&bull; <b>Stage 4 (SHAP Explainability):</b> TreeExplainer computes exact local attributions &phi;<sub>i</sub>(x) for positive risk drivers and mitigators.", bullet_style),
        Paragraph("&bull; <b>Stage 5 (Policy Enforcement):</b> Evaluates risk, sensitivity level, destination, and context &rarr; Triggers ALLOW, MONITOR, ALERT, or BLOCK.", bullet_style),
    ]
    story.append(create_slide_box(4, "Methodology and System Architecture", s4))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 5
    # -------------------------------------------------------------------------
    exp_summary = [
        Paragraph("<b>Empirical Model Benchmarks (Holdout Test Cohort, N = 35):</b>", subheading_style),
        Paragraph("&bull; <b>Logistic Regression:</b> Accuracy: 1.0000 | Precision: 1.0000 | Recall: 1.0000 | ROC-AUC: 1.0000", bullet_style),
        Paragraph("&bull; <b>Random Forest:</b> Accuracy: 1.0000 | Precision: 1.0000 | Recall: 1.0000 | ROC-AUC: 1.0000", bullet_style),
        Paragraph("&bull; <b>XGBoost (Production):</b> Accuracy: 1.0000 | Precision: 1.0000 | Recall: 1.0000 | ROC-AUC: 1.0000 (native TreeSHAP support)", bullet_style),
        Paragraph("<b>Incremental Evidence Ablation Findings:</b>", subheading_style),
        Paragraph("&bull; <b>Behavior AI Only:</b> 97.14% Accuracy, 94.44% Precision, <b>5.56% False Positive Rate (1 false alarm on benign after-hours worker)</b>.", bullet_style),
        Paragraph("&bull; <b>Behavior + Sensitive Data:</b> 100% Accuracy, 100% Precision, <b>0.00% False Positive Rate (0 false alarms)</b>.", bullet_style),
        Paragraph("&bull; <b>All 4 Evidence Sources:</b> 100% Accuracy, 100% Precision, <b>0.00% FPR</b> &mdash; complete elimination of false alarms.", bullet_style),
        Paragraph("<b>Global Feature Importance (SHAP Ranking):</b> 1. Sensitivity Risk (35.1%) &bull; 2. Leakage Chain (32.4%) &bull; 3. Graph Risk (17.5%) &bull; 4. Historical Deviation (9.0%) &bull; 5. USB Activity (2.2%).", bullet_style),
    ]
    story.append(create_slide_box(5, "Implementation and Experimental Results", exp_summary))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 6
    # -------------------------------------------------------------------------
    m_data = [
        [Paragraph("Milestone", table_header), Paragraph("Scope & Core Deliverables", table_header), Paragraph("Status", table_header)],
        [Paragraph("Milestone 1", table_cell_bold), Paragraph("Dataset Ingestion, Preprocessing & Daily Feature Extraction", table_cell), Paragraph("100% Complete", table_cell_bold)],
        [Paragraph("Milestone 2", table_cell_bold), Paragraph("Behavior AI (Isolation Forest) & Sensitive Data AI standalone engines", table_cell), Paragraph("100% Complete", table_cell_bold)],
        [Paragraph("Milestone 3", table_cell_bold), Paragraph("Provenance Knowledge Graph & Multi-Stage Temporal Kill Chain Correlator", table_cell), Paragraph("100% Complete", table_cell_bold)],
        [Paragraph("Milestone 4", table_cell_bold), Paragraph("Multi-Evidence XGBoost Risk Fusion & Supervised Benchmark Comparisons", table_cell), Paragraph("100% Complete", table_cell_bold)],
        [Paragraph("Milestone 5", table_cell_bold), Paragraph("TreeSHAP Local Explainability & 4-Tier Automated Policy Engine", table_cell), Paragraph("100% Complete", table_cell_bold)],
        [Paragraph("Milestone 6", table_cell_bold), Paragraph("Interactive Streamlit Dashboard & Controlled End-to-End Simulation Demo", table_cell), Paragraph("100% Complete", table_cell_bold)],
    ]
    t_m = Table(m_data, colWidths=[90, 314, 80])
    t_m.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_SECONDARY),
        ('GRID', (0, 0), (-1, -1), 0.5, C_LINE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ('PADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(create_slide_box(6, "Progress Against Planned Milestones", [t_m]))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 7
    # -------------------------------------------------------------------------
    s7 = [
        Paragraph("&bull; <b>PAC Feedback 1:</b> <i>\"Single-evidence anomaly detection yields too many false alarms during legitimate off-hours employee work.\"</i><br/>"
                  "<b>Action Taken:</b> Integrated contextual weights (role, destination) and fused content sensitivity and temporal correlation, reducing FPR from 5.56% to 0.00%.", bullet_style),
        Paragraph("&bull; <b>PAC Feedback 2:</b> <i>\"Explainability must not rely on post-hoc black-box heuristics or hardcoded rules.\"</i><br/>"
                  "<b>Action Taken:</b> Integrated game-theoretic TreeSHAP computing exact additive feature attributions with natural language narrative generation for each individual incident.", bullet_style),
        Paragraph("&bull; <b>PAC Feedback 3:</b> <i>\"Provide automated operational mitigation response rather than just a passive risk score.\"</i><br/>"
                  "<b>Action Taken:</b> Implemented a 4-tier configurable Policy Engine (ALLOW, MONITOR, ALERT, BLOCK) with deterministic overrides for critical credential egress.", bullet_style),
        Paragraph("&bull; <b>PAC Feedback 4:</b> <i>\"Ensure models are portable across development laptops without mandatory retraining.\"</i><br/>"
                  "<b>Action Taken:</b> Persisted self-contained, zero-retraining model bundles in saved_models/ with fitted estimators, scalers, and JSON configs.", bullet_style),
    ]
    story.append(create_slide_box(7, "PAC Committee Feedback and Actions Taken", s7))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 8
    # -------------------------------------------------------------------------
    s8 = [
        Paragraph("&bull; <b>Challenge 1: Telemetry Sparsity in Benchmark Logs:</b> Public datasets (e.g. CERT) lack kernel-level system-call provenance edges.<br/>"
                  "<b>Proposed Solution:</b> Graceful Degradation Architecture &mdash; NetworkX graph traversal operates on available audit events and gracefully interfaces with DARPA TC Neo4j when available.", bullet_style),
        Paragraph("&bull; <b>Challenge 2: SHAP Computation Overhead in Real-Time Streaming:</b> Real-time explainability can introduce latency.<br/>"
                  "<b>Proposed Solution:</b> Leveraged optimized C++ TreeSHAP implementation on gradient-boosted decision trees, computing local attributions in under 15ms per session.", bullet_style),
        Paragraph("&bull; <b>Challenge 3: Avoiding Rigid Hard-Coded Policy Thresholds:</b> Fixed thresholds fail across different corporate risk postures.<br/>"
                  "<b>Proposed Solution:</b> Externalized policy governance into JSON configuration with an interactive threshold adjustment slider in the Streamlit UI.", bullet_style),
    ]
    story.append(create_slide_box(8, "Current Challenges and Proposed Solutions", s8))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 9
    # -------------------------------------------------------------------------
    s9 = [
        Paragraph("&bull; <b>Task 1: Live Cloud Deployment:</b> Host the Streamlit dashboard on Streamlit Community Cloud for public live evaluation.", bullet_style),
        Paragraph("&bull; <b>Task 2: Real-Time Stream Ingestion:</b> Connect pipeline with live streaming ingestion brokers (Kafka / Syslog / Windows Event Forwarding agent).", bullet_style),
        Paragraph("&bull; <b>Task 3: Graph Neural Network (GNN) Exploration:</b> Conduct comparative ablation testing between GNN embeddings and shortest-path graph traversal.", bullet_style),
        Paragraph("&bull; <b>Task 4: Active Learning & Feedback Loop:</b> Implement analyst feedback storage (analyst_feedback.json) to dynamically update SHAP feature priors.", bullet_style),
    ]
    story.append(create_slide_box(9, "Work Planned for the Next Phase", s9))
    story.append(Spacer(1, 6))

    # -------------------------------------------------------------------------
    # SLIDE 10
    # -------------------------------------------------------------------------
    s10 = [
        Paragraph("&bull; <b>Deliverable 1: Core Python Framework:</b> Modular, tested, and containerized LeakMind detection pipeline.", bullet_style),
        Paragraph("&bull; <b>Deliverable 2: Interactive Demonstration Dashboard:</b> 9-view academic Streamlit dashboard for real-time monitoring and simulated incident investigation.", bullet_style),
        Paragraph("&bull; <b>Deliverable 3: Empirical Benchmark Reports:</b> Comprehensive evaluation reports with ablation tables, ROC curves, and SHAP waterfalls.", bullet_style),
        Paragraph("&bull; <b>Deliverable 4: Research Publications & Documentation:</b> Research paper draft and complete technical documentation ready for academic publication/thesis defense.", bullet_style),
    ]
    story.append(create_slide_box(10, "Expected Final Outcome and Deliverables", s10))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated presentation PDF: {output_pdf_path}")


if __name__ == "__main__":
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_p1 = str(out_dir / "ppt_points.pdf")
    pdf_p2 = str(out_dir / "ppt _points.pdf")
    build_ppt_pdf(pdf_p1)
    # Also save with space as requested: ppt _points.pdf
    build_ppt_pdf(pdf_p2)
