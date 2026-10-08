"""
LeakMind Phase 5: Sensitive Data Model Training & Benchmark Evaluation
Trains the lightweight NLP sensitive content classifier on the sensitive-data corpus,
evaluates rule-based, classifier, and hybrid detection against ground-truth labels,
and exports all portable model artifacts to saved_models/sensitivity/.

Operates completely independently from the CERT behavior module.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.sensitivity import (
    DataSensitivityClassifier,
    SensitiveRuleEngine,
    SensitivityLevel
)
from src.utils.logger import get_logger

logger = get_logger("leakmind.train_sensitivity")


def train_and_evaluate_sensitivity(
    data_path: str = "data/raw/pii/sensitive_data.csv",
    save_dir: str = "saved_models/sensitivity",
    reports_dir: str = "reports"
):
    print("=" * 75)
    print("LEAKMIND PHASE 5: SENSITIVE DATA DETECTION TRAINING & BENCHMARK")
    print("=" * 75)

    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    rep_path = Path(reports_dir)
    rep_path.mkdir(parents=True, exist_ok=True)

    # 1. Ingest Sensitive Data Corpus
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Sensitive data corpus not found at: {data_path}")

    print(f"[1/4] Ingesting sensitive dataset from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"      Total records loaded: {len(df):,} samples across {df.shape[1]} columns")
    print(f"      Class distribution:\n{df['ground_truth_level'].value_counts().to_string()}")

    # 2. Train Lightweight Classifier Component
    print("\n[2/4] Training TF-IDF Lightweight Classifier...")
    detector = DataSensitivityClassifier(model_dir=str(save_path))
    detector.train(texts=df["text"].tolist(), labels=df["ground_truth_level"].tolist())

    # 3. Save Portable Model Artifacts
    print("\n[3/4] Exporting model bundle to saved_models/sensitivity/...")
    saved_artifacts = detector.save_model(str(save_path))
    for k, v in saved_artifacts.items():
        print(f"  [+] Saved {k:16s} -> {Path(v).name}")

    # 4. Evaluate Detection Performance Against Ground Truth
    print("\n[4/4] Evaluating Detection Approaches on Ground Truth...")

    # A. Rule Engine Alone
    rule_engine = SensitiveRuleEngine()
    rule_preds = []
    for txt in df["text"]:
        res = rule_engine.evaluate_text(str(txt))
        score = res["aggregate_rule_score"]
        if score >= 85.0:
            rule_preds.append("CRITICAL")
        elif score >= 60.0:
            rule_preds.append("HIGH")
        elif score >= 30.0:
            rule_preds.append("MEDIUM")
        else:
            rule_preds.append("LOW")

    # B. Hybrid Engine (Rule + Classifier)
    hybrid_preds = []
    hybrid_scores = []
    for txt in df["text"]:
        score, level, entities = detector.analyze_content(str(txt))
        hybrid_scores.append(score)
        hybrid_preds.append(level.value)

    y_true = df["ground_truth_level"].values

    rule_acc = accuracy_score(y_true, rule_preds)
    rule_f1 = f1_score(y_true, rule_preds, average="weighted", zero_division=0)

    hybrid_acc = accuracy_score(y_true, hybrid_preds)
    hybrid_f1 = f1_score(y_true, hybrid_preds, average="weighted", zero_division=0)

    print("\n" + "-" * 60)
    print("DETECTION ACCURACY & F1 COMPARISON:")
    print("-" * 60)
    print(f"  Rule Engine Alone : Accuracy = {rule_acc:.4f} ({rule_acc*100:.1f}%), Weighted F1 = {rule_f1:.4f}")
    print(f"  Hybrid Engine     : Accuracy = {hybrid_acc:.4f} ({hybrid_acc*100:.1f}%), Weighted F1 = {hybrid_f1:.4f}")

    print("\n" + "-" * 60)
    print("HYBRID ENGINE CLASSIFICATION REPORT (ALL 4 LEVELS):")
    print("-" * 60)
    report_dict = classification_report(y_true, hybrid_preds, output_dict=True, zero_division=0)
    print(classification_report(y_true, hybrid_preds, zero_division=0))

    # Confusion matrix
    classes = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cm = confusion_matrix(y_true, hybrid_preds, labels=classes)
    print("Confusion Matrix (Rows=True, Cols=Predicted):")
    print(f"Labels: {classes}")
    for i, row in enumerate(cm):
        print(f"  {classes[i]:8s}: {row.tolist()}")

    # Export Evaluation Report
    eval_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "dataset_samples": len(df),
        "rule_engine": {
            "accuracy": round(rule_acc, 4),
            "weighted_f1": round(rule_f1, 4)
        },
        "hybrid_engine": {
            "accuracy": round(hybrid_acc, 4),
            "weighted_f1": round(hybrid_f1, 4),
            "detailed_metrics": report_dict,
            "confusion_matrix": cm.tolist()
        }
    }

    report_file1 = save_path / "sensitivity_evaluation_report.json"
    report_file2 = rep_path / "sensitivity_evaluation_report.json"
    with open(report_file1, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)
    with open(report_file2, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    print(f"\n[+] Saved evaluation report to: {report_file1}")
    print(f"[+] Saved evaluation report to: {report_file2}")
    print("=" * 75)
    print("PHASE 5 SENSITIVE DATA MODULE TRAINING COMPLETE!")
    print("=" * 75)


if __name__ == "__main__":
    train_and_evaluate_sensitivity()
