"""
LeakMind Phase 5: Sensitive Data Inference Engine
Loads the pre-trained sensitivity bundle and performs classification on input payloads.
Strictly ZERO RETRAINING during inference.

Outputs:
- sensitivity_score (0.0 - 100.0)
- sensitivity_level (LOW, MEDIUM, HIGH, CRITICAL)
- detected_entities (list of detected PII, credentials, or sensitive markers)

Operates completely independently from CERT.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.sensitivity import (
    DataSensitivityClassifier,
    SensitivityLevel
)
from src.utils.logger import get_logger

logger = get_logger("leakmind.predict_sensitivity")


class SensitivityPredictor:
    """
    Inference runner for sensitive data & PII content analysis.
    """

    def __init__(self, model_dir: str = "saved_models/sensitivity"):
        self.model_dir = model_dir
        self.detector = DataSensitivityClassifier(model_dir=model_dir)

    def predict_text(self, text: str) -> Dict[str, any]:
        score, level, entities = self.detector.analyze_content(text)
        return {
            "text_snippet": text[:80] + ("..." if len(text) > 80 else ""),
            "sensitivity_score": score,
            "sensitivity_level": level.value,
            "detected_entities": entities
        }

    def predict_file(self, file_path: str) -> pd.DataFrame:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if path.suffix.lower() == ".csv":
            df = pd.read_csv(path)
            # Find candidate text column
            text_cols = [c for c in ["text", "content", "payload", "message"] if c in df.columns]
            col = text_cols[0] if text_cols else df.columns[0]
            return self.detector.evaluate_dataframe(df, text_col=col)
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            res = self.predict_text(content)
            return pd.DataFrame([res])


def main():
    parser = argparse.ArgumentParser(description="LeakMind Sensitive Data & PII Predictor")
    parser.add_argument("--text", type=str, default=None, help="Input raw text string to analyze")
    parser.add_argument("--input", type=str, default=None, help="Input CSV or text file to analyze")
    parser.add_argument("--output", type=str, default=None, help="Optional output CSV path")
    parser.add_argument("--model-dir", type=str, default="saved_models/sensitivity", help="Sensitivity model directory")
    args = parser.parse_args()

    print("=" * 75)
    print("LEAKMIND SENSITIVE DATA INFERENCE (INDEPENDENT FROM CERT)")
    print("=" * 75)

    predictor = SensitivityPredictor(model_dir=args.model_dir)

    if args.text:
        res = predictor.predict_text(args.text)
        print(f"Input Text Snippet : {res['text_snippet']}")
        print(f"Sensitivity Score  : {res['sensitivity_score']:.2f} / 100.0")
        print(f"Sensitivity Level  : {res['sensitivity_level']}")
        print(f"Detected Entities  : {res['detected_entities']}")

    elif args.input:
        print(f"Analyzing content from: {args.input}")
        df_res = predictor.predict_file(args.input)
        print("\nResults Preview:")
        cols = [c for c in ["id", "category", "sensitivity_score", "sensitivity_level", "detected_entities"] if c in df_res.columns]
        if not cols:
            cols = df_res.columns
        print(df_res[cols].head(10).to_string(index=False))

        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            df_res.to_csv(out_p, index=False)
            print(f"\nSaved predictions to: {out_p}")
    else:
        # Default smoke test demonstration across all 4 levels
        sample_queries = [
            "Normal documentation: install dependencies using pip install -r requirements.txt",
            "Customer phone number is +1 (555) 234-5678 and email is customer@domain.com",
            "CONFIDENTIAL: Project Titan merger agreement between Company A and Target Corp.",
            "Database secret: postgresql://admin:SuperSecretPassword2026@internal-db:5432/finance",
            "Customer payment: Visa 4532 8912 3456 7890 Exp: 12/28 CVV 492 with SSN 123-45-6789"
        ]
        print("No input specified. Executing multi-category verification suite:\n")
        results = [predictor.predict_text(q) for q in sample_queries]
        df_demo = pd.DataFrame(results)
        print(df_demo[["text_snippet", "sensitivity_score", "sensitivity_level", "detected_entities"]].to_string(index=False))

    print("=" * 75)


if __name__ == "__main__":
    main()
