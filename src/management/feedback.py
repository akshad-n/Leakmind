"""
Analyst Feedback Loop & Self-Learning Adaptive Memory
Collects SOC verdicts (True Positive, False Positive) to adjust policy thresholds and train memory.
"""

import json
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional


@dataclass
class FeedbackRecord:
    feedback_id: str
    incident_id: str
    user: str
    analyst: str
    verdict: str           # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_EXCEPTION
    notes: str
    timestamp: float


class AnalystFeedbackEngine:
    """
    Self-learning feedback loop that adapts risk engine sensitivity based on analyst verdicts.
    """

    def __init__(self, memory_file: str = "data/processed/analyst_feedback.json"):
        self.memory_file = memory_file
        self.records: List[FeedbackRecord] = []
        self._load()

    def _load(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.records = [FeedbackRecord(**d) for d in data]
            except Exception:
                self.records = []

    def _save(self):
        os.makedirs(os.path.dirname(self.memory_file), exist_ok=True)
        with open(self.memory_file, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self.records], f, indent=2)

    def record_verdict(
        self,
        incident_id: str,
        user: str,
        analyst: str,
        verdict: str,
        notes: str = ""
    ) -> FeedbackRecord:
        record = FeedbackRecord(
            feedback_id=f"FB-{len(self.records)+1:04d}",
            incident_id=incident_id,
            user=user,
            analyst=analyst,
            verdict=verdict,
            notes=notes,
            timestamp=time.time()
        )
        self.records.append(record)
        self._save()
        return record

    def get_performance_stats(self) -> Dict[str, Any]:
        if not self.records:
            return {"total_reviews": 0, "tp_count": 0, "fp_count": 0, "precision_rate": 1.0}

        tp = sum(1 for r in self.records if r.verdict == "TRUE_POSITIVE")
        fp = sum(1 for r in self.records if r.verdict == "FALSE_POSITIVE")
        total = len(self.records)

        return {
            "total_reviews": total,
            "tp_count": tp,
            "fp_count": fp,
            "precision_rate": round(tp / (tp + fp) if (tp + fp) > 0 else 1.0, 4)
        }

    def compute_threshold_adjustment(self) -> float:
        """
        Dynamically suggests threshold offset (e.g. +2.0 or -2.0) based on false positive rates.
        """
        stats = self.get_performance_stats()
        if stats["total_reviews"] < 5:
            return 0.0

        fp_rate = stats["fp_count"] / stats["total_reviews"]
        if fp_rate > 0.20:
            return 5.0   # Increase threshold by 5 points to reduce false positives
        elif fp_rate < 0.05:
            return -2.0  # Slightly decrease threshold to catch more subtle attacks
        return 0.0
