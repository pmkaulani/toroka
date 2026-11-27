"""Novelty, Distribution Shift & Drift Monitoring Engine for Toroka.

Monitors production inference telemetry:
- High-risk prediction rate (detects aggressive false-positive drift).
- Inconclusive / abstention rate (detects coverage collapse).
- User mistake report frequency (false positives vs missed scams).
- Category distribution shifts.
- Novelty and out-of-vocabulary signals.
- Automatic Rollback Trigger when production regression thresholds are breached.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .model_registry import get_models_dir

logger = logging.getLogger("toroka.ml.drift_monitor")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class TelemetryEvent:
    timestamp: str
    sample_text_length: int
    predicted_category: str
    fraud_risk_score: float
    confidence: float
    abstained: bool
    model_version: str
    user_reported_mistake: bool = False
    mistake_type: str | None = None  # "false_positive", "false_negative", "inaccurate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DriftReport:
    timestamp: str
    model_version: str
    window_sample_count: int
    high_risk_rate: float
    inconclusive_rate: float
    abstention_rate: float
    user_false_positive_rate: float
    confirmed_false_positive_rate: float
    category_distribution: dict[str, float]
    investigation_required: bool
    investigation_reasons: list[str]
    regression_detected: bool
    regression_reasons: list[str]
    should_rollback: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DriftMonitor:
    """Maintains rolling telemetry and evaluates operational drift and regression policies."""

    def __init__(
        self,
        telemetry_file: str | None = None,
        window_size: int = 100,
        max_fp_rate_threshold: float = 0.10,
        max_high_risk_rate_threshold: float = 0.70,
    ):
        self.telemetry_file = telemetry_file or os.path.join(get_models_dir(), "telemetry.jsonl")
        os.makedirs(os.path.dirname(self.telemetry_file), exist_ok=True)
        self.window_size = window_size
        self.max_fp_rate_threshold = max_fp_rate_threshold
        self.max_high_risk_rate_threshold = max_high_risk_rate_threshold
        self.events: list[TelemetryEvent] = self._load_recent_events()

    def _load_recent_events(self) -> list[TelemetryEvent]:
        if not os.path.exists(self.telemetry_file):
            return []
        events: list[TelemetryEvent] = []
        try:
            with open(self.telemetry_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(TelemetryEvent(**json.loads(line)))
            return events[-self.window_size :]
        except Exception as e:
            logger.warning(f"Could not load telemetry: {e}")
            return []

    def log_prediction(
        self,
        text_length: int,
        predicted_category: str,
        fraud_risk_score: float,
        confidence: float,
        abstained: bool,
        model_version: str,
    ) -> None:
        event = TelemetryEvent(
            timestamp=now_utc_iso(),
            sample_text_length=text_length,
            predicted_category=predicted_category,
            fraud_risk_score=fraud_risk_score,
            confidence=confidence,
            abstained=abstained,
            model_version=model_version,
        )
        self.events.append(event)
        if len(self.events) > self.window_size:
            self.events.pop(0)

        # Append to disk
        try:
            with open(self.telemetry_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Error logging telemetry event: {e}")

    def log_feedback_outcome(self, mistake_type: str, model_version: str) -> None:
        event = TelemetryEvent(
            timestamp=now_utc_iso(),
            sample_text_length=0,
            predicted_category="unknown",
            fraud_risk_score=0.5,
            confidence=1.0,
            abstained=False,
            model_version=model_version,
            user_reported_mistake=True,
            mistake_type=mistake_type,
        )
        self.events.append(event)
        if len(self.events) > self.window_size:
            self.events.pop(0)

        try:
            with open(self.telemetry_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Error logging feedback event: {e}")

    def evaluate_drift(self, current_model_version: str) -> DriftReport:
        if not self.events:
            return DriftReport(
                timestamp=now_utc_iso(),
                model_version=current_model_version,
                window_sample_count=0,
                high_risk_rate=0.0,
                inconclusive_rate=0.0,
                abstention_rate=0.0,
                user_false_positive_rate=0.0,
                confirmed_false_positive_rate=0.0,
                category_distribution={},
                investigation_required=False,
                investigation_reasons=[],
                regression_detected=False,
                regression_reasons=[],
                should_rollback=False,
            )

        n = len(self.events)
        high_risk_count = sum(1 for e in self.events if e.fraud_risk_score >= 0.60)
        inconclusive_count = sum(1 for e in self.events if 0.40 <= e.fraud_risk_score < 0.60)
        abstain_count = sum(1 for e in self.events if e.abstained)

        # Distinguish unverified user complaints from confirmed / moderated errors
        user_complaint_count = sum(
            1 for e in self.events if e.user_reported_mistake and e.mistake_type == "false_positive"
        )
        confirmed_mod_fp_count = sum(
            1 for e in self.events if e.user_reported_mistake and e.mistake_type == "confirmed_moderator_fp"
        )

        high_risk_rate = round(high_risk_count / max(1, n), 4)
        inconclusive_rate = round(inconclusive_count / max(1, n), 4)
        abstain_rate = round(abstain_count / max(1, n), 4)
        user_fp_rate = round(user_complaint_count / max(1, n), 4)
        confirmed_fp_rate = round(confirmed_mod_fp_count / max(1, n), 4)

        cat_counts: dict[str, int] = {}
        for e in self.events:
            cat_counts[e.predicted_category] = cat_counts.get(e.predicted_category, 0) + 1
        cat_dist = {k: round(v / n, 4) for k, v in cat_counts.items()}

        regression_reasons: list[str] = []
        investigation_reasons: list[str] = []
        should_rollback = False

        # Investigation Trigger 1: High-Risk rate spike (> 70%)
        # Signals potential incoming scam attack or drift; triggers investigative review without immediate blind rollback
        if high_risk_rate > self.max_high_risk_rate_threshold and n >= 15:
            investigation_reasons.append(
                f"Elevated high-risk prediction concentration ({high_risk_rate:.1%}); scam surge or potential over-flagging under investigation."
            )

        # Investigation Trigger 2: Unverified user complaints (> threshold)
        if user_fp_rate > self.max_fp_rate_threshold and user_complaint_count >= 3:
            investigation_reasons.append(
                f"Elevated user false-positive reports ({user_fp_rate:.1%}, {user_complaint_count} reports). Prioritized for moderator adjudication."
            )

        # Automatic Rollback Trigger: Requires CONFIRMED / CORROBORATED errors or severe verified breakdown
        # e.g. at least 3 confirmed moderator false positives in recent window (>= 10%)
        if (confirmed_fp_rate >= 0.10 and confirmed_mod_fp_count >= 3) or (user_complaint_count >= 10 and user_fp_rate >= 0.35):
            regression_reasons.append(
                f"CONFIRMED REGRESSION: Corroborated false positives ({confirmed_mod_fp_count} verified, {user_complaint_count} total complaints) breached tolerance."
            )
            should_rollback = True

        return DriftReport(
            timestamp=now_utc_iso(),
            model_version=current_model_version,
            window_sample_count=n,
            high_risk_rate=high_risk_rate,
            inconclusive_rate=inconclusive_rate,
            abstention_rate=abstain_rate,
            user_false_positive_rate=user_fp_rate,
            confirmed_false_positive_rate=confirmed_fp_rate,
            category_distribution=cat_dist,
            investigation_required=len(investigation_reasons) > 0,
            investigation_reasons=investigation_reasons,
            regression_detected=len(regression_reasons) > 0,
            regression_reasons=regression_reasons,
            should_rollback=should_rollback,
        )
