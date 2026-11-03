"""Configuration and validation for Toroka's Autonomous ML Engine.

Controls:
- Autonomous data acquisition
- Continuous dataset management & snapshotting
- Automated training triggers and thresholds
- Evaluation acceptance gates and auto-promotion
- Shadow mode evaluation and regression drift monitoring
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AutonomousMLConfig:
    auto_ingest_enabled: bool = True
    auto_train_enabled: bool = True
    auto_promote_enabled: bool = True
    train_interval_hours: float = 6.0
    min_new_eligible_samples: int = 5
    min_class_samples: int = 2
    max_pseudo_label_ratio: float = 0.20
    max_training_runtime_seconds: int = 300
    min_evaluation_support: int = 10
    min_category_eval_support: int = 5  # Strict per-category minimum test support required to replace champion
    monitoring_window_hours: int = 24
    max_resource_usage: float = 0.80
    data_retention_days: int = 90
    max_retries: int = 3
    shadow_mode_enabled: bool = True  # Default to shadow mode for newly trained candidates until scale verified

    # Dynamic pause switch (can be toggled at runtime)
    is_paused: bool = False
    pause_reason: str | None = None

    @classmethod
    def from_env(cls) -> "AutonomousMLConfig":
        g = os.environ.get

        def _b(k: str, default: bool) -> bool:
            v = g(k)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        def _i(k: str, default: int) -> int:
            v = g(k)
            if v is None:
                return default
            try:
                return int(v.strip())
            except ValueError:
                return default

        def _f(k: str, default: float) -> float:
            v = g(k)
            if v is None:
                return default
            try:
                return float(v.strip())
            except ValueError:
                return default

        return cls(
            auto_ingest_enabled=_b("ML_AUTO_INGEST_ENABLED", True),
            auto_train_enabled=_b("ML_AUTO_TRAIN_ENABLED", True),
            auto_promote_enabled=_b("ML_AUTO_PROMOTE_ENABLED", True),
            train_interval_hours=_f("ML_TRAIN_INTERVAL_HOURS", 6.0),
            min_new_eligible_samples=_i("ML_MIN_NEW_ELIGIBLE_SAMPLES", 5),
            min_class_samples=_i("ML_MIN_CLASS_SAMPLES", 2),
            max_pseudo_label_ratio=_f("ML_MAX_PSEUDO_LABEL_RATIO", 0.20),
            max_training_runtime_seconds=_i("ML_MAX_TRAINING_RUNTIME_SECONDS", 300),
            min_evaluation_support=_i("ML_MIN_EVALUATION_SUPPORT", 10),
            min_category_eval_support=_i("ML_MIN_CATEGORY_EVAL_SUPPORT", 5),
            monitoring_window_hours=_i("ML_MONITORING_WINDOW_HOURS", 24),
            max_resource_usage=_f("ML_MAX_RESOURCE_USAGE", 0.80),
            data_retention_days=_i("ML_DATA_RETENTION_DAYS", 90),
            max_retries=_i("ML_MAX_RETRIES", 3),
            shadow_mode_enabled=_b("ML_SHADOW_MODE_ENABLED", True),
        )

    def validate(self) -> tuple[bool, list[str]]:
        """Validate configuration settings and operational constraints."""
        errors: list[str] = []
        if self.min_new_eligible_samples < 1:
            errors.append("min_new_eligible_samples must be at least 1")
        if not (0.0 <= self.max_pseudo_label_ratio <= 0.50):
            errors.append("max_pseudo_label_ratio must be between 0.0 and 0.50")
        if self.train_interval_hours <= 0:
            errors.append("train_interval_hours must be positive")
        if self.max_training_runtime_seconds < 10:
            errors.append("max_training_runtime_seconds must be >= 10s")
        if not (0.1 <= self.max_resource_usage <= 1.0):
            errors.append("max_resource_usage must be between 0.1 and 1.0")

        return len(errors) == 0, errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "auto_ingest_enabled": self.auto_ingest_enabled,
            "auto_train_enabled": self.auto_train_enabled,
            "auto_promote_enabled": self.auto_promote_enabled,
            "train_interval_hours": self.train_interval_hours,
            "min_new_eligible_samples": self.min_new_eligible_samples,
            "min_class_samples": self.min_class_samples,
            "max_pseudo_label_ratio": self.max_pseudo_label_ratio,
            "max_training_runtime_seconds": self.max_training_runtime_seconds,
            "min_evaluation_support": self.min_evaluation_support,
            "min_category_eval_support": self.min_category_eval_support,
            "monitoring_window_hours": self.monitoring_window_hours,
            "max_resource_usage": self.max_resource_usage,
            "data_retention_days": self.data_retention_days,
            "max_retries": self.max_retries,
            "shadow_mode_enabled": self.shadow_mode_enabled,
            "is_paused": self.is_paused,
            "pause_reason": self.pause_reason,
        }
