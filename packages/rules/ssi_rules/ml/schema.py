"""Data structures and schemas for Toroka's Machine Learning & Intelligence Pipeline.

Strictly preserves data governance:
- No raw passwords, PINs, OTPs, or private identity credentials stored.
- Explicit distinction between pattern prediction, evidence strength, and assessment policy.
- Group-aware keys (incident_id, template_hash) prevent train/test leakage.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class SampleType(StrEnum):
    TEXT = "text"
    SMS = "sms"
    CHAT = "chat"
    SCREENSHOT_OCR = "screenshot_ocr"
    PROFILE = "profile"
    URL = "url"
    PAYMENT = "payment"
    OTHER = "other"


class Language(StrEnum):
    EN = "en"
    SW = "sw"
    SHENG = "sheng"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class Provenance(StrEnum):
    SYNTHETIC = "synthetic"
    CONSENTED_USER = "consented_user"
    PUBLIC_ADVISORY = "public_advisory"
    EXPERT_CURATED = "expert_curated"
    MODEL_PSEUDO_LABEL = "model_pseudo_label"
    RULE_HEURISTIC = "rule_heuristic"
    UNVERIFIED_COMMUNITY = "unverified_community"


class AdjudicationStatus(StrEnum):
    UNREVIEWED = "unreviewed"
    REVIEWER_APPROVED = "reviewer_approved"
    CONSENSUS = "consensus"
    REJECTED = "rejected"


class ReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED_FOR_TRAINING = "approved_for_training"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compute_template_hash(text: str) -> str:
    """Normalize whitespace, digits and case to cluster near-identical templates."""
    clean = re.sub(r"\d+", "<NUM>", text.strip().lower())
    clean = re.sub(r"https?://\S+", "<URL>", clean)
    clean = re.sub(r"@\w+", "<HANDLE>", clean)
    clean = re.sub(r"\s+", " ", clean)
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16]


@dataclass
class DatasetSample:
    id: str
    sample_type: SampleType
    text: str
    language: Language
    categories: list[str]
    assessment_label: str  # high_risk | suspicious_verify_first | inconclusive | no_known_threats_found | verified_official
    rationale: str
    source_refs: list[str] = field(default_factory=list)
    contradictory_refs: list[str] = field(default_factory=list)
    provenance: Provenance = Provenance.SYNTHETIC
    adjudication_status: AdjudicationStatus = AdjudicationStatus.UNREVIEWED
    confidence: float = 1.0
    created_at: str = field(default_factory=now_utc_iso)
    reviewed_at: str | None = None
    dataset_version: str = "v1.0"
    is_synthetic: bool = True
    incident_id: str | None = None
    template_hash: str = field(default="")

    def __post_init__(self):
        if not self.template_hash and self.text:
            self.template_hash = compute_template_hash(self.text)
        if not self.incident_id:
            self.incident_id = f"inc-{self.template_hash}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sample_type"] = self.sample_type.value if hasattr(self.sample_type, "value") else str(self.sample_type)
        d["language"] = self.language.value if hasattr(self.language, "value") else str(self.language)
        d["provenance"] = self.provenance.value if hasattr(self.provenance, "value") else str(self.provenance)
        d["adjudication_status"] = self.adjudication_status.value if hasattr(self.adjudication_status, "value") else str(self.adjudication_status)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatasetSample":
        d = dict(data)
        d["sample_type"] = SampleType(d.get("sample_type", "other"))
        d["language"] = Language(d.get("language", "unknown"))
        d["provenance"] = Provenance(d.get("provenance", "synthetic"))
        d["adjudication_status"] = AdjudicationStatus(d.get("adjudication_status", "unreviewed"))
        return cls(**d)


@dataclass
class PredictionResult:
    predicted_categories: list[tuple[str, float]]  # (category, probability)
    primary_category: str
    fraud_risk_score: float  # Calibrated risk level (0.0 to 1.0)
    calibrated_confidence: float  # Model's confidence in this specific prediction (0.0 to 1.0)
    evidence_strength: str  # "weak", "supporting", "strong", "conclusive"
    abstain: bool = False
    abstain_reason: str | None = None
    feature_contributions: dict[str, float] = field(default_factory=dict)
    disagreement_with_rules: bool = False
    active_learning_priority: float = 0.0
    model_version: str = "baseline-v1.0"
    raw_probabilities: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FeedbackItem:
    id: str
    check_id: str | None
    sample_text: str
    predicted_label: str
    predicted_category: str | None
    user_feedback: str  # "helpful" | "mistake_false_positive" | "mistake_false_negative" | "inaccurate_detail"
    user_comment: str
    active_learning_priority: float = 0.0
    review_status: ReviewStatus = ReviewStatus.PENDING
    adjudicated_label: str | None = None
    adjudicated_category: str | None = None
    reviewer_notes: str | None = None
    created_at: str = field(default_factory=now_utc_iso)
    reviewed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["review_status"] = self.review_status.value if hasattr(self.review_status, "value") else str(self.review_status)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeedbackItem":
        d = dict(data)
        d["review_status"] = ReviewStatus(d.get("review_status", "pending"))
        return cls(**d)


@dataclass
class ModelMetadata:
    version: str
    created_at: str
    dataset_version: str
    training_samples_count: int
    test_samples_count: int
    metrics: dict[str, Any]
    acceptance_passed: bool
    rollback_version: str | None = None
    is_active: bool = False
    algorithm: str = "TfidfCharWord_CalibratedLogisticRegression"
    feature_dim: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModelMetadata":
        return cls(**data)
