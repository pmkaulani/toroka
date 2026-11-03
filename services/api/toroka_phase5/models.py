from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import re

ARTIFACT_TYPES = {
    "sms", "message", "chat_transcript", "screenshot_ocr", "mpesa_receipt_ocr",
    "email", "webpage_extract", "social_profile_extract", "call_transcript", "other",
}
SOURCE_GROUPS = {
    "user_submitted_artifact", "user_sms", "user_chat", "user_screenshot",
    "user_receipt", "public_web_observation", "official_record", "threat_feed",
    "payment_provider_response", "moderator_review", "other_trusted_source",
}
SEVERITIES = {"critical", "high", "medium", "low", "context"}


def _normalized_iso_timestamp(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def _valid_evidence_source_group(value: str) -> bool:
    return value in SOURCE_GROUPS or bool(re.fullmatch(r"feed:[a-z0-9_-]{1,48}", value or ""))



@dataclass(frozen=True, slots=True)
class ArtifactInput:
    artifact_ref: str
    artifact_type: str
    extracted_text: str = field(repr=False)
    source_group: str = "user_submitted_artifact"
    language: str = "undetermined"
    observed_at: str | None = None
    extraction_method: str = "host_ocr_or_text_extractor"

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", self.artifact_ref or "") or re.fullmatch(r"0?7\d{8}", self.artifact_ref or "") or re.fullmatch(r"2547\d{8}", self.artifact_ref or ""):
            raise ValueError("artifact_ref must be an opaque 8-80 character identifier, not a phone number")
        if self.artifact_type not in ARTIFACT_TYPES:
            raise ValueError("unsupported artifact_type")
        if self.source_group not in SOURCE_GROUPS:
            raise ValueError("source_group must be a predefined trusted source group")
        if not isinstance(self.extracted_text, str) or len(self.extracted_text) > 50_000:
            raise ValueError("extracted_text must be text of at most 50,000 characters")
        if len(self.language) > 24:
            raise ValueError("language label is too long")
        if self.observed_at:
            try:
                object.__setattr__(self, "observed_at", _normalized_iso_timestamp(self.observed_at))
            except ValueError as exc:
                raise ValueError("observed_at must be an ISO-8601 timestamp") from exc


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    evidence_ref: str
    source_group: str
    category: str
    severity: str
    summary: str
    explanation: str
    confidence: float = 0.5
    excerpt: str = ""
    polarity: str = "risk"
    limitations: tuple[str, ...] = ()
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if (not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", self.evidence_ref or "")
                or re.fullmatch(r"0?7\d{8}", self.evidence_ref or "")
                or re.fullmatch(r"2547\d{8}", self.evidence_ref or "")):
            raise ValueError("evidence_ref must be an opaque 8-80 character identifier, not a phone number")
        if not re.fullmatch(r"[a-z0-9_:-]{1,80}", self.category or ""):
            raise ValueError("category must be a lowercase identifier")
        if self.severity not in SEVERITIES:
            raise ValueError("invalid severity")
        if self.polarity not in {"risk", "context", "reassuring"}:
            raise ValueError("invalid polarity")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not _valid_evidence_source_group(self.source_group):
            raise ValueError("invalid source_group")
        try:
            object.__setattr__(self, "observed_at", _normalized_iso_timestamp(self.observed_at))
        except (ValueError, AttributeError) as exc:
            raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
        if not isinstance(self.summary, str) or not isinstance(self.explanation, str) or not isinstance(self.excerpt, str):
            raise ValueError("signal display fields must be strings")
        if len(self.summary) > 300 or len(self.explanation) > 800:
            raise ValueError("signal text exceeds safe display bounds")
        if len(self.excerpt) > 240:
            raise ValueError("excerpt exceeds safe display bounds")

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["limitations"] = list(self.limitations)
        return row


@dataclass(slots=True)
class InvestigationSummary:
    case_ref: str
    indicator_band: str
    evidence_strength: str
    independent_source_groups: int
    evidence_count: int
    signals: list[EvidenceSignal]
    artifact_summaries: list[dict[str, Any]]
    model_shadow: dict[str, Any] | None
    recommended_actions: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_ref": self.case_ref,
            "indicator_band": self.indicator_band,
            "evidence_strength": self.evidence_strength,
            "independent_source_groups": self.independent_source_groups,
            "evidence_count": self.evidence_count,
            "signals": [s.to_dict() for s in self.signals],
            "artifact_summaries": self.artifact_summaries,
            "model_shadow": self.model_shadow,
            "recommended_actions": list(self.recommended_actions),
            "limitations": list(self.limitations),
            "raw_artifact_content_stored": False,
            "verdict_policy": "Phase 5 fuses explainable indicators; it does not independently prove seller identity, payment settlement or criminal conduct.",
        }

    def to_phase2_evidence(self):
        """Convert explainable Phase 5 signals into Phase 2 Evidence objects."""
        try:
            from toroka_evidence.models import Evidence
        except ImportError as exc:
            raise RuntimeError("Install the integrated Phase 2 toroka_evidence package before using this adapter") from exc
        strength_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "context": 1}
        evidence = []
        for signal in self.signals:
            if signal.source_group.startswith("user_"):
                # Phase 4 phrase evidence uses this exact group. Reusing it avoids
                # double-counting Phase 4 and Phase 5 analyses of the same upload.
                phase2_source_group = "toroka-content-patterns-v1"
            elif signal.source_group.startswith("feed:"):
                # Phase 4 threat-feed evidence uses the provider's configured group.
                phase2_source_group = signal.source_group.split(":", 1)[1]
            elif signal.source_group == "threat_feed":
                phase2_source_group = "threat_feed"
            else:
                phase2_source_group = f"toroka-phase5-{signal.source_group.replace('_', '-')}-v1"
            evidence.append(Evidence(
                source=f"Toroka Phase 5 {signal.source_group}",
                source_group=phase2_source_group,
                category=signal.category,
                polarity="risk" if signal.polarity == "risk" else "context",
                summary=signal.summary,
                why_it_matters=signal.explanation,
                strength=strength_map.get(signal.severity, 1),
                reliability=0.62,
                confidence=signal.confidence,
                subject=self.case_ref,
                observed_at=datetime.fromisoformat(signal.observed_at.replace("Z", "+00:00")),
                verified=False,
                limitations=list(signal.limitations) + [
                    "Phase 5 signal is derived from user-submitted or external observations and is not independently verified by this adapter."
                ],
                metadata={"phase": 5, "evidence_ref": signal.evidence_ref,
                          "source_group": signal.source_group, "excerpt": signal.excerpt,
                          "indicator_band": self.indicator_band},
            ))
        return evidence
