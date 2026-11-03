from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import re

SEVERITIES = {"critical", "high", "medium", "low", "context"}
POLARITIES = {"risk", "context", "reassuring"}
SOURCE_GROUPS = {"user_submitted_artifact", "public_web_observation", "official_record", "other_trusted_source", "threat_feed"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_timestamp(value: str | None) -> str:
    if not value:
        return utc_now()
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Finding:
    ref: str
    source_group: str
    category: str
    severity: str
    polarity: str
    summary: str
    explanation: str
    confidence: float = 0.5
    excerpt: str = ""
    observed_at: str = field(default_factory=utc_now)
    limitations: tuple[str, ...] = ()

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", self.ref or ""):
            raise ValueError("ref must be an opaque 8-80 character identifier")
        if self.source_group not in SOURCE_GROUPS:
            raise ValueError("unsupported source_group")
        if not re.fullmatch(r"[a-z0-9_:-]{1,80}", self.category or ""):
            raise ValueError("category must be a lowercase identifier")
        if self.severity not in SEVERITIES or self.polarity not in POLARITIES:
            raise ValueError("invalid severity or polarity")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if len(self.summary) > 300 or len(self.explanation) > 900 or len(self.excerpt) > 240:
            raise ValueError("display field exceeds limit")
        object.__setattr__(self, "observed_at", normalize_timestamp(self.observed_at))

    def to_dict(self) -> dict[str, Any]:
        row = asdict(self)
        row["limitations"] = list(self.limitations)
        return row


@dataclass(slots=True)
class Phase6Result:
    case_ref: str
    findings: list[Finding]
    sections: dict[str, Any]
    next_steps: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_ref": self.case_ref,
            "phase": 6,
            "findings": [f.to_dict() for f in self.findings],
            "sections": self.sections,
            "next_steps": list(self.next_steps),
            "limitations": list(self.limitations),
            "raw_uploads_stored": False,
            "verdict_policy": "Phase 6 adds explainable observations. It does not independently prove fraud, seller identity, payment settlement, or media authenticity.",
        }

    def to_phase5_signals(self):
        """Lazily adapt Phase 6 findings into Phase 5 EvidenceSignal instances."""
        try:
            from toroka_phase5.models import EvidenceSignal
        except ImportError as exc:
            raise RuntimeError("Install the integrated Phase 5 toroka_phase5 package to use this adapter") from exc
        return [EvidenceSignal(
            evidence_ref=f.ref,
            source_group=f.source_group,
            category=f.category,
            severity=f.severity,
            summary=f.summary,
            explanation=f.explanation,
            confidence=f.confidence,
            excerpt=f.excerpt,
            polarity=f.polarity,
            limitations=tuple(f.limitations) + ("Phase 6 observation; not an independent determination of fraud or authenticity.",),
            observed_at=f.observed_at,
        ) for f in self.findings]

    def to_phase2_evidence(self):
        """Optional direct adapter to the integrated Phase 2 Evidence model.

        User-submitted modalities share one provenance family, public observations
        share one family, and official records share one family. This avoids
        manufacturing corroboration merely by changing media type.
        """
        try:
            from toroka_evidence.models import Evidence
        except ImportError as exc:
            raise RuntimeError("Install the integrated Phase 2 toroka_evidence package to use this adapter") from exc
        from datetime import datetime, timezone
        group_map = {
            "user_submitted_artifact": "user_report",
            "public_web_observation": "website_behavior",
            "official_record": "official_registry",
            "threat_feed": "threat_intelligence",
            "other_trusted_source": "toroka_phase6_trusted_observation",
        }
        strength_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "context": 1}
        rows = []
        for finding in self.findings:
            try:
                observed = datetime.fromisoformat(finding.observed_at.replace("Z", "+00:00"))
            except ValueError:
                observed = datetime.now(timezone.utc)
            rows.append(Evidence(
                source=f"Toroka Phase 6 {finding.source_group}",
                source_group=group_map[finding.source_group],
                category=finding.category,
                polarity="risk" if finding.polarity == "risk" else "context",
                summary=finding.summary,
                why_it_matters=finding.explanation,
                strength=strength_map[finding.severity],
                reliability=0.62 if finding.source_group == "user_submitted_artifact" else 0.72,
                confidence=finding.confidence,
                subject=self.case_ref,
                observed_at=observed,
                verified=False,
                limitations=list(finding.limitations) + ["Phase 6 observation is not independently verified by this adapter."],
                metadata={"phase": 6, "evidence_ref": finding.ref, "source_group": finding.source_group,
                          "excerpt": finding.excerpt, "polarity_original": finding.polarity},
            ))
        return rows

