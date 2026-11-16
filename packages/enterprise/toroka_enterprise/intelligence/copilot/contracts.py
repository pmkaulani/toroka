from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ClaimKind(StrEnum):
    FACT = "fact"
    INFERENCE = "inference"
    UNKNOWN = "unknown"
    RECOMMENDATION = "recommendation"


class ReportDraftStatus(StrEnum):
    DRAFT = "DRAFT"
    INVESTIGATOR_REVIEW = "INVESTIGATOR_REVIEW"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class CopilotTaskType(StrEnum):
    EXPLAIN_CASE = "explain_case"
    EXPLAIN_TIMELINE = "explain_timeline"
    INVESTIGATE_ENTITY = "investigate_entity"
    COMPARE_HISTORICAL = "compare_historical"
    INVESTIGATE_CONTRADICTIONS = "investigate_contradictions"
    IDENTIFY_MISSING_EVIDENCE = "identify_missing_evidence"
    GENERATE_INVESTIGATION_PLAN = "generate_investigation_plan"
    DRAFT_REPORT = "draft_report"
    GENERAL_QA = "general_qa"


@dataclass(frozen=True)
class EvidenceQuote:
    evidence_id: str
    quoted_text: str


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    installation_id: str
    case_id: str
    source_system: str
    source_record_id: str
    event_time: datetime | None
    available_at: datetime | None
    excerpt: str
    content_sha256: str
    title: str = ""
    record_type: str = "event"
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def compute_sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        evidence_id: str,
        installation_id: str,
        case_id: str,
        source_system: str,
        source_record_id: str,
        excerpt: str,
        event_time: datetime | None = None,
        available_at: datetime | None = None,
        title: str = "",
        record_type: str = "event",
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceItem:
        digest = cls.compute_sha256(excerpt)
        return cls(
            evidence_id=evidence_id,
            installation_id=installation_id,
            case_id=case_id,
            source_system=source_system,
            source_record_id=source_record_id,
            event_time=event_time,
            available_at=available_at,
            excerpt=excerpt,
            content_sha256=digest,
            title=title or f"{source_system}:{source_record_id}",
            record_type=record_type,
            metadata=metadata or {},
        )


@dataclass(frozen=True)
class EvidenceContext:
    installation_id: str
    case_id: str
    items: tuple[EvidenceItem, ...]
    as_of: datetime | None = None
    context_digest: str = ""

    def __post_init__(self) -> None:
        if not self.context_digest and self.items:
            combined = "|".join(
                f"{item.evidence_id}:{item.content_sha256}"
                for item in sorted(self.items, key=lambda x: x.evidence_id)
            )
            digest = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            object.__setattr__(self, "context_digest", digest)

    @property
    def item_count(self) -> int:
        return len(self.items)

    def get_item(self, evidence_id: str) -> EvidenceItem | None:
        for item in self.items:
            if item.evidence_id == evidence_id:
                return item
        return None


@dataclass(frozen=True)
class GroundedClaim:
    claim_id: str
    kind: ClaimKind
    statement: str
    evidence_ids: tuple[str, ...] = ()
    quotes: tuple[EvidenceQuote, ...] = ()
    limitations: str | None = None
    investigative_basis: str | None = None
    alternative_explanations: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvestigationPlanStep:
    step_number: int
    objective: str
    evidence_sought: str
    reason_for_request: str
    relevant_source_system: str
    expected_investigative_value: str
    required_permissions: str = "investigator"


@dataclass(frozen=True)
class InvestigationPlan:
    plan_id: str
    case_id: str
    steps: tuple[InvestigationPlanStep, ...]


@dataclass(frozen=True)
class InvestigationReportDraft:
    draft_id: str
    installation_id: str
    case_id: str
    report_type: str
    title: str
    content_markdown: str
    evidence_context_hash: str
    citations: tuple[EvidenceQuote, ...] = ()
    status: ReportDraftStatus = ReportDraftStatus.DRAFT
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    investigator_edits_markdown: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None


@dataclass(frozen=True)
class InvestigationCopilotResponse:
    response_id: str
    thread_id: str
    case_id: str
    installation_id: str
    task_type: CopilotTaskType
    summary: str
    claims: tuple[GroundedClaim, ...]
    missing_evidence: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    plan: InvestigationPlan | None = None
    report_draft: InvestigationReportDraft | None = None
    tool_calls_executed: tuple[dict[str, Any], ...] = ()
    grounding_report: Any | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    provider_info: dict[str, Any] = field(default_factory=dict)
