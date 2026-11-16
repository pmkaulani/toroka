from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class CreateCopilotThreadRequest(BaseModel):
    case_id: str
    title: str = "Investigation Thread"


class CopilotThreadResponse(BaseModel):
    thread_id: str
    installation_id: str
    case_id: str
    title: str
    created_by: str
    is_archived: bool
    created_at: str
    updated_at: str


class SendCopilotMessageRequest(BaseModel):
    content: str


class EvidenceQuoteResponse(BaseModel):
    evidence_id: str
    quoted_text: str


class GroundedClaimResponse(BaseModel):
    claim_id: str
    kind: str
    statement: str
    evidence_ids: list[str] = Field(default_factory=list)
    quotes: list[EvidenceQuoteResponse] = Field(default_factory=list)
    limitations: str | None = None
    investigative_basis: str | None = None
    alternative_explanations: list[str] = Field(default_factory=list)


class GroundingReportResponse(BaseModel):
    valid: bool
    verified_claims: int
    rejected_claims: list[str] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)


class CopilotMessageResponse(BaseModel):
    message_id: str
    thread_id: str
    installation_id: str
    case_id: str
    role: str
    content: str
    task_type: str | None = None
    claims: list[GroundedClaimResponse] = Field(default_factory=list)
    citations: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    grounding_report: GroundingReportResponse | None = None
    created_at: str


class GenerateReportDraftRequest(BaseModel):
    case_id: str
    thread_id: str | None = None
    report_type: str = "INVESTIGATION_SUMMARY"
    title: str = "Investigation Brief"


class UpdateReportDraftRequest(BaseModel):
    investigator_edits_markdown: str


class ReviewReportDraftRequest(BaseModel):
    decision: str  # "ACCEPTED" or "REJECTED"
    notes: str | None = None


class CopilotReportDraftResponse(BaseModel):
    draft_id: str
    installation_id: str
    case_id: str
    thread_id: str | None = None
    report_type: str
    title: str
    content_markdown: str
    investigator_edits_markdown: str | None = None
    status: str
    evidence_context_hash: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    model_info: dict[str, Any] = Field(default_factory=dict)
    review_notes: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    created_at: str
    updated_at: str


class SubmitCopilotFeedbackRequest(BaseModel):
    rating: int  # 1 or -1
    feedback_text: str | None = None


class CopilotFeedbackResponse(BaseModel):
    feedback_id: str
    message_id: str
    rating: int
    feedback_text: str | None = None
    created_by: str
    created_at: str


class CopilotStatusResponse(BaseModel):
    status: str
    provider: str
    model: str
    air_gapped: bool
    data_retention_verified: bool
    active_tools_count: int
    allowed_tools: list[str]
