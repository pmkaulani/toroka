from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

MAX_CHARS = 5000
Category = Literal["message", "job", "grant", "payment", "shop", "website"]
Lang = Literal["en", "sw"]


def clean_text(v: str) -> str:
    v = "".join(ch for ch in v if ch in "\n\t" or ch.isprintable())
    if not v.strip():
        raise ValueError("text must contain more than whitespace")
    return v


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_CHARS, description="The message, link or identifier to check, as text.")
    category: Category | None = Field(None, description="Optional. If omitted, a category is suggested and returned.")
    language: Lang = "en"
    _c = field_validator("text")(clean_text)


class FindingOut(BaseModel):
    code: str
    evidence_type: str = "heuristic"
    strength: str
    plain_text: str
    why_it_matters: str
    excerpt: str | None = None
    start: int | None = None
    end: int | None = None
    source_id: str | None = None
    needs_external_verification: bool = False
    claim_status: str | None = None
    polarity: str = "risk"


class CoverageOut(BaseModel):
    id: str
    name: str
    status: str
    detail: str
    blocking: bool = False
    manual_searches: list[dict[str, str]] = Field(default_factory=list)


class NextStepOut(BaseModel):
    text: str
    source_id: str | None = None


class SourceOut(BaseModel):
    id: str
    statement: str
    source_url: str | None = None
    last_verified_at: str
    review_due: str | None = None
    reviewer: str


class AssessmentOut(BaseModel):
    label: str
    label_text: str | None = None
    language: str = "en"
    translation_status: str | None = None
    summary: str
    findings: list[FindingOut]
    coverage: list[CoverageOut]
    next_steps: list[NextStepOut]
    limitations: list[str]
    entities: dict
    category: dict = {}
    taxonomy: dict = {}
    shop_profile: dict | None = None
    sensitive_data_detected: bool
    checked_at: str
    policy_version: str
    sources: list[SourceOut] = []
    stale_sources: list[str] = []
    conversational_reply: str | None = None
    one_warning: str | None = None
    verified: list[dict] = []
    investigation_intelligence: dict | None = None


class EvidenceOut(BaseModel):
    evidence_id: str
    mime_type: str
    size_bytes: int
    width: int
    height: int
    redaction_state: str
    ocr_status: str
    ocr_confidence: int | None = None
    ocr_note: str = ""
    extracted_text: str | None = None
    retention_until: str


class StepOut(BaseModel):
    name: str
    status: str


class CheckResponse(BaseModel):
    request_id: str
    check_id: str
    status: Literal["queued", "extracting", "checking_sources", "needs_more_information", "completed", "failed_safely"]
    created_at: str
    expires_at: str
    steps: list[StepOut] = []
    prompt: str | None = None
    assessment: AssessmentOut | None = None
    evidence: list[EvidenceOut] = []
    guest_token: str | None = Field(None, description="Shown once, at creation. Needed to read this check as a guest.")


class IdentifierIn(BaseModel):
    type: Literal["phone", "till", "paybill", "domain", "handle"]
    value: str = Field(..., min_length=3, max_length=120)


class ReportIn(BaseModel):
    category: Category
    narrative: str = Field(..., min_length=20, max_length=4000)
    identifiers: list[IdentifierIn] = Field(..., min_length=1, max_length=5)
    incident_date: str | None = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    amount_band: Literal["none", "under_1k", "1k_10k", "10k_100k", "over_100k"] | None = None
    contact: str | None = Field(None, max_length=120, description="Optional. Used only to tell you the outcome, with your consent.")
    consent_to_contact: bool = False
    _n = field_validator("narrative")(clean_text)


class AppealIn(BaseModel):
    indicator_id: str
    contact: str = Field(..., min_length=5, max_length=120, description="Email or phone we can verify you at.")
    issue_type: Literal["correction", "right_of_reply", "appeal"]
    statement: str = Field(..., min_length=20, max_length=3000)
    _n = field_validator("statement")(clean_text)


class ModerationActionIn(BaseModel):
    action: Literal["approve", "reject", "request_info", "mark_duplicate"]
    reason_code: str = Field(..., min_length=3, max_length=40)
    notes: str | None = Field(None, max_length=1000)
    duplicate_of: str | None = None
    publish: bool = False
    verified_by_source: str | None = Field(None, max_length=200, description="Cite the primary source if publishing on fewer than the usual independent reports.")


class AuthIn(BaseModel):
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=160)
    password: str = Field(..., min_length=10, max_length=200)


class RecoveryIn(BaseModel):
    paid: bool | None = None
    shared_credentials: bool | None = None
    installed_app: bool | None = None
    sent_id_documents: bool | None = None
    language: str = "en"


class OpportunityIn(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9\-]{3,60}$")
    opportunity_type: Literal["job", "grant", "bursary", "programme"]
    official_name: str
    administering_body: str
    aliases: list[str] = []
    official_domain: str
    application_url: str | None = None
    eligibility: str | None = None
    counties: list[str] = []
    status: str | None = None
    fee_policy: Literal["no_fee", "fee_applies", "unknown"] | None = None
    source_url: str
    last_verified_at: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    review_interval_days: int = Field(90, ge=7, le=365)
    reviewer: str


class BusinessClaimIn(BaseModel):
    business_name: str = Field(..., min_length=2, max_length=160)
    domain: str | None = Field(None, max_length=120)
    note: str | None = Field(None, max_length=1000)


class VerifiedEntityIn(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9\-]{3,60}$")
    name: str = Field(..., min_length=2, max_length=160)
    entity_type: Literal["organisation", "online_shop", "website", "social_shop"]
    domains: list[str] = Field(default=[], max_length=5)
    handles: list[str] = Field(default=[], max_length=5, description="platform:handle, e.g. instagram:duka_la_viatu")
    include_subdomains: bool = False
    basis: Literal["official_registry", "government_register", "regulator_list", "moderator_verified_documents"]
    source_url: str = Field(..., pattern=r"^https://")
    evidence_note: str | None = Field(None, max_length=1000)
    last_verified_at: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    review_interval_days: int = Field(180, ge=7, le=365)
    reviewer: str = Field(..., min_length=2, max_length=80)


class ChatMessage(BaseModel):
    role: str
    text: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    history: list[ChatMessage] = Field(default_factory=list)
    language: str = "en"
    check_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    reply_en: str | None = None
    reply_sw: str | None = None
    check_id: str | None = None
    detected_patterns: list[str] = Field(default_factory=list)
    action_chips: list[dict[str, str]] = Field(default_factory=list)
    manual_searches: list[dict[str, str]] = Field(default_factory=list)
    url_investigation: dict[str, Any] | None = None


class URLInvestigateRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_CHARS, description="The URL or social profile link to investigate.")
    question: str | None = Field(None, description="Optional user question or context about the link.")
    language: Lang = "en"


class FeedbackIn(BaseModel):
    sample_text: str = Field(..., min_length=1, max_length=MAX_CHARS)
    predicted_label: str = ""
    predicted_category: str | None = None
    user_feedback: str = "helpful"  # helpful | mistake_false_positive | mistake_false_negative | inaccurate_detail
    user_comment: str = Field(default="", max_length=2000)
    check_id: str | None = None


class AdjudicationIn(BaseModel):
    feedback_id: str
    adjudicated_label: str
    adjudicated_category: str
    reviewer_notes: str = Field(default="", max_length=2000)
    status: str = "approved_for_training"
