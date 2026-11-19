"""Investigation intelligence domain contracts for Toroka Enterprise.

Represents evidence-backed entity graphs, temporal transactions, and explainable findings.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EntityKind(StrEnum):
    PERSON = "person"
    ORGANISATION = "organisation"
    BANK_ACCOUNT = "bank_account"
    MOBILE_MONEY_ACCOUNT = "mobile_money_account"
    MERCHANT = "merchant"
    PHONE = "phone"
    EMAIL = "email"
    DOMAIN = "domain"
    DEVICE = "device"
    IP_ADDRESS = "ip_address"
    CRYPTO_WALLET = "crypto_wallet"
    PAYMENT_REFERENCE = "payment_reference"
    ADDRESS = "address"


class EvidenceState(StrEnum):
    OBSERVED = "observed"
    CORROBORATED = "corroborated"
    HYPOTHESIS = "hypothesis"
    DISPUTED = "disputed"
    REVOKED = "revoked"


class EvidenceSourceType(StrEnum):
    BANK_TRANSACTION = "bank_transaction"
    MOBILE_MONEY_RECORD = "mobile_money_record"
    EMAIL = "email"
    EMAIL_HEADER = "email_header"
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    DEVICE_TELEMETRY = "device_telemetry"
    AUTHENTICATED_SYSTEM_LOG = "authenticated_system_log"
    PUBLIC_WEB_SOURCE = "public_web_source"
    INVESTIGATOR_NOTE = "investigator_note"
    OTHER = "other"


class EvidenceArtifactIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: UUID
    source_type: EvidenceSourceType
    source_system: str = Field(min_length=1, max_length=120)
    source_record_ref: str | None = Field(default=None, max_length=300)
    source_locator_ciphertext: str | None = None
    observed_at: datetime
    collected_at: datetime
    collected_by: str = Field(min_length=1, max_length=160)
    source_timezone: str = Field(min_length=1, max_length=80)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    media_type: str | None = Field(default=None, max_length=120)
    extractor_name: str | None = Field(default=None, max_length=120)
    extractor_version: str | None = Field(default=None, max_length=80)

    @field_validator("observed_at", "collected_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_time_order(self) -> EvidenceArtifactIn:
        if self.collected_at < self.observed_at:
            raise ValueError("collected_at cannot precede observed_at without an approved future-effective event type")
        return self


class EvidenceArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_id: str
    case_id: UUID
    source_type: EvidenceSourceType
    source_system: str
    source_record_ref: str | None = None
    observed_at: datetime
    collected_at: datetime
    collected_by: str
    source_timezone: str
    sha256: str
    media_type: str | None = None
    extractor_name: str | None = None
    extractor_version: str | None = None
    state: EvidenceState = EvidenceState.OBSERVED
    created_at: datetime


class EntityIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EntityKind
    identifier_token: str = Field(min_length=16, max_length=180)
    display_label: str | None = Field(default=None, max_length=180)
    first_seen_at: datetime
    last_seen_at: datetime
    sensitivity: str = Field(default="restricted", max_length=30)

    @field_validator("first_seen_at", "last_seen_at")
    @classmethod
    def require_seen_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_seen_window(self) -> EntityIn:
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at must not precede first_seen_at")
        return self


class EntityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_id: str
    case_id: UUID
    kind: EntityKind
    identifier_token: str
    display_label: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    sensitivity: str
    created_at: datetime


class RelationshipIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: str = Field(min_length=2, max_length=80)
    state: EvidenceState = EvidenceState.HYPOTHESIS
    evidence_ids: list[UUID] = Field(min_length=1, max_length=100)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    explanation: str = Field(min_length=5, max_length=1200)

    @model_validator(mode="after")
    def validate_relationship(self) -> RelationshipIn:
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("self-relationships are not supported")
        if self.valid_from and self.valid_to and self.valid_to < self.valid_from:
            raise ValueError("valid_to must not precede valid_from")
        return self


class RelationshipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_id: str
    case_id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    relationship_type: str
    state: EvidenceState
    evidence_ids: list[UUID]
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    explanation: str
    created_at: datetime


class TransactionEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: UUID
    source_entity_id: UUID
    destination_entity_id: UUID
    amount: Annotated[Decimal, Field(gt=Decimal("0"), max_digits=20, decimal_places=4)]
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    occurred_at: datetime
    source_timezone: str = Field(min_length=1, max_length=80)
    channel: str = Field(min_length=1, max_length=80)
    source_system: str = Field(min_length=1, max_length=120)
    source_record_ref: str = Field(min_length=1, max_length=300)
    evidence_id: UUID
    reference_token: str | None = Field(default=None, max_length=180)
    event_type: str = Field(default="transfer", max_length=40)

    @field_validator("occurred_at")
    @classmethod
    def require_event_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_counterparties(self) -> TransactionEventIn:
        if self.source_entity_id == self.destination_entity_id:
            raise ValueError("source and destination must be different entities")
        return self


class TransactionEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_id: str
    case_id: UUID
    source_entity_id: UUID
    destination_entity_id: UUID
    amount: Decimal
    currency: str
    occurred_at: datetime
    source_timezone: str
    channel: str
    source_system: str
    source_record_ref: str
    evidence_id: UUID
    reference_token: str | None = None
    event_type: str
    created_at: datetime


class FindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=2, max_length=100)
    rule_version: str = Field(min_length=1, max_length=40)
    title: str = Field(min_length=3, max_length=180)
    explanation: str = Field(min_length=10, max_length=2000)
    state: EvidenceState = EvidenceState.HYPOTHESIS
    evidence_ids: list[UUID] = Field(min_length=1, max_length=200)
    counter_evidence_ids: list[UUID] = Field(default_factory=list, max_length=200)
    unresolved_questions: list[str] = Field(default_factory=list, max_length=50)
    recommended_human_action: str = Field(min_length=3, max_length=500)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    installation_id: str
    case_id: UUID
    rule_id: str
    rule_version: str
    title: str
    explanation: str
    state: EvidenceState
    evidence_ids: list[UUID]
    counter_evidence_ids: list[UUID]
    unresolved_questions: list[str]
    recommended_human_action: str
    created_at: datetime


class GraphQueryResponse(BaseModel):
    installation_id: str
    case_id: UUID
    entities: list[EntityOut]
    relationships: list[RelationshipOut]
    hop_limit: int
    node_limit: int
    truncated: bool = False


class TimelineEventOut(BaseModel):
    event_id: str
    event_type: str
    timestamp: datetime
    source_timezone: str
    source_system: str
    source_record_ref: str | None = None
    evidence_id: UUID | None = None
    summary: str
    confidence_state: str
    details: dict[str, Any] = Field(default_factory=dict)


class TimelineResponse(BaseModel):
    installation_id: str
    case_id: UUID
    events: list[TimelineEventOut]
    total_events: int
