"""SQLAlchemy models for intelligence events, entity relationships, risk signals, and investigation bundles."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class IntelligenceBase(DeclarativeBase):
    """Declarative base for Toroka Enterprise cross-system intelligence persistence."""
    pass


class IntelligenceEventRecord(IntelligenceBase):
    """Normalized cross-system event with provenance and relationship metadata."""
    __tablename__ = "enterprise_intelligence_events"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    source_system: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    source_record_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    provenance_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class IntelligenceRelationshipRecord(IntelligenceBase):
    """Graph edge between resolved entities with provenance and confidence."""
    __tablename__ = "enterprise_intelligence_relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    source_system: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "installation_id", "source_type", "source_id", "target_type", "target_id", "relationship_type",
            name="uq_intelligence_relationship_edge",
        ),
    )


class IntelligenceSignalRecord(IntelligenceBase):
    """Detected cross-system correlation signal associated with cases or anchor events."""
    __tablename__ = "enterprise_intelligence_signals"

    signal_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    signal_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    alternative_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InvestigationBundleRecord(IntelligenceBase):
    """Structured, exportable intelligence bundle linked to an investigation or case."""
    __tablename__ = "enterprise_investigation_bundles"

    investigation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    anchor_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    finding: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    bundle_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationHypothesisRecord(IntelligenceBase):
    """Investigation hypothesis tracking competing explanations and investigator notes."""
    __tablename__ = "enterprise_investigation_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)

    supporting_signal_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_signal_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    investigator_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
