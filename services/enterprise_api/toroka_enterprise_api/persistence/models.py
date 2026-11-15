"""Operational database models for Toroka Enterprise persistence."""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def calculate_dedupe_key(
    installation_id: str,
    manifest_id: str,
    focus: str,
    secret: str = "",
) -> str:
    """Generate a keyed digest deduplication key from installation, manifest, and pseudonymised focus."""
    payload = f"{installation_id}:{manifest_id}:{focus}".encode("utf-8")
    key = (secret or "toroka-dedupe-key").encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class Base(DeclarativeBase):
    pass


class EnterpriseCase(Base):
    __tablename__ = "enterprise_cases"
    __table_args__ = (
        UniqueConstraint(
            "installation_id",
            "dedupe_key",
            name="uq_case_installation_dedupe",
        ),
        Index(
            "ix_case_status_created",
            "status",
            "created_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    installation_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    dedupe_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    label: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    focus: Mapped[str] = mapped_column(
        String(300), nullable=False
    )
    snapshot: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    snapshot_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    manifest_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="open"
    )
    disposition: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    closing_note: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    alternatives_considered: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_by: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )

    assignments: Mapped[list[CaseAssignment]] = relationship(
        "CaseAssignment", back_populates="case", cascade="all, delete-orphan"
    )
    notes: Mapped[list[CaseNote]] = relationship(
        "CaseNote", back_populates="case", cascade="all, delete-orphan"
    )
    reveal_requests: Mapped[list[RevealRequest]] = relationship(
        "RevealRequest", back_populates="case", cascade="all, delete-orphan"
    )
    closure_proposals: Mapped[list[CaseClosureProposal]] = relationship(
        "CaseClosureProposal", back_populates="case", cascade="all, delete-orphan"
    )


class CaseAssignment(Base):
    __tablename__ = "enterprise_case_assignments"
    __table_args__ = (
        Index(
            "ix_assignment_subject_status",
            "assigned_subject",
            "status",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assigned_subject: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    assignment_role: Mapped[str] = mapped_column(
        String(40), nullable=False, default="investigator"
    )
    assigned_by: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="active"
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    case: Mapped[EnterpriseCase] = relationship(
        "EnterpriseCase", back_populates="assignments"
    )


class CaseNote(Base):
    __tablename__ = "enterprise_case_notes"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("enterprise_cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    author_subject: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    body: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    case: Mapped[EnterpriseCase] = relationship(
        "EnterpriseCase", back_populates="notes"
    )


class RevealRequest(Base):
    __tablename__ = "enterprise_reveal_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected','expired','used')",
            name="ck_reveal_status",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("enterprise_cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    pseudonym: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    reason: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending"
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    rejection_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    case: Mapped[EnterpriseCase] = relationship(
        "EnterpriseCase", back_populates="reveal_requests"
    )


class CaseClosureProposal(Base):
    __tablename__ = "enterprise_case_closure_proposals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected','withdrawn')",
            name="ck_closure_status",
        ),
        Index(
            "ix_closure_case_status",
            "case_id",
            "status",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    disposition: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    closing_note: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    alternatives_considered: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    expected_case_version: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending"
    )
    reviewed_by: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    review_note: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    case: Mapped[EnterpriseCase] = relationship(
        "EnterpriseCase", back_populates="closure_proposals"
    )


class AuditHead(Base):
    __tablename__ = "enterprise_audit_heads"

    installation_id: Mapped[str] = mapped_column(
        String(100), primary_key=True
    )
    last_sequence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    last_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )


class AuditRecord(Base):
    __tablename__ = "enterprise_audit_records"

    sequence: Mapped[int] = mapped_column(
        Integer, primary_key=True
    )
    installation_id: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String(36), unique=True, default=new_id
    )
    actor_subject: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    actor_role: Mapped[str] = mapped_column(
        String(40), nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(100), nullable=False
    )
    target_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    target_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    safe_metadata: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    previous_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    event_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )


class RunRecord(Base):
    __tablename__ = "enterprise_runs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_id
    )
    installation_id: Mapped[str] = mapped_column(
        String(100), nullable=False, default="toroka-default-installation", index=True
    )
    manifest_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    manifest: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    result_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="completed"
    )
    created_by: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
