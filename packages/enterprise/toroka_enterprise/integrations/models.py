"""SQLAlchemy models for integration records, cursors, job executions, and event inboxes."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    DateTime,
    Integer,
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


class IntegrationBase(DeclarativeBase):
    """Declarative base for Toroka Enterprise integration persistence."""
    pass


class IntegrationRecord(IntegrationBase):
    """Canonical record stored in the integration gateway with full lineage."""
    __tablename__ = "enterprise_integration_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    connector_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    record_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    source_system: Mapped[str] = mapped_column(String(50), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="ingested")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    source_event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "installation_id", "connector_id", "record_id", "version",
            name="uq_integration_record_version",
        ),
    )


class IntegrationCursor(IntegrationBase):
    """Resumable connector checkpoint and ingestion watermark."""
    __tablename__ = "enterprise_integration_cursors"

    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    connector_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    cursor: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    records_ingested_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_duplicates_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_corrected_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class IntegrationJobRecord(IntegrationBase):
    """Operational history of connector sync, backfill, and reconciliation jobs."""
    __tablename__ = "enterprise_integration_jobs"

    job_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    connector_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False)
    triggered_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cursor_before: Mapped[str | None] = mapped_column(String(500), nullable=True)
    cursor_after: Mapped[str | None] = mapped_column(String(500), nullable=True)
    records_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_accepted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_duplicates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_corrected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)


class IntegrationEventInbox(IntegrationBase):
    """Durable inbox for authenticated incoming webhook events with replay protection."""
    __tablename__ = "enterprise_integration_events_inbox"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    connector_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="received")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class IntegrationRejectedRecord(IntegrationBase):
    """Audit log of records rejected during ingestion due to validation or schema errors."""
    __tablename__ = "enterprise_integration_rejected_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    connector_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    job_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    source_record_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    reason_message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    rejected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
