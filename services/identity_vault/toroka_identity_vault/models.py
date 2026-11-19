"""Database models for the isolated Identity Vault service."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, LargeBinary, PrimaryKeyConstraint, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VaultBase(DeclarativeBase):
    """Declarative base for isolated identity vault tables."""
    pass


class VaultRecord(VaultBase):
    __tablename__ = "enterprise_identity_vault"

    pseudonym: Mapped[str] = mapped_column(
        String(255), primary_key=True
    )
    installation_id: Mapped[str] = mapped_column(
        String(128), nullable=False, default="toroka-default-installation", index=True
    )
    ciphertext: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    key_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="v1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class VaultConsumedGrant(VaultBase):
    """Single-use record preventing replay or duplicate consumption of reveal grants."""
    __tablename__ = "enterprise_vault_consumed_grants"
    __table_args__ = (
        PrimaryKeyConstraint("installation_id", "grant_id", name="pk_vault_consumed_grants"),
    )

    installation_id: Mapped[str] = mapped_column(
        String(128), primary_key=True
    )
    grant_id: Mapped[str] = mapped_column(
        String(128), primary_key=True
    )
    case_id: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    requester_subject: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    consumed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
