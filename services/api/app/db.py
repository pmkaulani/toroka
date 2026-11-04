"""Schema follows blueprint section 7 (simplified: `subjects` double as identifiers, keyed by HMAC).

Times are ISO-8601 strings (UTC) so SQLite and PostgreSQL behave the same. Sensitive fields are Fernet-encrypted;
exact-match lookups use keyed HMAC digests.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, event, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


def uid() -> str:
    return str(uuid.uuid4())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Base(DeclarativeBase):
    pass


def col(t, **kw):
    return mapped_column(t, **kw)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    email_hmac: Mapped[str] = col(String(64), unique=True)
    email_encrypted: Mapped[str] = col(Text)
    password_hash: Mapped[str] = col(String(200))
    role: Mapped[str] = col(String(16), default="user")             # user | moderator | admin
    status: Mapped[str] = col(String(16), default="active")
    created_at: Mapped[str] = col(String(32), default=now_iso)


class SessionToken(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = col(String(64), primary_key=True)
    user_id: Mapped[str] = col(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[str] = col(String(32), default=now_iso)
    expires_at: Mapped[str] = col(String(32))


class Check(Base):
    __tablename__ = "checks"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = col(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    guest_token_hash: Mapped[str | None] = col(String(64), nullable=True)
    input_type: Mapped[str] = col(String(16), default="text")
    category: Mapped[str | None] = col(String(24), nullable=True)
    status: Mapped[str] = col(String(24), default="queued")          # queued|extracting|checking_sources|needs_more_information|completed|failed_safely
    risk_band: Mapped[str | None] = col(String(32), nullable=True)
    assessment_version: Mapped[str | None] = col(String(32), nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)
    expires_at: Mapped[str] = col(String(32), index=True)
    input_encrypted: Mapped[str | None] = col(Text, nullable=True)
    input_sha256: Mapped[str] = col(String(64))
    input_chars: Mapped[int] = col(Integer, default=0)
    result_json: Mapped[dict | None] = col(JSON, nullable=True)
    steps_json: Mapped[list | None] = col(JSON, nullable=True)


class EvidenceFile(Base):
    __tablename__ = "evidence_files"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    check_id: Mapped[str] = col(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    object_key: Mapped[str] = col(String(80))
    sha256: Mapped[str] = col(String(64))
    mime_type: Mapped[str] = col(String(32))
    size_bytes: Mapped[int] = col(Integer)
    width: Mapped[int] = col(Integer, default=0)
    height: Mapped[int] = col(Integer, default=0)
    dhash: Mapped[str] = col(String(16), index=True)
    consent_scope: Mapped[str] = col(String(24), default="this_check_only")
    retention_until: Mapped[str] = col(String(32))
    redaction_state: Mapped[str] = col(String(24), default="metadata_stripped")
    created_at: Mapped[str] = col(String(32), default=now_iso)


class EvidenceExtraction(Base):
    __tablename__ = "evidence_extractions"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    evidence_id: Mapped[str] = col(ForeignKey("evidence_files.id", ondelete="CASCADE"), index=True)
    extracted_text_encrypted: Mapped[str] = col(Text)
    language: Mapped[str] = col(String(16))
    extractor_version: Mapped[str] = col(String(40))
    status: Mapped[str] = col(String(20))
    confidence: Mapped[int | None] = col(Integer, nullable=True)
    note: Mapped[str] = col(String(200), default="")


class Subject(Base):
    __tablename__ = "subjects"
    __table_args__ = (UniqueConstraint("subject_type", "lookup_hmac"),)
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    subject_type: Mapped[str] = col(String(16))                     # phone | till | paybill | domain | other
    lookup_hmac: Mapped[str] = col(String(64))
    display_masked: Mapped[str] = col(String(80))
    value_encrypted: Mapped[str] = col(Text)
    privacy_class: Mapped[str] = col(String(16), default="identifier")
    first_seen_at: Mapped[str] = col(String(32), default=now_iso)
    last_seen_at: Mapped[str] = col(String(32), default=now_iso)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    reporter_user_id: Mapped[str | None] = col(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reporter_key: Mapped[str] = col(String(64), index=True)         # HMAC of user id or guest client; used for independence only
    token_hash: Mapped[str] = col(String(64))
    category: Mapped[str] = col(String(24))
    narrative_encrypted: Mapped[str] = col(Text)
    script_hash: Mapped[str] = col(String(64), index=True)
    minhash: Mapped[list] = col(JSON)
    incident_date: Mapped[str | None] = col(String(10), nullable=True)
    amount_band: Mapped[str | None] = col(String(24), nullable=True)
    moderation_status: Mapped[str] = col(String(20), default="pending", index=True)   # pending|approved|rejected|needs_info|duplicate
    duplicate_of: Mapped[str | None] = col(String(36), nullable=True)
    possible_coordinated: Mapped[bool] = col(Boolean, default=False)
    publication_scope: Mapped[str] = col(String(16), default="private")
    contact_encrypted: Mapped[str | None] = col(Text, nullable=True)
    public_outcome: Mapped[str | None] = col(String(40), nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)


class ReportSubject(Base):
    __tablename__ = "report_subjects"
    report_id: Mapped[str] = col(ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True)
    subject_id: Mapped[str] = col(ForeignKey("subjects.id", ondelete="CASCADE"), primary_key=True)


class Indicator(Base):
    """The only thing the public can search: a moderated publication object, never raw reports."""
    __tablename__ = "indicators"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    subject_id: Mapped[str] = col(ForeignKey("subjects.id", ondelete="CASCADE"), unique=True)
    status: Mapped[str] = col(String(16), default="published")      # published | under_review | withdrawn
    independent_reports: Mapped[int] = col(Integer, default=0)
    last_reported: Mapped[str | None] = col(String(10), nullable=True)
    basis: Mapped[str] = col(String(40), default="independent_reports")   # independent_reports | verified_by_source
    basis_note: Mapped[str | None] = col(String(200), nullable=True)
    published_at: Mapped[str] = col(String(32), default=now_iso)


class EntityEdge(Base):
    __tablename__ = "entity_edges"
    __table_args__ = (UniqueConstraint("subject_a", "subject_b", "relation_type"),)
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    subject_a: Mapped[str] = col(ForeignKey("subjects.id", ondelete="CASCADE"))
    subject_b: Mapped[str] = col(ForeignKey("subjects.id", ondelete="CASCADE"))
    relation_type: Mapped[str] = col(String(24))                    # co_reported | same_script
    evidence_ref: Mapped[str] = col(String(60))
    status: Mapped[str] = col(String(12), default="candidate")
    strength_band: Mapped[str] = col(String(12), default="weak")
    first_seen_at: Mapped[str] = col(String(32), default=now_iso)
    last_seen_at: Mapped[str] = col(String(32), default=now_iso)


class ModerationAction(Base):
    __tablename__ = "moderation_actions"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    moderator_id: Mapped[str] = col(String(36))
    target_type: Mapped[str] = col(String(16))
    target_id: Mapped[str] = col(String(36), index=True)
    action: Mapped[str] = col(String(24))
    reason_code: Mapped[str] = col(String(40))
    notes: Mapped[str | None] = col(Text, nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)


class Appeal(Base):
    __tablename__ = "appeals"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    indicator_id: Mapped[str] = col(ForeignKey("indicators.id", ondelete="CASCADE"))
    requester_contact_encrypted: Mapped[str] = col(Text)
    contact_kind: Mapped[str] = col(String(8))
    issue_type: Mapped[str] = col(String(24))                       # correction | right_of_reply | appeal
    statement_encrypted: Mapped[str] = col(Text)
    token_hash: Mapped[str] = col(String(64))
    code_hash: Mapped[str] = col(String(64))
    code_attempts: Mapped[int] = col(Integer, default=0)
    status: Mapped[str] = col(String(24), default="pending_verification")   # pending_verification|open|upheld|rejected
    outcome: Mapped[str | None] = col(String(200), nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)
    resolved_at: Mapped[str | None] = col(String(32), nullable=True)


class Opportunity(Base):
    __tablename__ = "official_opportunities"
    id: Mapped[str] = col(String(60), primary_key=True)
    opportunity_type: Mapped[str] = col(String(16))                 # job | grant | bursary | programme
    official_name: Mapped[str] = col(String(160))
    administering_body: Mapped[str] = col(String(160))
    aliases: Mapped[list] = col(JSON, default=list)
    official_domain: Mapped[str] = col(String(120))
    application_url: Mapped[str | None] = col(String(300), nullable=True)
    eligibility: Mapped[str | None] = col(Text, nullable=True)
    counties: Mapped[list] = col(JSON, default=list)
    status: Mapped[str | None] = col(String(24), nullable=True)
    fee_policy: Mapped[str | None] = col(String(24), nullable=True)
    source_url: Mapped[str] = col(String(300))
    last_verified_at: Mapped[str] = col(String(10))
    review_due: Mapped[str] = col(String(10))
    reviewer: Mapped[str] = col(String(80), default="unreviewed")


class VerifiedRecord(Base):
    """Reviewed proof that a website or shop is genuine. It vouches for the site, never for an offer. Revocable at once; expires unless re-reviewed."""
    __tablename__ = "verified_entities"
    id: Mapped[str] = col(String(60), primary_key=True)
    name: Mapped[str] = col(String(160))
    entity_type: Mapped[str] = col(String(16))                      # organisation | online_shop | website | social_shop
    domains: Mapped[list] = col(JSON, default=list)
    handles: Mapped[list] = col(JSON, default=list)
    include_subdomains: Mapped[bool] = col(Boolean, default=False)
    basis: Mapped[str] = col(String(40))
    source_url: Mapped[str] = col(String(300))
    evidence_note: Mapped[str | None] = col(Text, nullable=True)
    last_verified_at: Mapped[str] = col(String(10))
    review_due: Mapped[str] = col(String(10))
    reviewer: Mapped[str] = col(String(80))
    status: Mapped[str] = col(String(12), default="active")         # active | revoked
    revoked_reason: Mapped[str | None] = col(String(60), nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)


class NEARegistrySnapshot(Base):
    """Moderator-imported snapshots of the public NEA agency register."""
    __tablename__ = "nea_registry_snapshots"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    source_url: Mapped[str] = col(String(300))
    data_as_of: Mapped[str] = col(String(10))
    retrieved_at: Mapped[str] = col(String(32), default=now_iso)
    content_sha256: Mapped[str] = col(String(64))
    record_count: Mapped[int] = col(Integer)
    invalid_rows: Mapped[int] = col(Integer, default=0)
    imported_by: Mapped[str] = col(ForeignKey("users.id", ondelete="RESTRICT"))
    status: Mapped[str] = col(String(16), default="active")  # active | superseded


class NEARegistryEntry(Base):
    """Only business-register fields and email domains are stored; no personal identifiers."""
    __tablename__ = "nea_registry_entries"
    __table_args__ = (UniqueConstraint("snapshot_id", "registration_number"),)
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    snapshot_id: Mapped[str] = col(ForeignKey("nea_registry_snapshots.id", ondelete="CASCADE"), index=True)
    registration_number: Mapped[str] = col(String(40), index=True)
    agency_name: Mapped[str] = col(String(180))
    normalized_name: Mapped[str] = col(String(180), index=True)
    service_type: Mapped[str] = col(String(100), default="")
    email_domains: Mapped[list] = col(JSON, default=list)
    website_domains: Mapped[list] = col(JSON, default=list)
    licence_status: Mapped[str] = col(String(16), default="unknown")
    valid_from: Mapped[str | None] = col(String(10), nullable=True)
    expires_on: Mapped[str | None] = col(String(10), nullable=True)
    row_sha256: Mapped[str] = col(String(64))


class BRSBusinessRecord(Base):
    """Minimised moderator-reviewed BRS result; never stores CR12 shareholder/director data."""
    __tablename__ = "brs_business_records"
    __table_args__ = (UniqueConstraint("registration_type", "registration_hmac"),)
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    registration_type: Mapped[str] = col(String(24))
    registration_hmac: Mapped[str] = col(String(64), index=True)
    registration_masked: Mapped[str] = col(String(48))
    registered_name: Mapped[str] = col(String(180))
    normalized_name: Mapped[str] = col(String(180), index=True)
    source_url: Mapped[str] = col(String(300))
    evidence_sha256: Mapped[str] = col(String(64))
    checked_at: Mapped[str] = col(String(10))
    review_due: Mapped[str] = col(String(10))
    reviewer_id: Mapped[str] = col(ForeignKey("users.id", ondelete="RESTRICT"))
    status: Mapped[str] = col(String(16), default="active")  # active | revoked
    created_at: Mapped[str] = col(String(32), default=now_iso)


class BRSBusinessAssociation(Base):
    """Separately reviewed link between a BRS entity and its public digital presence."""
    __tablename__ = "brs_business_associations"
    __table_args__ = (UniqueConstraint("business_record_id", "association_type", "normalized_value"),)
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    business_record_id: Mapped[str] = col(ForeignKey("brs_business_records.id", ondelete="CASCADE"), index=True)
    association_type: Mapped[str] = col(String(24))  # website_domain | social_profile | contact_email_domain
    value: Mapped[str] = col(String(255))
    normalized_value: Mapped[str] = col(String(255), index=True)
    source_url: Mapped[str] = col(String(500))
    evidence_sha256: Mapped[str] = col(String(64))
    reviewed_at: Mapped[str] = col(String(10))
    review_due: Mapped[str] = col(String(10))
    reviewer_id: Mapped[str] = col(ForeignKey("users.id", ondelete="RESTRICT"))
    status: Mapped[str] = col(String(16), default="active")  # active | revoked
    created_at: Mapped[str] = col(String(32), default=now_iso)


class SourceObservation(Base):
    __tablename__ = "source_observations"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    check_id: Mapped[str] = col(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = col(String(60))
    claim_type: Mapped[str] = col(String(30))
    result: Mapped[str] = col(String(24))                           # checked | could_not_check | not_checked
    detail: Mapped[str] = col(String(300), default="")
    fetched_at: Mapped[str] = col(String(32), default=now_iso)
    valid_until: Mapped[str | None] = col(String(40), nullable=True)


class RiskSignal(Base):
    __tablename__ = "risk_signals"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    check_id: Mapped[str] = col(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    signal_code: Mapped[str] = col(String(48))
    severity_band: Mapped[str] = col(String(12))
    provenance_type: Mapped[str] = col(String(24))
    evidence_ref: Mapped[str | None] = col(String(80), nullable=True)
    rule_version: Mapped[str] = col(String(32))


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    check_id: Mapped[str] = col(ForeignKey("checks.id", ondelete="CASCADE"), index=True)
    status_label: Mapped[str] = col(String(32))
    summary: Mapped[str] = col(Text)
    policy_version: Mapped[str] = col(String(32))
    created_at: Mapped[str] = col(String(32), default=now_iso)
    reviewed_by: Mapped[str | None] = col(String(36), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str | None] = col(String(36), nullable=True)
    action: Mapped[str] = col(String(48))
    target_type: Mapped[str] = col(String(24))
    target_id: Mapped[str | None] = col(String(60), nullable=True)
    request_id: Mapped[str | None] = col(String(64), nullable=True)
    safe_metadata: Mapped[dict | None] = col(JSON, nullable=True)
    timestamp: Mapped[str] = col(String(32), default=now_iso)


class Notification(Base):
    """Outbox. Nothing is sent from here yet; a delivery worker would drain it."""
    __tablename__ = "notifications"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = col(String(36), nullable=True)
    channel: Mapped[str] = col(String(12))
    template: Mapped[str] = col(String(40))
    to_encrypted: Mapped[str] = col(Text)
    payload_encrypted: Mapped[str] = col(Text)
    status: Mapped[str] = col(String(20), default="queued")
    consent_context: Mapped[str] = col(String(60))
    created_at: Mapped[str] = col(String(32), default=now_iso)
    sent_at: Mapped[str | None] = col(String(32), nullable=True)


class SourceSnapshot(Base):
    """Last seen text hash of an official page, so a change prompts a human review (docs/process, section B)."""
    __tablename__ = "source_snapshots"
    url: Mapped[str] = col(String(300), primary_key=True)
    text_sha256: Mapped[str] = col(String(64))
    text_length: Mapped[int] = col(Integer)
    fetched_at: Mapped[str] = col(String(32), default=now_iso)


class BusinessClaim(Base):
    __tablename__ = "business_claims"
    id: Mapped[str] = col(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = col(ForeignKey("users.id", ondelete="CASCADE"))
    business_name: Mapped[str] = col(String(160))
    domain: Mapped[str | None] = col(String(120), nullable=True)
    note_encrypted: Mapped[str | None] = col(Text, nullable=True)
    status: Mapped[str] = col(String(16), default="pending")        # pending | approved | rejected
    reviewed_by: Mapped[str | None] = col(String(36), nullable=True)
    reason_code: Mapped[str | None] = col(String(40), nullable=True)
    created_at: Mapped[str] = col(String(32), default=now_iso)


Index("ix_subject_lookup", Subject.subject_type, Subject.lookup_hmac)


def make_engine(url: str):
    if url.startswith("sqlite"):
        if url.startswith("sqlite:///"):
            db_file = url[len("sqlite:///"):]
            if not db_file.startswith(":memory:") and db_file:
                import os
                db_dir = os.path.dirname(db_file)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
        memory = ":memory:" in url or url in ("sqlite://", "sqlite:///:memory:")
        kw = {"poolclass": StaticPool} if memory else {}
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}, **kw)

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")          # SQLite ignores foreign keys (and ON DELETE CASCADE) unless asked
            dbapi_conn.execute("PRAGMA busy_timeout=30000")
            if not memory:
                dbapi_conn.execute("PRAGMA journal_mode=WAL")      # readers no longer block the writer
                dbapi_conn.execute("PRAGMA synchronous=NORMAL")
        return engine
    return create_engine(url, pool_pre_ping=True)


def make_sessionmaker(engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)
