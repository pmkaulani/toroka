"""Append-only, transaction-bound hash chain audit log."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditHead, AuditRecord

GENESIS_HASH = "0" * 64

# Strict allowlist of safe audit metadata fields
# Never log raw employee IDs, raw customer accounts, passwords, bearer tokens, or decrypted identities
ALLOWED_METADATA_KEYS = frozenset({
    "case_id",
    "proposal_id",
    "manifest_id",
    "pseudonym",
    "reason",
    "disposition",
    "disposition_label",
    "assigned_subject",
    "assignment_role",
    "actor_role",
    "status",
    "version",
    "expected_case_version",
    "reviewed_by",
    "review_note",
    "requested_by",
    "count",
    "error",
    "error_type",
    "installation_id",
    "action",
    "contradiction_id",
    "reconstruction_id",
    "simulation_id",
    "strategy_id",
    "strategy_version",
    "approval_id",
    "decision",
    "label",
    "pattern_id",
    "pattern_version",
    "review_id",
    "match_id",
    "query_case_id",
    "target_id",
    "lifecycle_status",
    "eligible_for_review",
    "node_key",
    "edge_id",
    "candidate_id",
    "finding_id",
    "snapshot_id",
    "run_id",
    "depth",
    "max_depth",
    "include_shared_attributes",
    "pattern_type",
    "anchor_entity",
    "new_status",
    "previous_status",
    # Copilot Phase 11
    "thread_id",
    "message_id",
    "draft_id",
    "feedback_id",
    "task_type",
    "report_type",
    "verified_claims",
    "rejected_claims_count",
    "tools_called",
    "rating",
    "grounding_valid",
    # Production Governance Phase 12
    "component_id",
    "component_version",
    "component_type",
    "risk_tier",
    "run_id",
    "validation_result",
    "release_id",
    "environment",
    "suspension_id",
    "incident_id",
    "incident_severity",
    "drift_id",
    "drift_type",
    "passport_id",
    "provider_id",
    "gate_name",
    "gate_status",
    "is_production_ready",
    # Phase 12.6 Production Integrity additions
    "previous_content_digest",
    "content_digest",
    "edit_version",
    "grounding_status",
    "attestation_id",
    "verified_role",
    "evidence_digest",
    "evidence_reference",
    "proposed_by",
    "first_reviewed_by",
    "second_reviewed_by",
    # Investigation Intelligence & Referral Pack
    "pack_hash",
    "recipient_org",
    "sha256",
    "source_type",
    "approver",
})


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def filter_safe_metadata(metadata: dict | None) -> dict:
    """Filter metadata against strict allowlist to guarantee no PII or secret leakage."""
    if not metadata:
        return {}
    return {
        k: str(v) if not isinstance(v, (int, float, bool, list, dict)) else v
        for k, v in metadata.items()
        if k in ALLOWED_METADATA_KEYS
    }


def append_audit(
    db: Session,
    *,
    installation_id: str,
    actor_subject: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str | None,
    safe_metadata: dict | None = None,
) -> str:
    """Append a cryptographic audit event atomically within the active transaction."""
    head = db.execute(
        select(AuditHead)
        .where(AuditHead.installation_id == installation_id)
        .with_for_update()
    ).scalar_one_or_none()

    if head is None:
        head = AuditHead(
            installation_id=installation_id,
            last_sequence=0,
            last_hash=GENESIS_HASH,
        )
        db.add(head)
        db.flush()

    now = datetime.now(timezone.utc)
    sequence = head.last_sequence + 1
    metadata = filter_safe_metadata(safe_metadata)
    canonical = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    previous_hash = head.last_hash
    payload = json.dumps(
        [
            installation_id,
            sequence,
            now.isoformat(),
            actor_subject,
            actor_role,
            action,
            target_type,
            target_id,
            canonical,
            previous_hash,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    record = AuditRecord(
        installation_id=installation_id,
        sequence=sequence,
        actor_subject=actor_subject,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=target_id,
        safe_metadata=metadata,
        created_at=now,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    db.add(record)
    head.last_sequence = sequence
    head.last_hash = event_hash
    db.flush()
    return event_hash


def verify_audit_chain(db: Session, installation_id: str) -> tuple[bool, str, int]:
    """Verify the complete cryptographic audit chain for an installation.

    Returns:
        (is_valid, current_head_hash, total_records_verified)
    """
    head = db.execute(
        select(AuditHead).where(AuditHead.installation_id == installation_id)
    ).scalar_one_or_none()

    if head is None:
        return False, "", 0

    records = db.execute(
        select(AuditRecord)
        .where(AuditRecord.installation_id == installation_id)
        .order_by(AuditRecord.sequence.asc())
    ).scalars().all()

    if not records:
        return head.last_hash == GENESIS_HASH and head.last_sequence == 0, head.last_hash, 0

    expected_prev = GENESIS_HASH
    for idx, rec in enumerate(records):
        expected_seq = idx + 1
        if rec.sequence != expected_seq:
            return False, head.last_hash, idx

        if rec.previous_hash != expected_prev:
            return False, head.last_hash, idx

        canonical = json.dumps(
            rec.safe_metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        dt_str = _ensure_utc(rec.created_at).isoformat()
        payload = json.dumps(
            [
                rec.installation_id,
                rec.sequence,
                dt_str,
                rec.actor_subject,
                rec.actor_role,
                rec.action,
                rec.target_type,
                rec.target_id,
                canonical,
                rec.previous_hash,
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        )
        computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if computed_hash != rec.event_hash:
            return False, head.last_hash, idx

        expected_prev = rec.event_hash

    if expected_prev != head.last_hash:
        return False, head.last_hash, len(records)

    return True, head.last_hash, len(records)
