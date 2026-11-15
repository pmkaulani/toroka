"""Tests for append-only cryptographic audit chain integrity and tamper evidence."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from toroka_enterprise_api.persistence.audit import (
    GENESIS_HASH,
    append_audit,
    filter_safe_metadata,
    verify_audit_chain,
)
from toroka_enterprise_api.persistence.models import AuditHead, AuditRecord


def test_audit_chain_verification_and_linkage(db_session):
    inst_id = "toroka-default-installation"

    # Initially empty chain
    is_valid, head_hash, count = verify_audit_chain(db_session, inst_id)
    assert is_valid is True
    assert head_hash == GENESIS_HASH
    assert count == 0

    # Append 3 audit events
    h1 = append_audit(
        db_session,
        installation_id=inst_id,
        actor_subject="investigator.alice",
        actor_role="investigator",
        action="case_created",
        target_type="case",
        target_id="case-001",
        safe_metadata={"case_id": "case-001"},
    )
    h2 = append_audit(
        db_session,
        installation_id=inst_id,
        actor_subject="investigator.alice",
        actor_role="investigator",
        action="case_note_added",
        target_type="case",
        target_id="case-001",
        safe_metadata={"case_id": "case-001"},
    )
    h3 = append_audit(
        db_session,
        installation_id=inst_id,
        actor_subject="authoriser.charlie",
        actor_role="authoriser",
        action="reveal_approved",
        target_type="reveal_request",
        target_id="req-001",
        safe_metadata={"case_id": "case-001"},
    )
    db_session.commit()

    # Verify chain
    is_valid, final_hash, verified_count = verify_audit_chain(db_session, inst_id)
    assert is_valid is True
    assert final_hash == h3
    assert verified_count == 3

    # Check linkage
    records = db_session.execute(
        select(AuditRecord).order_by(AuditRecord.sequence.asc())
    ).scalars().all()
    assert records[0].previous_hash == GENESIS_HASH
    assert records[0].event_hash == h1
    assert records[1].previous_hash == h1
    assert records[1].event_hash == h2
    assert records[2].previous_hash == h2
    assert records[2].event_hash == h3


def test_audit_tamper_detection(db_session):
    inst_id = "toroka-default-installation"

    append_audit(
        db_session,
        installation_id=inst_id,
        actor_subject="investigator.alice",
        actor_role="investigator",
        action="case_created",
        target_type="case",
        target_id="case-002",
        safe_metadata={"case_id": "case-002"},
    )
    db_session.commit()

    # Tamper with an audit record in the database
    rec = db_session.execute(
        select(AuditRecord).where(AuditRecord.target_id == "case-002")
    ).scalar_one()
    rec.actor_subject = "attacker.mallory"  # Malicious alteration
    db_session.commit()

    is_valid, _, _ = verify_audit_chain(db_session, inst_id)
    assert is_valid is False  # Tampering detected!


def test_audit_metadata_filtering_strictly_excludes_sensitive_keys():
    meta = {
        "case_id": "C-12345",
        "reason": "Suspicious transaction review",
        "raw_staff_id": "S9999",             # FORBIDDEN
        "password": "supersecretpassword",   # FORBIDDEN
        "bearer_token": "eyJh...",           # FORBIDDEN
        "salary_account": "0110928374",      # FORBIDDEN
    }
    filtered = filter_safe_metadata(meta)
    assert "case_id" in filtered
    assert "reason" in filtered
    assert "raw_staff_id" not in filtered
    assert "password" not in filtered
    assert "bearer_token" not in filtered
    assert "salary_account" not in filtered
