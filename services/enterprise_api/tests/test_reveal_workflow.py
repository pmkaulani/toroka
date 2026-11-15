"""Tests for identity reveal requests, dual-approval, single-use consumption, and audit privacy."""
from __future__ import annotations

from datetime import timedelta

import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.persistence.models import utc_now


@pytest.fixture
def inv_alice():
    return EnterprisePrincipal(
        subject="investigator.alice",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )


@pytest.fixture
def inv_bob():
    return EnterprisePrincipal(
        subject="investigator.bob",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )


@pytest.fixture
def auth_charlie():
    return EnterprisePrincipal(
        subject="authoriser.charlie",
        roles=frozenset({"authoriser"}),
        issuer="test-idp",
    )


def test_reveal_request_approval_and_single_use_consume(
    test_case_service, test_reveal_service, test_vault_repo, inv_alice, auth_charlie
):
    # 1. Setup case and seed identity vault
    case = test_case_service.create_case(
        inv_alice,
        installation_id="toroka-default-installation",
        label="payroll_beneficiary_integrity",
        focus="STF-REVEAL-01",
        snapshot={},
        manifest_id="manifest-reveal",
        assign_to_subject="investigator.alice",
    )
    pseudonym = "STF-REVEAL-01"
    plaintext_identity = "STAFF-EMP-98765"
    test_vault_repo.store(pseudonym, plaintext_identity)

    # 2. Investigator requests reveal
    req = test_reveal_service.request_reveal(
        inv_alice,
        case_id=case.id,
        pseudonym=pseudonym,
        reason="Confirm employee identity before disciplinary referral.",
        ttl_hours=24,
    )
    assert req.status == "pending"
    assert req.requested_by == "investigator.alice"

    # Pending request cannot be consumed
    with pytest.raises(ValueError, match="not approved"):
        test_reveal_service.consume_reveal(inv_alice, request_id=req.id)

    # 3. Authoriser approves request
    approved = test_reveal_service.approve_reveal(auth_charlie, request_id=req.id)
    assert approved.status == "approved"
    assert approved.approved_by == "authoriser.charlie"

    # 4. Requester consumes reveal (single use)
    revealed = test_reveal_service.consume_reveal(inv_alice, request_id=req.id)
    assert revealed == plaintext_identity

    # Request is marked used
    req_after = test_reveal_service.reveals.get_by_id(req.id)
    assert req_after.status == "used"
    assert req_after.used_at is not None

    # 5. Second consumption attempt fails (cannot reuse single-use token)
    with pytest.raises(ValueError, match="already been consumed"):
        test_reveal_service.consume_reveal(inv_alice, request_id=req.id)


def test_reveal_self_approval_blocked(
    test_case_service, test_reveal_service, inv_alice
):
    case = test_case_service.create_case(
        inv_alice,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-SELF-01",
        snapshot={},
        manifest_id="manifest-self",
    )

    req = test_reveal_service.request_reveal(
        inv_alice,
        case_id=case.id,
        pseudonym="STF-SELF-01",
        reason="Legitimate written explanation.",
    )

    # Dual role user (investigator + authoriser) attempting to approve their own request
    dual_alice = EnterprisePrincipal(
        subject="investigator.alice",
        roles=frozenset({"investigator", "authoriser"}),
        issuer="test-idp",
    )

    with pytest.raises(PermissionError, match="Self-approval blocked"):
        test_reveal_service.approve_reveal(dual_alice, request_id=req.id)


def test_reveal_expired_request_fails(
    test_case_service, test_reveal_service, inv_alice, auth_charlie
):
    case = test_case_service.create_case(
        inv_alice,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-EXP-01",
        snapshot={},
        manifest_id="manifest-exp",
    )
    req = test_reveal_service.request_reveal(
        inv_alice,
        case_id=case.id,
        pseudonym="STF-EXP-01",
        reason="Explanation for review.",
    )

    # Force expiration
    req_db = test_reveal_service.reveals.get_by_id(req.id)
    req_db.expires_at = utc_now() - timedelta(hours=1)
    test_reveal_service.db.commit()

    with pytest.raises(ValueError, match="expired"):
        test_reveal_service.approve_reveal(auth_charlie, request_id=req.id)


def test_reveal_rejected_cannot_be_consumed(
    test_case_service, test_reveal_service, inv_alice, auth_charlie
):
    case = test_case_service.create_case(
        inv_alice,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-REJ-01",
        snapshot={},
        manifest_id="manifest-rej",
    )
    req = test_reveal_service.request_reveal(
        inv_alice,
        case_id=case.id,
        pseudonym="STF-REJ-01",
        reason="Explanation for review.",
    )

    rejected = test_reveal_service.reject_reveal(
        auth_charlie,
        request_id=req.id,
        rejection_reason="Insufficient evidentiary justification provided.",
    )
    assert rejected.status == "rejected"
    assert rejected.rejection_reason == "Insufficient evidentiary justification provided."

    with pytest.raises(ValueError, match="not approved"):
        test_reveal_service.consume_reveal(inv_alice, request_id=req.id)


def test_reveal_cannot_be_consumed_by_different_investigator(
    test_case_service, test_reveal_service, test_vault_repo, inv_alice, inv_bob, auth_charlie
):
    case = test_case_service.create_case(
        inv_alice,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-DIFF-01",
        snapshot={},
        manifest_id="manifest-diff",
    )
    test_vault_repo.store("STF-DIFF-01", "REAL-STAFF-ID")

    req = test_reveal_service.request_reveal(
        inv_alice,
        case_id=case.id,
        pseudonym="STF-DIFF-01",
        reason="Reason for investigation.",
    )
    test_reveal_service.approve_reveal(auth_charlie, request_id=req.id)

    # Bob tries to consume Alice's approved reveal
    with pytest.raises(PermissionError, match="Only the original requesting investigator"):
        test_reveal_service.consume_reveal(inv_bob, request_id=req.id)
