"""Tests for operational case persistence, assignments, notes, concurrency, and closures."""
from __future__ import annotations

import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.persistence.models import EnterpriseCase


@pytest.fixture
def inv_principal():
    return EnterprisePrincipal(
        subject="investigator.alice",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )


@pytest.fixture
def other_inv_principal():
    return EnterprisePrincipal(
        subject="investigator.bob",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )


@pytest.fixture
def auth_principal():
    return EnterprisePrincipal(
        subject="authoriser.charlie",
        roles=frozenset({"authoriser"}),
        issuer="test-idp",
    )


@pytest.fixture
def auditor_principal():
    return EnterprisePrincipal(
        subject="auditor.dan",
        roles=frozenset({"auditor"}),
        issuer="test-idp",
    )


def test_case_creation_and_deduplication(test_case_service, inv_principal):
    case1 = test_case_service.create_case(
        inv_principal,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-12345/CUS-67890",
        snapshot={"events": 5, "risk": "high"},
        manifest_id="manifest-001",
    )
    assert case1.id is not None
    assert case1.status == "open"
    assert case1.version == 1

    # Creating identical case with same manifest and focus should return existing case
    case2 = test_case_service.create_case(
        inv_principal,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-12345/CUS-67890",
        snapshot={"events": 5, "risk": "high"},
        manifest_id="manifest-001",
    )
    assert case2.id == case1.id


def test_investigator_assignment_restrictions(
    test_case_service, inv_principal, other_inv_principal, auth_principal
):
    # Case created and assigned to Alice
    case = test_case_service.create_case(
        inv_principal,
        installation_id="toroka-default-installation",
        label="payroll_beneficiary_integrity",
        focus="STF-ALICE-01",
        snapshot={"salary_entries": 3},
        manifest_id="manifest-002",
        assign_to_subject="investigator.alice",
    )

    # Alice can get the case
    retrieved = test_case_service.get_case(inv_principal, case.id)
    assert retrieved.id == case.id

    # Bob (unassigned investigator) cannot get the case (raises LookupError to avoid disclosure)
    with pytest.raises(LookupError, match="Case not found"):
        test_case_service.get_case(other_inv_principal, case.id)

    # Bob's case list does not include Alice's case
    bob_cases, count = test_case_service.list_cases(
        other_inv_principal, "toroka-default-installation"
    )
    assert not any(c.id == case.id for c in bob_cases)

    # Authoriser assigns Bob to the case
    test_case_service.assign_case(
        auth_principal, case.id, "investigator.bob", "investigator"
    )

    # Now Bob can access the case
    retrieved_by_bob = test_case_service.get_case(other_inv_principal, case.id)
    assert retrieved_by_bob.id == case.id


def test_case_notes_are_append_only(test_case_service, inv_principal):
    case = test_case_service.create_case(
        inv_principal,
        installation_id="toroka-default-installation",
        label="auth_channel_change",
        focus="STF-NOTE-01",
        snapshot={},
        manifest_id="manifest-003",
    )

    note1 = test_case_service.add_note(
        inv_principal, case.id, "Initial investigation note."
    )
    assert note1.id is not None
    assert note1.body == "Initial investigation note."
    assert note1.author_subject == "investigator.alice"

    note2 = test_case_service.add_note(
        inv_principal, case.id, "Follow-up audit evidence checked."
    )
    assert note2.id != note1.id

    notes = test_case_service.notes.list_notes_for_case(case.id)
    assert len(notes) == 2
    assert notes[0].body == "Initial investigation note."
    assert notes[1].body == "Follow-up audit evidence checked."


def test_case_closure_validation_and_optimistic_locking(
    test_case_service, inv_principal
):
    case = test_case_service.create_case(
        inv_principal,
        installation_id="toroka-default-installation",
        label="account_lifecycle",
        focus="STF-CLOSE-01",
        snapshot={},
        manifest_id="manifest-004",
    )

    # Closing without alternatives considered fails
    with pytest.raises(ValueError, match="alternative explanations"):
        test_case_service.close_case(
            inv_principal,
            case.id,
            disposition="substantiated_referral",
            closing_note="Confirmed unauthorised reactivation.",
            alternatives_considered="   ",
            expected_version=1,
        )

    # Closing with invalid disposition fails
    with pytest.raises(ValueError, match="Invalid disposition"):
        test_case_service.close_case(
            inv_principal,
            case.id,
            disposition="random_invalid_status",
            closing_note="Done.",
            alternatives_considered="None.",
            expected_version=1,
        )

    # Optimistic concurrency conflict: wrong version
    with pytest.raises(ValueError, match="Concurrent modification conflict"):
        test_case_service.close_case(
            inv_principal,
            case.id,
            disposition="substantiated_referral",
            closing_note="Closing note.",
            alternatives_considered="Customer mandate was missing.",
            expected_version=99,
        )

    # Successful close
    closed = test_case_service.close_case(
        inv_principal,
        case.id,
        disposition="substantiated_referral",
        closing_note="Investigation completed with full audit trail.",
        alternatives_considered="Ruled out system migration and core-banking batch error.",
        expected_version=1,
    )
    assert closed.status == "closed"
    assert closed.version == 2
    assert closed.closed_at is not None

    # Cannot close already closed case
    with pytest.raises(ValueError, match="already closed"):
        test_case_service.close_case(
            inv_principal,
            case.id,
            disposition="not_substantiated",
            closing_note="Another note.",
            alternatives_considered="None.",
            expected_version=2,
        )


def test_run_manifest_persistence(test_run_service, inv_principal):
    manifest = {
        "manifest_id": "run-manifest-999",
        "contract_version": "2.0.0",
        "contract_fingerprint": "3d2fa5df86a37dc1903b55ef3f4318819395842dcc8d901a931f7bed9c769c40",
        "sources": {"audit_log": "hash123", "postings": "hash456"},
    }
    run = test_run_service.record_run(
        inv_principal,
        installation_id="toroka-default-installation",
        manifest=manifest,
        result_digest="digest-abc-123",
        status="completed",
    )
    assert run.manifest_id == "run-manifest-999"

    retrieved = test_run_service.get_run(inv_principal, "run-manifest-999")
    assert retrieved.manifest["contract_version"] == "2.0.0"
    assert retrieved.result_digest == "digest-abc-123"
