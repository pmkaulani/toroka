"""API endpoint integration tests for Cases, Notes, Reveals, Runs, and Readiness."""
from __future__ import annotations

import pytest


def test_api_health_ready_check(oidc_client):
    resp = oidc_client.get("/health/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["persistence"] == "connected"
    assert data["vault"] == "connected"


def test_api_capabilities_reports_active_casework(oidc_client, token_factory):
    token = token_factory(roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/capabilities",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["casework_api"] is True
    assert data["production_persistence"] is True


def test_api_data_steward_blocked_from_cases(oidc_client, token_factory):
    token = token_factory(roles=["BANK_DATA_STEWARD"])
    resp = oidc_client.get(
        "/api/enterprise/v1/cases",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "not permitted" in resp.json()["detail"]


def test_api_case_lifecycle_notes_and_close(oidc_client, token_factory, test_case_service):
    # Setup test case in db
    alice_principal = test_case_service._assert_can_access_cases
    from toroka_enterprise_api.auth import EnterprisePrincipal
    p = EnterprisePrincipal("investigator.alice", frozenset({"investigator"}), "test")
    case = test_case_service.create_case(
        p,
        installation_id="toroka-default-installation",
        label="payroll_beneficiary_integrity",
        focus="STF-API-CASE-01",
        snapshot={"detail": "sample"},
        assign_to_subject="investigator.alice",
    )

    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # 1. Retrieve case
    r1 = oidc_client.get(
        f"/api/enterprise/v1/cases/{case.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 200
    assert r1.json()["id"] == case.id
    assert r1.json()["status"] == "open"

    # 2. Add note
    r2 = oidc_client.post(
        f"/api/enterprise/v1/cases/{case.id}/notes",
        headers={"Authorization": f"Bearer {token}"},
        json={"body": "Investigated payroll discrepancy with HR."},
    )
    assert r2.status_code == 201
    assert r2.json()["body"] == "Investigated payroll discrepancy with HR."

    # 3. Retrieve notes
    r3 = oidc_client.get(
        f"/api/enterprise/v1/cases/{case.id}/notes",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r3.status_code == 200
    assert len(r3.json()) == 1

    # 4. Close case
    r4 = oidc_client.post(
        f"/api/enterprise/v1/cases/{case.id}/close",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "disposition": "substantiated_referral",
            "closing_note": "Disciplinary referral forwarded to HR.",
            "alternatives_considered": "Ruled out system accounting glitch.",
            "expected_version": 1,
        },
    )
    assert r4.status_code == 200
    assert r4.json()["status"] == "closed"
    assert r4.json()["version"] == 2


def test_api_reveal_endpoints_end_to_end(
    oidc_client, token_factory, test_case_service, test_vault_repo
):
    from toroka_enterprise_api.auth import EnterprisePrincipal
    p = EnterprisePrincipal("investigator.alice", frozenset({"investigator"}), "test")
    case = test_case_service.create_case(
        p,
        installation_id="toroka-default-installation",
        label="suspense_posting_integrity",
        focus="STF-API-REV-01",
        snapshot={},
        assign_to_subject="investigator.alice",
    )
    test_vault_repo.store("STF-API-REV-01", "STAFF-REAL-IDENTIFIER-999")

    alice_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    charlie_token = token_factory(sub="authoriser.charlie", roles=["BANK_AUTHORISER"])

    # 1. Investigator requests reveal
    r1 = oidc_client.post(
        f"/api/enterprise/v1/cases/{case.id}/reveal-requests",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "pseudonym": "STF-API-REV-01",
            "reason": "Verify identity for disciplinary report submission.",
            "ttl_hours": 24,
        },
    )
    assert r1.status_code == 201
    req_id = r1.json()["id"]

    # 2. Authoriser lists pending requests
    r2 = oidc_client.get(
        "/api/enterprise/v1/reveal-requests",
        headers={"Authorization": f"Bearer {charlie_token}"},
    )
    assert r2.status_code == 200
    assert any(req["id"] == req_id for req in r2.json())

    # 3. Authoriser approves request
    r3 = oidc_client.post(
        f"/api/enterprise/v1/reveal-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {charlie_token}"},
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "approved"

    # 4. Requester consumes reveal (single use)
    r4 = oidc_client.post(
        f"/api/enterprise/v1/reveal-requests/{req_id}/consume",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r4.status_code == 200
    assert r4.json()["plaintext_identity"] == "STAFF-REAL-IDENTIFIER-999"

    # 5. Repeat consumption fails
    r5 = oidc_client.post(
        f"/api/enterprise/v1/reveal-requests/{req_id}/consume",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert r5.status_code == 400
    assert "already been consumed" in r5.json()["detail"]
