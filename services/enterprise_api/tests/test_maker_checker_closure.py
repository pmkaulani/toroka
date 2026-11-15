"""Tests for maker-checker case closure workflow and governance."""
from __future__ import annotations

from toroka_enterprise_api.persistence.models import RunRecord


def test_investigator_propose_and_authoriser_review_closure(oidc_client, token_factory):
    alice_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    bob_token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    charlie_token = token_factory(sub="investigator.charlie", roles=["BANK_INVESTIGATOR"])
    alice_dual_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])

    # 1. Attempting intake before recording manifest fails with 404
    res_err = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": "man-test-1",
            "leads": [
                {
                    "label": "PRIORITY REVIEW",
                    "focus": "staff:S1001",
                    "verdict": "FLAGGED",
                    "risk_index": 75,
                }
            ],
            "assign_to_subject": "investigator.alice",
        },
    )
    assert res_err.status_code == 404

    # Record the run first in db
    with oidc_client.app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="toroka-default-installation",
                manifest_id="man-test-1",
                manifest={"manifest_id": "man-test-1", "leads": [{"focus": "staff:S1001"}]},
                created_by="system",
            )
        )
        db.commit()

    # Now intake succeeds
    res = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": "man-test-1",
            "leads": [
                {
                    "label": "PRIORITY REVIEW",
                    "focus": "staff:S1001",
                    "verdict": "FLAGGED",
                    "risk_index": 75,
                }
            ],
            "assign_to_subject": "investigator.alice",
        },
    )
    assert res.status_code == 201
    case_id = res.json()["case_ids"][0]

    # 2. Unassigned investigator Charlie cannot propose closure
    unassigned_res = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/propose-closure",
        headers={"Authorization": f"Bearer {charlie_token}"},
        json={
            "disposition": "not_substantiated",
            "closing_note": "Legitimate business purpose confirmed.",
            "alternatives_considered": "Considered payroll diversion, confirmed valid project code.",
            "expected_case_version": 1,
        },
    )
    assert unassigned_res.status_code == 404

    # 3. Assigned investigator Alice proposes closure
    prop_res = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/propose-closure",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "disposition": "not_substantiated",
            "closing_note": "Legitimate business purpose confirmed with branch manager.",
            "alternatives_considered": "Considered payroll diversion, confirmed valid project code.",
            "expected_case_version": 1,
        },
    )
    assert prop_res.status_code == 201
    proposal = prop_res.json()
    assert proposal["status"] == "pending"
    assert proposal["requested_by"] == "investigator.alice"
    assert proposal["disposition"] == "not_substantiated"
    proposal_id = proposal["id"]

    # 4. Duplicate proposal while one is pending is rejected
    dup_res = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/propose-closure",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "disposition": "not_substantiated",
            "closing_note": "Second proposal",
            "alternatives_considered": "None",
            "expected_case_version": 1,
        },
    )
    assert dup_res.status_code == 400
    assert "already pending" in dup_res.json()["detail"]

    # 5. Dual approval check: Alice holds authoriser role too, but cannot approve her own proposal!
    self_appr = oidc_client.post(
        f"/api/enterprise/v1/closure-proposals/{proposal_id}/review",
        headers={"Authorization": f"Bearer {alice_dual_token}"},
        json={
            "approve": True,
            "review_note": "Self-approval attempt",
        },
    )
    assert self_appr.status_code == 403
    assert "Self-approval blocked" in self_appr.json()["detail"]

    # 6. Authoriser Bob approves closure
    auth_appr = oidc_client.post(
        f"/api/enterprise/v1/closure-proposals/{proposal_id}/review",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "approve": True,
            "review_note": "Reviewed branch manager confirmation. Approved closure.",
        },
    )
    assert auth_appr.status_code == 200
    assert auth_appr.json()["status"] == "approved"
    assert auth_appr.json()["reviewed_by"] == "authoriser.bob"

    # 7. Check case is now closed
    case_res = oidc_client.get(
        f"/api/enterprise/v1/cases/{case_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert case_res.status_code == 200
    case_data = case_res.json()
    assert case_data["status"] == "closed"
    assert case_data["disposition"] == "not_substantiated"
    assert case_data["version"] == 2


def test_authoriser_rejection_leaves_case_open(oidc_client, token_factory):
    alice_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    bob_token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])

    with oidc_client.app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="toroka-default-installation",
                manifest_id="man-test-2",
                manifest={"manifest_id": "man-test-2", "leads": [{"focus": "staff:S2002"}]},
                created_by="system",
            )
        )
        db.commit()

    oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": "man-test-2",
            "leads": [{"label": "REVIEW", "focus": "staff:S2002"}],
            "assign_to_subject": "investigator.alice",
        },
    )

    cases = oidc_client.get(
        "/api/enterprise/v1/cases",
        headers={"Authorization": f"Bearer {alice_token}"},
    ).json()["items"]
    case_id = cases[0]["id"]

    # Propose closure
    prop = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/propose-closure",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "disposition": "not_substantiated",
            "closing_note": "Insufficient evidence to pursue.",
            "alternatives_considered": "None checked.",
            "expected_case_version": 1,
        },
    ).json()

    # Authoriser rejects proposal
    rej = oidc_client.post(
        f"/api/enterprise/v1/closure-proposals/{prop['id']}/review",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "approve": False,
            "review_note": "Please request identity reveal and interview line manager before closing.",
        },
    )
    assert rej.status_code == 200
    assert rej.json()["status"] == "rejected"
    assert rej.json()["review_note"] == "Please request identity reveal and interview line manager before closing."

    # Case remains open!
    case = oidc_client.get(
        f"/api/enterprise/v1/cases/{case_id}",
        headers={"Authorization": f"Bearer {alice_token}"},
    ).json()
    assert case["status"] == "open"
    assert case["version"] == 1
