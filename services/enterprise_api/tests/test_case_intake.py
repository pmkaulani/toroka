"""Tests for trusted case intake workflow and deduplication."""
from __future__ import annotations

from toroka_enterprise_api.persistence.models import RunRecord


def test_trusted_case_intake_and_deduplication(oidc_client, token_factory):
    bob_token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    dave_token = token_factory(sub="steward.dave", roles=["BANK_DATA_STEWARD"])
    alice_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    manifest_id = "manifest-scan-2026-11-15"
    leads = [
        {
            "label": "PRIORITY REVIEW",
            "focus": "staff:S901/customer:C001",
            "verdict": "FLAGGED",
            "risk_index": 92,
        },
        {
            "label": "REVIEW",
            "focus": "staff:S902",
            "verdict": "SUSPICIOUS",
            "risk_index": 68,
        },
    ]

    # 1. Attempting intake before recording run manifest fails with 404
    err_res = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": manifest_id,
            "leads": leads,
        },
    )
    assert err_res.status_code == 404
    assert "not found" in err_res.json()["detail"]

    # 2. Data steward attempting intake is denied with 403
    steward_res = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {dave_token}"},
        json={
            "manifest_id": manifest_id,
            "leads": leads,
        },
    )
    assert steward_res.status_code == 403

    # 3. Record run manifest
    with oidc_client.app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="toroka-default-installation",
                manifest_id=manifest_id,
                manifest={"manifest_id": manifest_id, "leads": leads},
                created_by="system",
            )
        )
        db.commit()

    # 4. First intake run creates cases
    res1 = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": manifest_id,
            "leads": leads,
            "assign_to_subject": "investigator.alice",
        },
    )
    assert res1.status_code == 201
    data1 = res1.json()
    assert data1["created_count"] == 2
    assert data1["existing_count"] == 0
    assert len(data1["case_ids"]) == 2

    # 5. Second intake with same manifest and leads is idempotent (0 created, 2 existing)
    res2 = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": manifest_id,
            "leads": leads,
            "assign_to_subject": "investigator.alice",
        },
    )
    assert res2.status_code == 201
    data2 = res2.json()
    assert data2["created_count"] == 0
    assert data2["existing_count"] == 2
    assert data2["case_ids"] == data1["case_ids"]

    # 6. Verify investigator sees their assigned cases
    my_cases = oidc_client.get(
        "/api/enterprise/v1/cases",
        headers={"Authorization": f"Bearer {alice_token}"},
    ).json()
    assert my_cases["total"] == 2
