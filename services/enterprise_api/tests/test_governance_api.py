"""Tests for governance endpoints: overview, case timeline, and audit verification."""
from __future__ import annotations

from toroka_enterprise_api.persistence.models import RunRecord


def test_workbench_overview_and_role_views(oidc_client, token_factory):
    dave_token = token_factory(sub="steward.dave", roles=["BANK_DATA_STEWARD"])
    bob_token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    alice_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    carol_token = token_factory(sub="auditor.carol", roles=["BANK_AUDITOR"])

    # 1. Data steward view: sees contract version and run count, zero cases/reveals/identities
    steward_overview = oidc_client.get(
        "/api/enterprise/v1/overview",
        headers={"Authorization": f"Bearer {dave_token}"},
    )
    assert steward_overview.status_code == 200
    stew_data = steward_overview.json()
    assert stew_data["role"] == "data_steward"
    assert stew_data["contract_version"] == "2.0.0"
    assert stew_data["open_cases_count"] == 0
    assert stew_data["assigned_cases_count"] == 0

    # 2. Record a run and intake a case
    with oidc_client.app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="toroka-default-installation",
                manifest_id="gov-man-1",
                manifest={"manifest_id": "gov-man-1", "leads": [{"focus": "staff:S303"}]},
                created_by="system",
            )
        )
        db.commit()

    intake_res = oidc_client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={
            "manifest_id": "gov-man-1",
            "leads": [{"label": "REVIEW", "focus": "staff:S303"}],
            "assign_to_subject": "investigator.alice",
        },
    )
    assert intake_res.status_code == 201
    case_id = intake_res.json()["case_ids"][0]

    # 3. Investigator view: sees open case and assigned case
    inv_overview = oidc_client.get(
        "/api/enterprise/v1/overview",
        headers={"Authorization": f"Bearer {alice_token}"},
    ).json()
    assert inv_overview["role"] == "investigator"
    assert inv_overview["open_cases_count"] == 1
    assert inv_overview["assigned_cases_count"] == 1

    # 4. Add a note
    oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/notes",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"body": "Reviewed ledger activity for staff member."},
    )

    # 5. Timeline endpoint returns audit trail for this case
    timeline_res = oidc_client.get(
        f"/api/enterprise/v1/cases/{case_id}/timeline",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert timeline_res.status_code == 200
    events = timeline_res.json()
    assert len(events) >= 2
    actions = [e["action"] for e in events]
    assert "case_created" in actions
    assert "case_note_added" in actions

    # 6. Audit chain verification
    verify_res = oidc_client.get(
        "/api/enterprise/v1/audit/verify",
        headers={"Authorization": f"Bearer {carol_token}"},
    )
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["valid"] is True
    assert verify_data["records_verified"] >= 2
    assert len(verify_data["head_hash"]) == 64

    # 7. Audit records listing for auditor
    records_res = oidc_client.get(
        "/api/enterprise/v1/audit/records",
        headers={"Authorization": f"Bearer {carol_token}"},
    )
    assert records_res.status_code == 200
    assert len(records_res.json()) >= 2
