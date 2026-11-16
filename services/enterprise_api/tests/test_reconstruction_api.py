"""Integration and security tests for the Attack Reconstruction API."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise_api.services.intelligence import IntelligenceService


@pytest.fixture
def seeded_case_for_reconstruction(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)

    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Account Takeover and Unauthorized Beneficiary Payout",
        focus="cif_customer_77",
        snapshot={
            "staff_ref": "emp_operator_12",
            "customer_ref": "cif_customer_77",
            "account_ref": "acc_corporate_01",
            "focus": "cif_customer_77",
            "risk_index": 80,
        },
        principal=investigator,
    )

    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)

    # 1. Event 1: Login
    e1 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt_recon_01",
        event_type="session_start",
        event_time=t0,
        actor="emp_operator_12",
        subject="session_lead",
        source_system="iam",
        attributes={"ip_address": "192.168.1.10", "branch_code": "NAIROBI_MAIN"},
    )
    intel_svc.record_event(e1)

    # 2. Event 2: Conflicting SIEM login (produces contradiction)
    e2 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt_recon_02",
        event_type="terminal_login",
        event_time=t0 + timedelta(seconds=15),
        actor="emp_operator_12",
        subject="session_lead",
        source_system="siem",
        attributes={"ip_address": "10.0.99.1", "branch_code": "MOMBASA_BRANCH"},
    )
    intel_svc.record_event(e2)

    # 3. Event 3: Beneficiary Change (produces state transition)
    e3 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt_recon_03",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=10),
        actor="emp_operator_12",
        subject="acc_corporate_01",
        source_system="core_banking",
        attributes={"new_beneficiary": "acc_mule_destination"},
    )
    intel_svc.record_event(e3)

    db_session.commit()
    return case.id


def test_reconstruct_incident_endpoint(oidc_client, token_factory, seeded_case_for_reconstruction):
    case_id = seeded_case_for_reconstruction
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/reconstruct",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["case_id"] == case_id
    assert len(data["steps"]) >= 3
    assert len(data["state_transitions"]) >= 1
    assert data["change_vector"] is not None
    assert data["attack_path"] is not None
    assert len(data["scenarios"]) == 4
    assert data["evidence_completeness"]["percentage"] > 0
    assert len(data["contradictions"]) >= 1


def test_get_case_reconstruction_and_sub_endpoints(oidc_client, token_factory, seeded_case_for_reconstruction):
    case_id = seeded_case_for_reconstruction
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Full reconstruction GET
    resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["case_id"] == case_id

    # 2. Change vector GET
    cv_resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/change-vector",
        headers=headers,
    )
    assert cv_resp.status_code == 200
    cv = cv_resp.json()
    assert "subject_id" in cv

    # 3. Attack path GET
    path_resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/attack-path",
        headers=headers,
    )
    assert path_resp.status_code == 200
    path = path_resp.json()
    assert len(path["nodes"]) >= 2
    assert len(path["edges"]) >= 1

    # 4. Scenarios GET
    sc_resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/scenarios",
        headers=headers,
    )
    assert sc_resp.status_code == 200
    scenarios = sc_resp.json()
    assert len(scenarios) == 4


def test_resolve_contradiction_lifecycle(oidc_client, token_factory, seeded_case_for_reconstruction):
    case_id = seeded_case_for_reconstruction
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # Generate reconstruction to create contradiction records
    recon_resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/reconstruct",
        headers=headers,
    )
    contradictions = recon_resp.json()["contradictions"]
    assert len(contradictions) >= 1
    cid = contradictions[0]["contradiction_id"]

    # Resolve contradiction with investigator note
    resolve_resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/contradictions/{cid}/resolve",
        headers=headers,
        json={"resolution_note": "Verified timestamp drift due to unsynced branch NTP server; not an active session hijacking."},
    )
    assert resolve_resp.status_code == 200
    res_data = resolve_resp.json()
    assert res_data["status"] == "resolved"
    assert res_data["resolved_by"] == "inv.user"
    assert "NTP server" in res_data["resolution_note"]


def test_reconstruction_installation_isolation_and_rbac(oidc_client, token_factory, seeded_case_for_reconstruction):
    case_id = seeded_case_for_reconstruction

    # 1. Unauthenticated -> 401
    resp_no_auth = oidc_client.get(f"/api/enterprise/v1/reconstruction/cases/{case_id}")
    assert resp_no_auth.status_code == 401

    # 2. Token from foreign installation
    token_foreign = token_factory(
        sub="inv.other",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "foreign-bank-tenant"},
    )
    headers_foreign = {"Authorization": f"Bearer {token_foreign}"}

    # Foreign installation gets isolated reconstruction (empty steps from foreign scope)
    resp_foreign = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/reconstruct",
        headers=headers_foreign,
    )
    assert resp_foreign.status_code == 200
    # Steps are strictly isolated to foreign installation
    for s in resp_foreign.json()["steps"]:
        assert s["event_id"] != "evt_recon_01"
