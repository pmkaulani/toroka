"""Integration and security tests for the Attack Reconstruction API."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.entities import Relationship, EntityRef, EntityType
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

    # 4. Verified relationships connecting case entities
    intel_svc.record_relationship(
        Relationship(
            installation_id=inst_id,
            source=EntityRef(installation_id=inst_id, entity_type=EntityType.EMPLOYEE, entity_id="emp_operator_12"),
            target=EntityRef(installation_id=inst_id, entity_type=EntityType.CUSTOMER, entity_id="cif_customer_77"),
            relationship_type="accessed",
            confidence=0.95,
            source_system="core_banking",
        )
    )
    intel_svc.record_relationship(
        Relationship(
            installation_id=inst_id,
            source=EntityRef(installation_id=inst_id, entity_type=EntityType.CUSTOMER, entity_id="cif_customer_77"),
            target=EntityRef(installation_id=inst_id, entity_type=EntityType.ACCOUNT, entity_id="acc_corporate_01"),
            relationship_type="owns",
            confidence=1.0,
            source_system="core_banking",
        )
    )

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

    # 0. Before POST reconstruct, GET returns 404 (non-mutating)
    resp_init = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}",
        headers=headers,
    )
    assert resp_init.status_code == 404

    # 1. Create reconstruction via POST
    post_resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/reconstruct",
        headers=headers,
    )
    assert post_resp.status_code == 200

    # 2. Full reconstruction GET retrieves stored state without side effects
    resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["case_id"] == case_id
    assert bundle["reconstruction_id"] == post_resp.json()["reconstruction_id"]

    # 3. Change vector GET
    cv_resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/change-vector",
        headers=headers,
    )
    assert cv_resp.status_code == 200
    cv = cv_resp.json()
    assert "subject_id" in cv

    # 4. Attack path GET
    path_resp = oidc_client.get(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/attack-path",
        headers=headers,
    )
    assert path_resp.status_code == 200
    path = path_resp.json()
    assert len(path["nodes"]) >= 2
    assert len(path["edges"]) >= 1

    # 5. Scenarios GET
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

    # 2. Token from foreign installation cannot reconstruct domestic case -> 404
    token_foreign = token_factory(
        sub="inv.other",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "foreign-bank-tenant"},
    )
    headers_foreign = {"Authorization": f"Bearer {token_foreign}"}

    resp_foreign = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_id}/reconstruct",
        headers=headers_foreign,
    )
    assert resp_foreign.status_code == 404


def test_case_evidence_isolation_within_same_installation(oidc_client, token_factory, db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)

    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )

    # Create Case A and Case B in the SAME bank installation
    case_a = case_svc.create_case(
        installation_id=inst_id,
        label="Case A - Branch Teller",
        focus="emp_teller_alpha",
        snapshot={"staff_ref": "emp_teller_alpha"},
        principal=investigator,
    )
    case_b = case_svc.create_case(
        installation_id=inst_id,
        label="Case B - Corporate Trader",
        focus="emp_trader_beta",
        snapshot={"staff_ref": "emp_trader_beta"},
        principal=investigator,
    )

    t0 = datetime.now(timezone.utc)
    # Event for Case A
    intel_svc.record_event(
        IntelligenceEvent(
            installation_id=inst_id,
            event_id="evt_teller_alpha_01",
            event_type="teller_cash_drawer_open",
            event_time=t0,
            actor="emp_teller_alpha",
            subject="drawer_01",
            source_system="core_banking",
        )
    )
    # Event for Case B
    intel_svc.record_event(
        IntelligenceEvent(
            installation_id=inst_id,
            event_id="evt_trader_beta_01",
            event_type="fx_limit_override",
            event_time=t0 + timedelta(minutes=5),
            actor="emp_trader_beta",
            subject="fx_desk_01",
            source_system="core_banking",
        )
    )
    db_session.commit()

    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # Reconstruct Case A
    resp_a = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_a.id}/reconstruct",
        headers=headers,
    )
    assert resp_a.status_code == 200
    steps_a = resp_a.json()["steps"]
    event_ids_a = {s["event_id"] for s in steps_a}
    assert "evt_teller_alpha_01" in event_ids_a
    assert "evt_trader_beta_01" not in event_ids_a  # NEVER sees Case B event!

    # Reconstruct Case B
    resp_b = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{case_b.id}/reconstruct",
        headers=headers,
    )
    assert resp_b.status_code == 200
    steps_b = resp_b.json()["steps"]
    event_ids_b = {s["event_id"] for s in steps_b}
    assert "evt_trader_beta_01" in event_ids_b
    assert "evt_teller_alpha_01" not in event_ids_b  # NEVER sees Case A event!


def test_empty_evidence_no_fabrication(oidc_client, token_factory, db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )

    empty_case = case_svc.create_case(
        installation_id=inst_id,
        label="Empty Evidence Case",
        focus="cif_ghost_customer",
        snapshot={"customer_ref": "cif_ghost_customer"},
        principal=investigator,
    )
    db_session.commit()

    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{empty_case.id}/reconstruct",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    # Zero evidence: NO fabricated steps, NO invented sessions
    assert len(data["steps"]) == 0
    assert len(data["state_transitions"]) == 0
    assert data["attack_path"]["nodes"] == []
    assert data["attack_path"]["edges"] == []
    assert data["confidence"] == 0.0
    assert data["evidence_completeness"]["percentage"] == 0.0
    assert len(data["evidence_completeness"]["evidence_debt"]) > 0
    assert "evidence debt" in data["change_vector"]["explanation"].lower()


def test_contradiction_resolution_enforces_case_id(oidc_client, token_factory, seeded_case_for_reconstruction, db_session):
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

    # Attempt to resolve using WRONG case_id in URL -> 404
    wrong_case_id = "00000000-0000-0000-0000-000000000000"
    wrong_resp = oidc_client.post(
        f"/api/enterprise/v1/reconstruction/cases/{wrong_case_id}/contradictions/{cid}/resolve",
        headers=headers,
        json={"resolution_note": "Attempting cross-case resolution"},
    )
    assert wrong_resp.status_code == 404
