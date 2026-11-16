"""Integration, RBAC, maker-checker, and endpoint tests for Institutional Memory API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.services.intelligence import IntelligenceService
from toroka_enterprise_api.services.simulation import SimulationService
from toroka_enterprise_api.simulation_schemas import CaseOutcomeCreate


@pytest.fixture
def memory_test_cases(db_session):
    """Seed test cases with adjudicated outcomes and normalized telemetry."""
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)
    sim_svc = SimulationService(db_session, inst_id)

    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )

    t0 = datetime.now(timezone.utc) - timedelta(days=2)

    # 1. Historical Fraud Case 1
    case1 = case_svc.create_case(
        installation_id=inst_id,
        label="Adjudicated Fraud Case 1",
        focus="cif_fraud_01",
        snapshot={"customer_ref": "cif_fraud_01", "staff_ref": "emp_01"},
        principal=investigator,
    )
    sim_svc.adjudicate_case_outcome(
        CaseOutcomeCreate(case_id=case1.id, label="confirmed_fraud", notes="Confirmed internal fraud"),
        adjudicator_subject="adjudicator.chief",
        adjudicator_role="authoriser",
    )
    e1 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_f1_1",
        event_type="customer_record_access",
        event_time=t0,
        actor="emp_01",
        subject="cif_fraud_01",
        source_system="crm_support",
        attributes={"case_id": case1.id},
    )
    e2 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_f1_2",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=2),
        actor="emp_01",
        subject="cif_fraud_01",
        source_system="core_banking",
        attributes={"case_id": case1.id},
    )
    intel_svc.record_event(e1)
    intel_svc.record_event(e2)

    # 2. Historical Fraud Case 2
    case2 = case_svc.create_case(
        installation_id=inst_id,
        label="Adjudicated Fraud Case 2",
        focus="cif_fraud_02",
        snapshot={"customer_ref": "cif_fraud_02", "staff_ref": "emp_02"},
        principal=investigator,
    )
    sim_svc.adjudicate_case_outcome(
        CaseOutcomeCreate(case_id=case2.id, label="confirmed_fraud", notes="Confirmed collusion"),
        adjudicator_subject="adjudicator.chief",
        adjudicator_role="authoriser",
    )
    e3 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_f2_1",
        event_type="customer_record_access",
        event_time=t0 + timedelta(hours=1),
        actor="emp_02",
        subject="cif_fraud_02",
        source_system="crm_support",
        attributes={"case_id": case2.id},
    )
    e4 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_f2_2",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(hours=1, minutes=3),
        actor="emp_02",
        subject="cif_fraud_02",
        source_system="core_banking",
        attributes={"case_id": case2.id},
    )
    intel_svc.record_event(e3)
    intel_svc.record_event(e4)

    # 3. Confirmed Legitimate Comparison Case 3
    case3 = case_svc.create_case(
        installation_id=inst_id,
        label="Adjudicated Legitimate Case 3",
        focus="cif_legit_03",
        snapshot={"customer_ref": "cif_legit_03", "staff_ref": "emp_03"},
        principal=investigator,
    )
    sim_svc.adjudicate_case_outcome(
        CaseOutcomeCreate(case_id=case3.id, label="confirmed_legitimate", notes="Documented branch request"),
        adjudicator_subject="adjudicator.chief",
        adjudicator_role="authoriser",
    )
    e5 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_l3_1",
        event_type="customer_record_access",
        event_time=t0 + timedelta(hours=2),
        actor="emp_03",
        subject="cif_legit_03",
        source_system="crm_support",
        attributes={"case_id": case3.id},
    )
    e6 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_l3_2",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(hours=2, minutes=4),
        actor="emp_03",
        subject="cif_legit_03",
        source_system="core_banking",
        attributes={"case_id": case3.id},
    )
    e7 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="ev_l3_3",
        event_type="service_ticket_created",
        event_time=t0 + timedelta(hours=2),
        subject="cif_legit_03",
        source_system="crm_support",
        attributes={"case_id": case3.id},
    )
    intel_svc.record_event(e5)
    intel_svc.record_event(e6)
    intel_svc.record_event(e7)

    return {
        "fraud_1": case1.id,
        "fraud_2": case2.id,
        "legit_3": case3.id,
    }


def test_memory_overview_endpoint(oidc_client, token_factory, memory_test_cases):
    """Test GET /api/enterprise/v1/memory/overview returns aggregated metrics."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.get(
        "/api/enterprise/v1/memory/overview",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "adjudicated_case_count" in data
    assert data["adjudicated_case_count"] >= 3
    assert "validated_pattern_count" in data
    assert "candidate_pattern_count" in data


def test_case_fingerprint_extraction_and_zero_pii(oidc_client, token_factory, memory_test_cases):
    """Test extracting zero-PII fingerprint for an investigated case."""
    case_id = memory_test_cases["fraud_1"]
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.get(
        f"/api/enterprise/v1/memory/cases/{case_id}/fingerprint",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["extractor_version"] == "v1"
    assert data["total_events"] == 2
    assert "event.customer_record_access" in data["features"]
    assert data["features"]["event.customer_record_access"] == "present"
    assert data["features"]["event.beneficiary_change"] == "present"
    assert "control_weaknesses" in data
    # No PII in features
    for k, v in data["features"].items():
        assert "cif_fraud" not in k
        assert "emp_01" not in v


def test_pattern_discovery_and_curation(oidc_client, token_factory, memory_test_cases):
    """Test mining candidate patterns and listing them."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    # 1. Discover candidates from adjudicated cases
    disc_resp = oidc_client.post(
        "/api/enterprise/v1/memory/patterns/discover?min_support=2",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert disc_resp.status_code == 200
    candidates = disc_resp.json()
    assert len(candidates) >= 1
    assert candidates[0]["status"] == "candidate"

    # 2. List patterns
    list_resp = oidc_client.get(
        "/api/enterprise/v1/memory/patterns",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1


def test_pattern_validation_governance_and_maker_checker(oidc_client, token_factory, memory_test_cases):
    """Test dual-control validation of a candidate pattern."""
    token_curator = token_factory(sub="inv.curator", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    token_reviewer = token_factory(sub="auth.independent", roles=["BANK_AUTHORISER"])

    # 1. Manually create a candidate pattern with full support
    pat_id = "PAT-TEST-001"
    create_resp = oidc_client.post(
        "/api/enterprise/v1/memory/patterns/candidates",
        headers={"Authorization": f"Bearer {token_curator}"},
        json={
            "pattern_id": pat_id,
            "title": "Access Followed by Beneficiary Update",
            "description": "Cross-system sequence with rapid sensitive changes",
            "feature_signature": {
                "sequence.customer_record_access_to_beneficiary_change": "present",
                "sensitive_change.beneficiary": "present",
            },
            "confirmed_fraud_case_ids": [memory_test_cases["fraud_1"], memory_test_cases["fraud_2"]],
            "confirmed_legitimate_case_ids": [memory_test_cases["legit_3"]],
            "independent_source_systems": ["core_banking", "crm_support"],
            "control_weaknesses": ["customer_authorisation_evidence_gap"],
            "limitations": ["Requires CRM source availability"],
        },
    )
    assert create_resp.status_code == 201

    # 2. Evaluate pattern
    eval_resp = oidc_client.get(
        f"/api/enterprise/v1/memory/patterns/{pat_id}/evaluate",
        headers={"Authorization": f"Bearer {token_curator}"},
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["eligible_for_review"] is True

    # 3. Maker-checker violation: Curator cannot validate their own pattern
    fail_review = oidc_client.post(
        f"/api/enterprise/v1/memory/patterns/{pat_id}/review",
        headers={"Authorization": f"Bearer {token_curator}"},
        json={
            "action": "validate",
            "rationale": "I created and approve this pattern",
        },
    )
    assert fail_review.status_code == 400
    assert "Maker-checker violation" in fail_review.json()["detail"]

    # 4. Independent reviewer validates pattern
    valid_review = oidc_client.post(
        f"/api/enterprise/v1/memory/patterns/{pat_id}/review",
        headers={"Authorization": f"Bearer {token_reviewer}"},
        json={
            "action": "validate",
            "rationale": "Independent quality review completed against historical outcomes.",
        },
    )
    assert valid_review.status_code == 200
    assert valid_review.json()["status"] == "validated"
    assert valid_review.json()["reviewer_subject"] == "auth.independent"

    # 5. Check version history
    ver_resp = oidc_client.get(
        f"/api/enterprise/v1/memory/patterns/{pat_id}/versions",
        headers={"Authorization": f"Bearer {token_curator}"},
    )
    assert ver_resp.status_code == 200
    assert len(ver_resp.json()) == 1


def test_case_similarity_and_pattern_matching_endpoints(oidc_client, token_factory, memory_test_cases):
    """Test retrieving similar cases and matching against institutional patterns."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])
    fraud_case_id = memory_test_cases["fraud_1"]

    # 1. Search similar historical cases
    sim_resp = oidc_client.get(
        f"/api/enterprise/v1/memory/cases/{fraud_case_id}/similar",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert sim_resp.status_code == 200
    similarities = sim_resp.json()
    assert isinstance(similarities, list)
    assert len(similarities) >= 1
    top_match = similarities[0]
    assert "similarity_index" in top_match
    assert "comparison_coverage" in top_match
    assert "summary_explanation" in top_match

    # 2. Match against patterns
    match_resp = oidc_client.get(
        f"/api/enterprise/v1/memory/cases/{fraud_case_id}/patterns",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert match_resp.status_code == 200
    matches = match_resp.json()
    assert isinstance(matches, list)


def test_memory_rbac_and_unauthorized_rejection(oidc_client, token_factory, memory_test_cases):
    """Test unauthenticated and unauthorized access control."""
    # 1. Unauthenticated request rejected
    anon_resp = oidc_client.get("/api/enterprise/v1/memory/overview")
    assert anon_resp.status_code == 401

    # 2. Role without authoriser cannot perform validation review
    token_inv = token_factory(sub="inv.junior", roles=["BANK_INVESTIGATOR"])
    forbid_resp = oidc_client.post(
        "/api/enterprise/v1/memory/patterns/PAT-TEST-001/review",
        headers={"Authorization": f"Bearer {token_inv}"},
        json={"action": "validate", "rationale": "Attempted unauthorized review"},
    )
    assert forbid_resp.status_code == 403
