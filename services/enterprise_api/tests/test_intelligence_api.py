"""API tests for cross-system fraud intelligence, temporal correlation, and investigation hypotheses."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.services.intelligence import IntelligenceService


@pytest.fixture
def seeded_case_and_events(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)

    # 1. Create a Case
    investigator = EnterprisePrincipal(
        subject="inv.test",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Dormant Account Activation and Transfer",
        focus="cif_vip_1001",
        snapshot={
            "staff_ref": "emp_teller_42",
            "customer_ref": "cif_vip_1001",
            "account_ref": "acc_savings_88",
            "focus": "cif_vip_1001",
            "risk_index": 72,
        },
        principal=investigator,
    )

    t0 = case.created_at
    # 2. Seed Intelligence Events
    # Event 1: Access
    e1 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt-acc-42-01",
        event_type="customer_record_access",
        event_time=t0 - timedelta(minutes=15),
        actor="emp_teller_42",
        subject="cif_vip_1001",
        source_system="cbs_audit_trail",
        source_record_id="cbs-aud-991",
        entities=("emp_teller_42", "cif_vip_1001", "acc_savings_88"),
        provenance_digest="sha256-mock-digest-1",
    )
    intel_svc.record_event(e1)

    # Event 2: Sensitive profile change
    e2 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt-chg-42-02",
        event_type="beneficiary_change",
        event_time=t0 - timedelta(minutes=5),
        actor="emp_teller_42",
        subject="cif_vip_1001",
        source_system="core_banking",
        source_record_id="cbs-txn-881",
        entities=("cif_vip_1001", "acc_savings_88"),
        provenance_digest="sha256-mock-digest-2",
    )
    intel_svc.record_event(e2)

    # Event 3: Relationship
    rel = Relationship(
        installation_id=inst_id,
        source=EntityRef(inst_id, EntityType.EMPLOYEE, "emp_teller_42"),
        target=EntityRef(inst_id, EntityType.ACCOUNT, "acc_savings_88"),
        relationship_type="accessed",
        first_seen=t0 - timedelta(minutes=15),
        last_seen=t0 - timedelta(minutes=5),
        confidence=0.98,
        source_system="core_banking",
    )
    intel_svc.record_relationship(rel)
    db_session.commit()

    return case.id


def test_correlate_case_events_endpoint(oidc_client, token_factory, seeded_case_and_events):
    case_id = seeded_case_and_events
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.post(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/correlate",
        headers=headers,
        json={"window_before_minutes": 60, "window_after_minutes": 60},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert data["events_evaluated"] >= 2
    assert data["signals_detected"] >= 1
    assert any(s["signal_type"] == "access_before_sensitive_change" for s in data["signals"])


def test_get_investigation_bundle_endpoint(oidc_client, token_factory, seeded_case_and_events):
    case_id = seeded_case_and_events
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.get(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/investigation",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["case_id"] == case_id
    assert len(data["events"]) >= 2
    assert len(data["relationships"]) >= 1
    assert len(data["signals"]) >= 1
    assert len(data["hypotheses"]) >= 2  # Default competing hypotheses generated

    summary = data["summary"]
    assert summary["requires_human_review"] is True
    assert len(summary["alternative_explanations"]) >= 1
    assert len(summary["missing_evidence"]) >= 1


def test_case_hypotheses_lifecycle(oidc_client, token_factory, seeded_case_and_events):
    case_id = seeded_case_and_events
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Add Hypothesis
    create_resp = oidc_client.post(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/hypotheses",
        headers=headers,
        json={
            "hypothesis_id": "H-TEST-01",
            "title": "Legitimate Account Servicing",
            "description": "Employee was assisting customer with authorized beneficiary change.",
            "status": "supported",
            "supporting_signal_ids": [],
            "contradicting_signal_ids": [],
            "confidence": 0.85,
            "investigator_note": "Verified customer signed mandate on paper.",
        },
    )
    assert create_resp.status_code == 200
    h_data = create_resp.json()
    assert h_data["hypothesis_id"] == "H-TEST-01"
    assert h_data["status"] == "supported"
    assert h_data["confidence"] == 0.85

    # 2. List Hypotheses
    list_resp = oidc_client.get(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/hypotheses",
        headers=headers,
    )
    assert list_resp.status_code == 200
    hypos = list_resp.json()
    assert any(h["hypothesis_id"] == "H-TEST-01" for h in hypos)


def test_relationships_and_timeline_endpoints(oidc_client, token_factory, seeded_case_and_events):
    case_id = seeded_case_and_events
    auditor_token = token_factory(sub="auditor.user", roles=["BANK_AUDITOR"])
    headers = {"Authorization": f"Bearer {auditor_token}"}

    # 1. Relationships
    rel_resp = oidc_client.get(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/relationships",
        headers=headers,
    )
    assert rel_resp.status_code == 200
    rels = rel_resp.json()
    assert len(rels) >= 1
    assert rels[0]["relationship_type"] == "accessed"

    # 2. Timeline
    tl_resp = oidc_client.get(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/timeline",
        headers=headers,
    )
    assert tl_resp.status_code == 200
    tl = tl_resp.json()
    assert len(tl) >= 2
    # Verify chronological ordering
    assert tl[0]["event_time"] <= tl[1]["event_time"]


def test_authorization_role_enforcement(oidc_client, token_factory, seeded_case_and_events):
    case_id = seeded_case_and_events
    auditor_token = token_factory(sub="auditor.user", roles=["BANK_AUDITOR"])
    headers = {"Authorization": f"Bearer {auditor_token}"}

    # Auditor is read-only -> cannot create hypothesis (403 Forbidden)
    resp = oidc_client.post(
        f"/api/enterprise/v1/intelligence/cases/{case_id}/hypotheses",
        headers=headers,
        json={
            "hypothesis_id": "H-AUD-FAIL",
            "title": "Auditor Test",
            "description": "Should fail",
            "status": "open",
        },
    )
    assert resp.status_code == 403
