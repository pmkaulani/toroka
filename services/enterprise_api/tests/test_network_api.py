"""Integration, RBAC, maker-checker, and endpoint tests for Network Intelligence API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.models import (
    EntityLinkCandidateRecord,
    NetworkEdgeRecord,
    NetworkNodeRecord,
)
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.services.intelligence import IntelligenceService


@pytest.fixture
def network_test_data(db_session):
    """Seed test graph entities, transfers, and intelligence events."""
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)

    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )

    t0 = datetime.now(timezone.utc) - timedelta(days=1)

    # 1. Create a case
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Coordinated Mule Movement Case",
        focus="acc_mule_target",
        snapshot={"customer_ref": "cif_100", "staff_ref": "emp_branch_01"},
        principal=investigator,
    )

    # 2. Add nodes directly
    nodes = [
        NetworkNodeRecord(
            node_key="account:acc_mule_target",
            installation_id=inst_id,
            entity_type="account",
            pseudonymous_label="Account Mule Target",
            attributes={"risk_tier": "high"},
            first_seen=t0,
            created_at=t0,
        ),
        NetworkNodeRecord(
            node_key="account:acc_src_1",
            installation_id=inst_id,
            entity_type="account",
            pseudonymous_label="Account Source 1",
            attributes={},
            first_seen=t0,
            created_at=t0,
        ),
        NetworkNodeRecord(
            node_key="account:acc_src_2",
            installation_id=inst_id,
            entity_type="account",
            pseudonymous_label="Account Source 2",
            attributes={},
            first_seen=t0,
            created_at=t0,
        ),
        NetworkNodeRecord(
            node_key="account:acc_beneficiary",
            installation_id=inst_id,
            entity_type="account",
            pseudonymous_label="Account Beneficiary",
            attributes={},
            first_seen=t0,
            created_at=t0,
        ),
        NetworkNodeRecord(
            node_key="device:dev_shared_kiosk",
            installation_id=inst_id,
            entity_type="device",
            pseudonymous_label="Branch Kiosk 4",
            attributes={},
            first_seen=t0,
            created_at=t0,
        ),
    ]
    for n in nodes:
        db_session.add(n)

    # 3. Add edges directly
    edges = [
        NetworkEdgeRecord(
            id="edge_1",
            installation_id=inst_id,
            source_key="account:acc_src_1",
            target_key="account:acc_mule_target",
            relationship_type="transferred_funds_to",
            evidence_basis="direct_observation",
            event_ids=["ev_tx_1"],
            source_systems=["payment_switch"],
            confidence=1.0,
            directed=True,
            first_seen=t0,
            created_at=t0,
        ),
        NetworkEdgeRecord(
            id="edge_2",
            installation_id=inst_id,
            source_key="account:acc_src_2",
            target_key="account:acc_mule_target",
            relationship_type="transferred_funds_to",
            evidence_basis="direct_observation",
            event_ids=["ev_tx_2"],
            source_systems=["payment_switch"],
            confidence=1.0,
            directed=True,
            first_seen=t0 + timedelta(minutes=10),
            created_at=t0,
        ),
        NetworkEdgeRecord(
            id="edge_3",
            installation_id=inst_id,
            source_key="account:acc_mule_target",
            target_key="account:acc_beneficiary",
            relationship_type="transferred_funds_to",
            evidence_basis="direct_observation",
            event_ids=["ev_tx_3"],
            source_systems=["payment_switch"],
            confidence=1.0,
            directed=True,
            first_seen=t0 + timedelta(minutes=25),
            created_at=t0,
        ),
        NetworkEdgeRecord(
            id="edge_weak_1",
            installation_id=inst_id,
            source_key="account:acc_mule_target",
            target_key="device:dev_shared_kiosk",
            relationship_type="accessed_via_device",
            evidence_basis="shared_attribute",
            confidence=0.35,
            directed=False,
            first_seen=t0,
            created_at=t0,
        ),
    ]
    for e in edges:
        db_session.add(e)

    # 4. Add candidate link
    cand = EntityLinkCandidateRecord(
        candidate_id="cand_test_001",
        installation_id=inst_id,
        source_entity_key="account:acc_src_1",
        target_entity_key="account:acc_src_2",
        attribute_type="phone",
        attribute_value="555019999",
        match_type="normalized",
        status="SHARED_ATTRIBUTE_ONLY",
        confidence=0.55,
        supporting_evidence=[{"source": "crm_profile"}],
        contradicting_evidence=[],
        source_systems=["crm"],
        first_observed=t0,
        last_observed=t0,
        created_at=t0,
    )
    db_session.add(cand)

    # 5. Record normalized intelligence events for motif mining
    events = [
        IntelligenceEvent(
            installation_id=inst_id,
            event_id="ev_tx_1",
            event_type="transfer_completed",
            event_time=t0,
            actor="acc_src_1",
            subject="acc_mule_target",
            source_system="payment_switch",
            attributes={"amount": 10000, "currency": "USD"},
        ),
        IntelligenceEvent(
            installation_id=inst_id,
            event_id="ev_tx_2",
            event_type="transfer_completed",
            event_time=t0 + timedelta(minutes=10),
            actor="acc_src_2",
            subject="acc_mule_target",
            source_system="payment_switch",
            attributes={"amount": 15000, "currency": "USD"},
        ),
        IntelligenceEvent(
            installation_id=inst_id,
            event_id="ev_tx_3",
            event_type="transfer_completed",
            event_time=t0 + timedelta(minutes=25),
            actor="acc_mule_target",
            subject="acc_beneficiary",
            source_system="payment_switch",
            attributes={"amount": 24500, "currency": "USD"},
        ),
    ]
    for ev in events:
        intel_svc.record_event(ev)

    db_session.commit()

    return {
        "case_id": case.id,
        "anchor": "account:acc_mule_target",
    }


def test_expand_neighborhood_api(oidc_client, token_factory, network_test_data):
    """Test POST /api/enterprise/v1/network/expand with bounded traversal and weak attribute toggle."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    # Default expansion (include_shared_attributes=False)
    resp = oidc_client.post(
        "/api/enterprise/v1/network/expand",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "seed_nodes": ["account:acc_mule_target"],
            "max_depth": 2,
            "include_shared_attributes": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    node_keys = [n["node_key"] for n in data["nodes"]]
    assert "account:acc_mule_target" in node_keys
    assert "account:acc_src_1" in node_keys
    assert "account:acc_beneficiary" in node_keys
    # Device must be excluded under include_shared_attributes=False
    assert "device:dev_shared_kiosk" not in node_keys

    # Expand with weak attributes enabled
    resp_weak = oidc_client.post(
        "/api/enterprise/v1/network/expand",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "seed_nodes": ["account:acc_mule_target"],
            "max_depth": 2,
            "minimum_confidence": 0.2,
            "include_shared_attributes": True,
        },
    )
    assert resp_weak.status_code == 200
    data_weak = resp_weak.json()
    assert "device:dev_shared_kiosk" in [n["node_key"] for n in data_weak["nodes"]]


def test_find_shortest_path_api(oidc_client, token_factory, network_test_data):
    """Test POST /api/enterprise/v1/network/path returns shortest evidence-backed path."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/network/path",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source_key": "account:acc_src_1",
            "target_key": "account:acc_beneficiary",
            "max_depth": 5,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["path_length"] == 2
    assert [n["node_key"] for n in data["nodes"]] == [
        "account:acc_src_1",
        "account:acc_mule_target",
        "account:acc_beneficiary",
    ]


def test_network_analysis_and_findings_api(oidc_client, token_factory, network_test_data):
    """Test running network analysis and verifying findings & minimal evidence subgraphs."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    # 1. Run analysis
    resp = oidc_client.post(
        "/api/enterprise/v1/network/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "seed_entities": ["account:acc_mule_target"],
            "case_id": network_test_data["case_id"],
            "max_depth": 2,
        },
    )
    assert resp.status_code == 200
    analysis = resp.json()
    assert analysis["analysis_id"].startswith("netrun_")
    assert "subgraph" in analysis
    assert len(analysis["findings"]) >= 1
    # Check rapid pass-through or fan detection
    types = [f["pattern_type"] for f in analysis["findings"]]
    assert "rapid_pass_through" in types

    finding_id = next(f["pattern_id"] for f in analysis["findings"] if f["pattern_type"] == "rapid_pass_through")

    # 2. Retrieve finding evidence subgraph
    ev_resp = oidc_client.get(
        f"/api/enterprise/v1/network/findings/{finding_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ev_resp.status_code == 200
    ev_sub = ev_resp.json()
    assert ev_sub["finding_id"] == finding_id
    assert len(ev_sub["nodes"]) >= 2
    assert len(ev_sub["limitations"]) > 0


def test_entity_link_review_api(oidc_client, token_factory, network_test_data):
    """Test human reviewer governance on candidate relationship."""
    token = token_factory(sub="authoriser.chief", roles=["BANK_AUTHORISER"])

    # 1. List candidates
    cand_resp = oidc_client.get(
        "/api/enterprise/v1/network/entity-links",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert cand_resp.status_code == 200
    cands = cand_resp.json()
    assert len(cands) >= 1
    target_cand_id = cands[0]["candidate_id"]

    # 2. Submit review decision
    review_resp = oidc_client.post(
        f"/api/enterprise/v1/network/entity-links/{target_cand_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "decision": "SAME_ENTITY_CONFIRMED",
            "rationale": "Verified customer phone record matches in telco registry and contract file.",
        },
    )
    assert review_resp.status_code == 200
    rev = review_resp.json()
    assert rev["new_status"] == "SAME_ENTITY_CONFIRMED"
    assert rev["reviewer_subject"] == "authoriser.chief"


def test_network_snapshots_and_runs_api(oidc_client, token_factory, network_test_data):
    """Test creating and listing point-in-time graph snapshots and runs."""
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])

    # 1. Create snapshot
    snap_resp = oidc_client.post(
        "/api/enterprise/v1/network/snapshots",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert snap_resp.status_code == 200
    snap = snap_resp.json()
    assert snap["node_count"] >= 4
    assert len(snap["nodes_digest"]) == 64

    # 2. List snapshots
    list_resp = oidc_client.get(
        "/api/enterprise/v1/network/snapshots",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1

    # 3. List analysis runs
    runs_resp = oidc_client.get(
        "/api/enterprise/v1/network/runs",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert runs_resp.status_code == 200


def test_network_rbac_protection(oidc_client, token_factory):
    """Verify unauthorized role cannot run analysis or review links."""
    # Data Steward cannot analyze network
    steward_token = token_factory(sub="steward.bob", roles=["BANK_DATA_STEWARD"])
    resp = oidc_client.post(
        "/api/enterprise/v1/network/analyze",
        headers={"Authorization": f"Bearer {steward_token}"},
        json={"seed_entities": ["account:acc_1"]},
    )
    assert resp.status_code == 403

    # Unauthenticated request rejected with 401
    anon_resp = oidc_client.post(
        "/api/enterprise/v1/network/analyze",
        json={"seed_entities": ["account:acc_1"]},
    )
    assert anon_resp.status_code == 401
