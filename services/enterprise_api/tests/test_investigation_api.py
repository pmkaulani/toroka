"""API integration tests for Investigation Intelligence, Money-Flow, and Referral Packs."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4
import pytest

from toroka_enterprise_api.persistence.models import EnterpriseCase
from toroka_enterprise.investigation.evidence import sha256_bytes


def test_investigation_endpoints_flow(oidc_client, token_factory, db_session):
    # 1. Create a case in default installation
    case_id = str(uuid4())
    case = EnterpriseCase(
        id=case_id,
        installation_id="toroka-default-installation",
        label="BEC Investigation Case 100",
        focus="Vendor payment redirect attempt",
        snapshot={"status": "open"},
        snapshot_sha256="0" * 64,
        created_by="investigator.alice",
    )
    db_session.add(case)
    db_session.commit()

    token_alice = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    headers_alice = {"Authorization": f"Bearer {token_alice}"}

    # 2. Ingest Evidence
    now = datetime.now(timezone.utc)
    ev_bytes = b"Raw invoice payment receipt"
    ev_hash = sha256_bytes(ev_bytes)

    resp_ev = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/evidence",
        headers=headers_alice,
        json={
            "case_id": case_id,
            "source_type": "bank_transaction",
            "source_system": "CoreBanking",
            "source_record_ref": "TXN-INV-999",
            "observed_at": now.isoformat(),
            "collected_at": (now + timedelta(minutes=5)).isoformat(),
            "collected_by": "investigator.alice",
            "source_timezone": "Africa/Nairobi",
            "sha256": ev_hash,
        },
    )
    assert resp_ev.status_code == 201
    ev_data = resp_ev.json()
    ev_id = ev_data["id"]

    # 3. Register Entities
    resp_e1 = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/entities",
        headers=headers_alice,
        json={
            "kind": "bank_account",
            "identifier_token": "te1:bank_account:1111222233334444",
            "display_label": "Vendor Safe Account",
            "first_seen_at": now.isoformat(),
            "last_seen_at": (now + timedelta(days=1)).isoformat(),
            "sensitivity": "restricted",
        },
    )
    assert resp_e1.status_code == 201
    e1_id = resp_e1.json()["id"]

    resp_e2 = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/entities",
        headers=headers_alice,
        json={
            "kind": "bank_account",
            "identifier_token": "te1:bank_account:5555666677778888",
            "display_label": "Intermediary Account",
            "first_seen_at": now.isoformat(),
            "last_seen_at": (now + timedelta(days=1)).isoformat(),
            "sensitivity": "restricted",
        },
    )
    assert resp_e2.status_code == 201
    e2_id = resp_e2.json()["id"]

    # 4. Add Relationship (must cite evidence)
    resp_rel = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/relationships",
        headers=headers_alice,
        json={
            "source_entity_id": e1_id,
            "target_entity_id": e2_id,
            "relationship_type": "vendor_bank_change",
            "state": "hypothesis",
            "evidence_ids": [ev_id],
            "explanation": "Payee account altered on invoice matching",
        },
    )
    assert resp_rel.status_code == 201

    # 5. Add Transaction
    resp_tx = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/transactions",
        headers=headers_alice,
        json={
            "case_id": case_id,
            "source_entity_id": e1_id,
            "destination_entity_id": e2_id,
            "amount": "250000.00",
            "currency": "KES",
            "occurred_at": (now + timedelta(minutes=2)).isoformat(),
            "source_timezone": "Africa/Nairobi",
            "channel": "PESALINK",
            "source_system": "CoreBanking",
            "source_record_ref": "TXN-INV-999",
            "evidence_id": ev_id,
            "event_type": "transfer",
        },
    )
    assert resp_tx.status_code == 201

    # 6. Run Rule Engine Findings
    resp_findings = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/findings/run",
        headers=headers_alice,
    )
    assert resp_findings.status_code == 200
    findings = resp_findings.json()
    assert len(findings) >= 1
    bec_finding = next(f for f in findings if f["rule_id"] == "bec.vendor_instruction_change")
    assert "does NOT accuse" in bec_finding["explanation"]

    # 7. Query Timeline and Graph
    resp_tl = oidc_client.get(f"/api/enterprise/v1/cases/{case_id}/intelligence/timeline", headers=headers_alice)
    assert resp_tl.status_code == 200
    assert resp_tl.json()["total_events"] >= 2

    resp_graph = oidc_client.get(f"/api/enterprise/v1/cases/{case_id}/intelligence/graph", headers=headers_alice)
    assert resp_graph.status_code == 200
    assert len(resp_graph.json()["entities"]) == 2
    assert len(resp_graph.json()["relationships"]) == 1

    # 8. Query Money Flow
    resp_mf = oidc_client.get(
        f"/api/enterprise/v1/cases/{case_id}/intelligence/money-flow?root_entity_id={e1_id}",
        headers=headers_alice,
    )
    assert resp_mf.status_code == 200
    assert Decimal(resp_mf.json()["net_by_currency"]["KES"]) == Decimal("250000.00")

    # 9. Referral Pack Preview
    resp_prev = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/referral-packs/preview",
        headers=headers_alice,
        json={
            "recipient_org": "Central Bank of Kenya - BFID",
            "purpose": "Interbank funds recovery referral",
            "legal_basis": "NPS Act Sec 31",
        },
    )
    assert resp_prev.status_code == 200
    prev_data = resp_prev.json()
    pack_id = prev_data["pack_id"]
    pack_hash = prev_data["pack_hash"]
    assert len(pack_hash) == 64

    # 10. Approval by Authoriser (Dual-Approver Enforcement: Alice alone as investigator cannot approve)
    resp_bad_appr = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/referral-packs",
        headers=headers_alice,
        json={
            "pack_id": pack_id,
            "expected_pack_hash": pack_hash,
        },
    )
    assert resp_bad_appr.status_code == 403
    assert "Secondary authoriser approval required" in resp_bad_appr.json()["detail"]

    # Bob authorises
    token_bob = token_factory(sub="manager.bob", roles=["BANK_AUTHORISER"])
    headers_bob = {"Authorization": f"Bearer {token_bob}"}

    resp_appr = oidc_client.post(
        f"/api/enterprise/v1/cases/{case_id}/referral-packs",
        headers=headers_bob,
        json={
            "pack_id": pack_id,
            "expected_pack_hash": pack_hash,
        },
    )
    assert resp_appr.status_code == 200
    assert resp_appr.json()["status"] == "approved"
    assert "manager.bob" in resp_appr.json()["approving_principals"]


def test_cross_installation_isolation_enforcement(oidc_client, token_factory, db_session):
    # Case belongs to inst-other
    case = EnterpriseCase(
        id="case-tenant-other",
        installation_id="inst-other",
        label="Other Tenant Private Case",
        focus="Confidential investigation",
        snapshot={"status": "open"},
        snapshot_sha256="0" * 64,
        created_by="other_user",
    )
    db_session.add(case)
    db_session.commit()

    # User in default installation attempts to access Case in inst-other
    token_user = token_factory(sub="intruder.eve", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token_user}"}

    # Graph access -> 404
    resp_graph = oidc_client.get("/api/enterprise/v1/cases/case-tenant-other/intelligence/graph", headers=headers)
    assert resp_graph.status_code == 404

    # Timeline access -> 404
    resp_tl = oidc_client.get("/api/enterprise/v1/cases/case-tenant-other/intelligence/timeline", headers=headers)
    assert resp_tl.status_code == 404

    # Money-flow access -> 404
    resp_mf = oidc_client.get(f"/api/enterprise/v1/cases/case-tenant-other/intelligence/money-flow?root_entity_id={uuid4()}", headers=headers)
    assert resp_mf.status_code == 404
