"""Tests for Phase 14.2: Federated Mule Directory & Hash-Linked Interbank Blacklist."""
import pytest
from toroka_enterprise.intelligence.models import FederatedMuleRecord


def test_register_federated_mule_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "01100998877",
            "severity_tier": "CORROBORATED_MULE",
            "originating_bank_bic": "EQBLKENA",
            "reason_code": "VERIFIED_VICTIM_FRAUD_COMPLAINT",
            "dossier_reference": "DOS-2026-0042",
            "ttl_days": 180,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["entry_id"].startswith("mule-")
    assert len(data["blinded_token"]) == 64
    assert data["cleartext_preview"] == "0110****877"
    assert data["severity_tier"] == "CORROBORATED_MULE"
    assert data["originating_bank_bic"] == "EQBLKENA"
    assert data["reason_code"] == "VERIFIED_VICTIM_FRAUD_COMPLAINT"
    assert data["status"] == "ACTIVE"
    assert data["registered_by"] == "investigator.alice"


def test_query_federated_mule_api_match(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Register
    oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "MSISDN",
            "value": "+254711223344",
            "severity_tier": "CONFIRMED_SYNDICATE_CONTROLLER",
            "originating_bank_bic": "KCBKKENA",
            "reason_code": "POLICE_FREEZE_NOTICE_DCI",
        },
    )

    # Query with raw local format
    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "MSISDN",
            "value": "0711223344",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_match"] is True
    assert data["severity_tier"] == "CONFIRMED_SYNDICATE_CONTROLLER"
    assert data["originating_bank_bic"] == "KCBKKENA"
    assert "syndicate controller" in data["recommended_action"].lower()


def test_query_federated_mule_api_blinded_token(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    reg_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "999888777",
            "severity_tier": "SUSPECT_MULE",
        },
    )
    assert reg_resp.status_code == 200
    blinded_token = reg_resp.json()["blinded_token"]

    # Query using already-blinded token
    query_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": blinded_token,
            "is_already_blinded": True,
        },
    )
    assert query_resp.status_code == 200
    assert query_resp.json()["is_match"] is True
    assert query_resp.json()["severity_tier"] == "SUSPECT_MULE"


def test_query_federated_mule_api_no_match(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/query",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "CLEAN_ACCOUNT_00000",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_match"] is False
    assert data["severity_tier"] is None
    assert "NO_MULE_RECORD" in data["recommended_action"]


def test_list_and_update_mule_status(oidc_client, token_factory):
    inv_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    auth_token = token_factory(sub="authoriser.charlie", roles=["BANK_AUTHORISER"])

    # Register
    reg_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "01155566677",
            "severity_tier": "CORROBORATED_MULE",
        },
    )
    entry_id = reg_resp.json()["entry_id"]

    # List entries
    list_resp = oidc_client.get(
        "/api/enterprise/v1/governance/integrations/federated-mules/entries",
        headers={"Authorization": f"Bearer {inv_token}"},
    )
    assert list_resp.status_code == 200
    assert any(e["entry_id"] == entry_id for e in list_resp.json())

    # Update to EXPUNGED
    patch_resp = oidc_client.patch(
        f"/api/enterprise/v1/governance/integrations/federated-mules/entries/{entry_id}/status",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={
            "status": "EXPUNGED",
            "justification": "Court order cleared customer of fraudulent involvement",
        },
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "EXPUNGED"

    # Subsequent query returns no match because status is EXPUNGED
    query_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/query",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "01155566677",
        },
    )
    assert query_resp.status_code == 200
    assert query_resp.json()["is_match"] is False


def test_iso20022_inflight_payment_federated_mule_auto_escalation(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Register corroborated mule in directory
    mule_acc = "01199922233"
    oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": mule_acc,
            "severity_tier": "CORROBORATED_MULE",
            "originating_bank_bic": "EQBLKENA",
            "reason_code": "CROSS_BANK_MULE_RING",
        },
    )

    # In-flight transfer to this creditor account
    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-FEDMULE-01",
            "amount": 45000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Victim Payer",
            "debtor_account": "01100011122",
            "creditor_name": "Mule Receiver",
            "creditor_account": mule_acc,
            "check_federated_mule_directory": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["risk_tier"] == "CRITICAL"
    assert data["is_federated_mule"] is True
    assert data["federated_mule_tier"] == "CORROBORATED_MULE"
    assert any("RULE_FEDERATED_MULE_MATCH" in r for r in data["triggered_rules"])


def test_federated_mule_rbac_unauthorized(oidc_client, token_factory):
    auditor_token = token_factory(sub="auditor.bob", roles=["BANK_AUDITOR"])
    inv_token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Auditor cannot register
    reg_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {auditor_token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "111222333",
        },
    )
    assert reg_resp.status_code == 403

    # Investigator cannot expunge (requires authoriser)
    patch_resp = oidc_client.patch(
        "/api/enterprise/v1/governance/integrations/federated-mules/entries/mule-fake123/status",
        headers={"Authorization": f"Bearer {inv_token}"},
        json={
            "status": "EXPUNGED",
            "justification": "Attempted self-expungement",
        },
    )
    assert patch_resp.status_code == 403
