"""Tests for Phase 14.0: Confirmation of Payee (CoP) and Graduated Clearing Controls."""
import pytest


def test_cop_verify_api_match(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/cop/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "intended_name": "Patrick Mwangi",
            "registered_name": "Patrick Mwangi",
            "account_number": "01100998877",
            "account_type": "PERSONAL",
            "clearing_rail": "PESALINK",
            "bank_bic": "KCBKKENA",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "MATCH"
    assert data["match_score"] == 1.0
    assert data["suggested_name"] is None
    assert "Verified" in data["advisory_message"]
    assert len(data["inquiry_digest"]) == 64


def test_cop_verify_api_close_match(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/cop/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "intended_name": "Patrik Mwangi",
            "registered_name": "Patrick Mwangi",
            "account_number": "01100998877",
            "account_type": "PERSONAL",
            "clearing_rail": "PESALINK",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CLOSE_MATCH"
    assert 0.65 <= data["match_score"] < 0.88
    assert data["suggested_name"] == "Patrick Mwangi"
    assert "Close Match" in data["advisory_message"]


def test_cop_verify_api_no_match(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/cop/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "intended_name": "Safaricom Customer Care",
            "registered_name": "Daniel Kipchoge",
            "account_number": "0712345678",
            "account_type": "BUSINESS",
            "clearing_rail": "MPESA_B2C",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "NO_MATCH"
    assert data["match_score"] < 0.65
    assert data["suggested_name"] is None
    assert "Warning - No Match" in data["advisory_message"]


def test_iso20022_graduated_escrow_delay_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # High amount on instant rail to first-time beneficiary -> DELAY_SETTLEMENT_15M
    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-ESCROW-01",
            "amount": 300000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Victim Payer",
            "debtor_account": "01100099988",
            "creditor_name": "New Beneficiary",
            "creditor_account": "01188877766",
            "account_prior_transfers_count": 0,
            "enable_graduated_controls": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DELAY_SETTLEMENT_15M"
    assert data["risk_tier"] == "HIGH"
    assert "RECOMMEND_DELAY_SETTLEMENT_15M" in data["recommended_action"]


def test_iso20022_graduated_inflow_only_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-INFLOW-01",
            "amount": 50000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Alice Payer",
            "debtor_account": "01100011122",
            "creditor_name": "Suspect Mule Account",
            "creditor_account": "01199988877",
            "account_prior_transfers_count": 5,
            "beneficiary_inflow_restriction": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "INFLOW_ONLY"
    assert data["risk_tier"] == "HIGH"
    assert "RECOMMEND_INFLOW_ONLY" in data["recommended_action"]


def test_iso20022_graduated_non_counter_restriction_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-NONCOUNTER-01",
            "amount": 75000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Target Account",
            "debtor_account": "01100011122",
            "creditor_name": "Third Party",
            "creditor_account": "01199988877",
            "account_prior_transfers_count": 5,
            "debtor_channel_anomaly": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "RESTRICT_NON_COUNTER"
    assert data["risk_tier"] == "HIGH"
    assert "RECOMMEND_RESTRICT_NON_COUNTER" in data["recommended_action"]


def test_iso20022_cop_composite_escalation_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Fast rail transfer with CoP NO_MATCH (+0.45) escalates to BLOCK
    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-COP-BLOCK-01",
            "amount": 300000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Victim",
            "debtor_account": "01100011122",
            "creditor_name": "Alleged CEO",
            "creditor_account": "01199988877",
            "account_prior_transfers_count": 0,
            "cop_status": "NO_MATCH",
            "cop_match_score": 0.12,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["risk_tier"] == "CRITICAL"
    assert data["cop_status"] == "NO_MATCH"
    assert data["cop_match_score"] == 0.12
    assert any("RULE_COP_NO_MATCH" in r for r in data["triggered_rules"])
