"""Tests for Phase 14.1: Telecom Scam Signal API Gateway & Live-Call Telemetry."""
import pytest
from toroka_enterprise.intelligence.models import TelecomScamSignalRecord


def test_telecom_scam_signal_active_call_coercion_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/telecom/scam-signal",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "msisdn": "+254712345678",
            "carrier": "SAFARICOM",
            "simulated_call_status": "CALL_IN_PROGRESS",
            "simulated_call_duration_seconds": 320,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["msisdn"] == "+254712345678"
    assert data["carrier"] == "SAFARICOM"
    assert data["call_status"] == "CALL_IN_PROGRESS"
    assert data["call_duration_seconds"] == 320
    assert data["is_high_coercion_risk"] is True
    assert data["scam_signal_score"] >= 0.55
    assert "DELAY" in data["advisory_action"] or "BLOCK" in data["advisory_action"]
    assert "WARNING" in data["statutory_warning"] or "coaching" in data["statutory_warning"].lower()
    assert len(data["query_digest"]) == 64
    assert any("ACTIVE" in ind for ind in data["coercion_indicators"])


def test_telecom_scam_signal_sim_swap_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/telecom/scam-signal",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "msisdn": "0733123456",
            "carrier": "AIRTEL",
            "simulated_sim_swap_age_hours": 12.0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["carrier"] == "AIRTEL"
    assert data["sim_swap_status"] == "SWAPPED_LAST_24H"
    assert data["sim_swap_age_hours"] == 12.0
    assert data["is_high_coercion_risk"] is True
    assert data["scam_signal_score"] >= 0.60
    assert any("SIM_SWAP" in ind for ind in data["coercion_indicators"])


def test_telecom_scam_signal_clean_idle_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/telecom/scam-signal",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "msisdn": "0722000000",
            "carrier": "SAFARICOM",
            "simulated_call_status": "IDLE",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["call_status"] == "IDLE"
    assert data["is_high_coercion_risk"] is False
    assert data["scam_signal_score"] <= 0.05
    assert "NO_TELECOM_ANOMALY" in data["advisory_action"] or "PROCEED" in data["advisory_action"]


def test_iso20022_inflight_payment_with_active_call_triggers_delay_15m(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-TELECOM-DELAY-01",
            "amount": 20000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Coerced Victim",
            "debtor_account": "01100011122",
            "creditor_name": "Scammer Agent",
            "creditor_account": "01199988877",
            "account_prior_transfers_count": 5,
            "enable_graduated_controls": True,
            "telecom_call_status": "CALL_IN_PROGRESS",
            "telecom_coercion_score": 0.75,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "DELAY_SETTLEMENT_15M"
    assert data["risk_tier"] == "HIGH"
    assert data["is_telecom_coerced"] is True
    assert data["telecom_call_status"] == "CALL_IN_PROGRESS"
    assert data["telecom_coercion_score"] == 0.75
    assert any("RULE_TELECOM_ACTIVE_CALL" in r for r in data["triggered_rules"])
    assert "RECOMMEND_DELAY_SETTLEMENT_15M" in data["recommended_action"]


def test_iso20022_inflight_payment_active_call_plus_cop_no_match_escalates_to_block(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-PH14-TELECOM-BLOCK-01",
            "amount": 50000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Elderly Payer",
            "debtor_account": "01100011122",
            "creditor_name": "Alleged Police Commander",
            "creditor_account": "01199988877",
            "account_prior_transfers_count": 5,
            "cop_status": "NO_MATCH",
            "cop_match_score": 0.10,
            "telecom_call_status": "CALL_IN_PROGRESS",
            "telecom_coercion_score": 0.85,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["risk_tier"] == "CRITICAL"
    assert data["is_telecom_coerced"] is True
    assert any("RULE_TELECOM_ACTIVE_CALL" in r for r in data["triggered_rules"])
    assert any("RULE_COP_NO_MATCH" in r for r in data["triggered_rules"])


def test_telecom_signal_persistence_in_db(oidc_client, token_factory, db_session):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/telecom/scam-signal",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "msisdn": "+254700112233",
            "carrier": "SAFARICOM",
            "simulated_call_status": "CALL_IN_PROGRESS",
            "simulated_call_duration_seconds": 180,
            "simulated_sim_swap_age_hours": 8.0,
        },
    )
    assert resp.status_code == 200
    query_id = resp.json()["query_id"]

    db_rec = db_session.query(TelecomScamSignalRecord).filter_by(query_id=query_id).first()
    assert db_rec is not None
    assert db_rec.msisdn == "+254700112233"
    assert db_rec.call_status == "CALL_IN_PROGRESS"
    assert db_rec.sim_swap_status == "SWAPPED_LAST_24H"
    assert db_rec.is_high_coercion_risk is True
    assert db_rec.actor_subject == "investigator.alice"


def test_telecom_signal_rbac_unauthorized(oidc_client, token_factory):
    # Auditor role should not have mutation access to telecom gateway query
    token = token_factory(sub="auditor.bob", roles=["BANK_AUDITOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/telecom/scam-signal",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "msisdn": "+254711223344",
            "carrier": "SAFARICOM",
        },
    )
    assert resp.status_code == 403
