"""Tests for Phase 14.4: Swiss SIC5 Sub-50ms Parallel Clearing Engine API."""
import pytest


def test_inflight_payment_parallel_pipeline_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-SIC5-API-001",
            "clearing_rail": "PESALINK",
            "amount": "80000.00",
            "currency": "KES",
            "debtor_name": "Alice Mukami",
            "debtor_account": "01100998811",
            "debtor_bic": "KCBKKENA",
            "debtor_msisdn": "+254711223344",
            "creditor_name": "Bob Omondi",
            "creditor_account": "02200998822",
            "creditor_bic": "EQBLKENA",
            "remittance_narrative": "Standard invoice payment",
            "use_parallel_pipeline": True,
            "sla_budget_ms": 45.0,
            "check_federated_mule_directory": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["end_to_end_id"] == "E2E-SIC5-API-001"
    assert data["is_parallel_pipeline"] is True
    assert data["sla_budget_ms"] == 45.0
    assert data["is_sla_compliant"] is True
    assert data["circuit_breaker_tripped"] is False
    assert data["cop_latency_ms"] is not None
    assert data["telecom_latency_ms"] is not None
    assert data["federated_mule_latency_ms"] is not None
    assert data["feed_statuses"]["cop"] in ("SUCCESS", "SKIPPED")
    assert data["feed_statuses"]["telecom"] in ("SUCCESS", "SKIPPED")
    assert data["feed_statuses"]["federated_mule"] in ("SUCCESS", "SKIPPED")


def test_inflight_payment_circuit_breaker_tripped_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Simulate an external telecom carrier endpoint hanging for 80ms
    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-SIC5-API-TIMEOUT",
            "clearing_rail": "PESALINK",
            "amount": "50000.00",
            "currency": "KES",
            "debtor_name": "Alice Mukami",
            "debtor_account": "01100998811",
            "debtor_bic": "KCBKKENA",
            "debtor_msisdn": "+254711223344",
            "creditor_name": "Bob Omondi",
            "creditor_account": "02200998822",
            "creditor_bic": "EQBLKENA",
            "remittance_narrative": "Emergency transfer",
            "use_parallel_pipeline": True,
            "sla_budget_ms": 45.0,
            "simulated_latencies": {"telecom": 80.0},  # Exceeds 35ms feed timeout!
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_parallel_pipeline"] is True
    assert data["circuit_breaker_tripped"] is True
    assert data["feed_statuses"]["telecom"] == "TIMEOUT"
    # Even with hanging feed, total latency is capped around feed timeout (~35-45ms)
    assert data["latency_ms"] < 60.0
    assert data["decision"] is not None


def test_inflight_payment_parallel_with_multiple_phase14_signals(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Register creditor as corroborated mule in federated directory
    oidc_client.post(
        "/api/enterprise/v1/governance/integrations/federated-mules/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "entity_type": "BANK_ACCOUNT",
            "value": "09988776655",
            "severity_tier": "CONFIRMED_SYNDICATE_CONTROLLER",
            "originating_bank_bic": "BARBKENA",
            "reason_code": "POLICE_FREEZE_NOTICE_DCI",
        },
    )

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-SIC5-MULTI-SIGNAL",
            "clearing_rail": "PESALINK",
            "amount": "450000.00",
            "currency": "KES",
            "debtor_name": "Alice Victim",
            "debtor_account": "0110001111",
            "debtor_bic": "KCBKKENA",
            "debtor_msisdn": "+254711000111",
            "creditor_name": "Fake Merchant Ltd",
            "creditor_account": "09988776655",
            "creditor_bic": "EQBLKENA",
            "remittance_narrative": "Urgent security transfer to safe account",
            "account_prior_transfers_count": 0,
            "cop_status": "NO_MATCH",
            "telecom_call_status": "CALL_IN_PROGRESS",
            "telecom_coercion_score": 0.85,
            "check_federated_mule_directory": True,
            "use_parallel_pipeline": True,
            "sla_budget_ms": 45.0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "BLOCK"
    assert data["risk_tier"] == "CRITICAL"
    assert data["risk_score"] >= 0.95
    assert data["is_federated_mule"] is True
    assert data["is_telecom_coerced"] is True
    assert data["cop_status"] == "NO_MATCH"

    rule_prefixes = [r.split(":")[0] for r in data["triggered_rules"]]
    assert "RULE_FEDERATED_MULE_MATCH" in rule_prefixes
    assert "RULE_COP_NO_MATCH" in rule_prefixes
    assert "RULE_TELECOM_ACTIVE_CALL" in rule_prefixes


def test_inflight_payment_serial_fallback_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "end_to_end_id": "E2E-SERIAL-FALLBACK",
            "clearing_rail": "INTERNAL_BOOK",
            "amount": "25000.00",
            "currency": "KES",
            "debtor_name": "Alice Debtor",
            "debtor_account": "0110001111",
            "creditor_name": "Bob Creditor",
            "creditor_account": "0220002222",
            "remittance_narrative": "Internal book transfer",
            "use_parallel_pipeline": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_parallel_pipeline"] is False
