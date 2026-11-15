"""Integration and security tests for behavioral baselines, deviations, anomalies, and prioritization API."""
from __future__ import annotations

import pytest
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise_api.services.intelligence import IntelligenceService
from toroka_enterprise.intelligence.signals import CorrelationSignal, SignalSeverity
from datetime import datetime, timezone, timedelta


@pytest.fixture
def seeded_case_with_signals(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    intel_svc = IntelligenceService(db_session, inst_id)

    investigator = EnterprisePrincipal(
        subject="inv.tester",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="High Priority Cross-System Anomaly",
        focus="emp_analyst_88",
        snapshot={
            "staff_ref": "emp_analyst_88",
            "focus": "emp_analyst_88",
            "risk_index": 65,
        },
        principal=investigator,
    )

    # Seed correlation signal associated with this case
    sig = CorrelationSignal(
        signal_id=f"sig_{case.id[:8]}",
        signal_type="access_before_sensitive_change",
        severity=SignalSeverity.HIGH,
        title="Access Followed By Beneficiary Modification",
        explanation="Staff accessed record 3 minutes before payout beneficiary change.",
        event_ids=("evt-1", "evt-2"),
        confidence=0.9,
        evidence=({"source_system": "core_banking"}, {"source_system": "iam"}),
    )
    intel_svc.record_signal(sig, case_id=case.id)
    db_session.commit()
    return case.id


def test_get_behavioral_profile_lifecycle(oidc_client, token_factory):
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.get(
        "/api/enterprise/v1/baselines/profiles/employee/emp_test_42",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["subject_id"] == "emp_test_42"
    assert data["subject_type"] == "employee"
    assert data["maturity"] == "insufficient"
    assert data["sample_count"] == 0


def test_evaluate_subject_observation_and_anomaly_creation(oidc_client, token_factory, seeded_case_with_signals):
    case_id = seeded_case_with_signals
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # 20 samples to establish a MATURE baseline with median=5.0
    history = [5.0, 6.0, 4.0, 5.0, 6.0, 5.0, 4.0, 5.0, 6.0, 5.0] * 2

    resp = oidc_client.post(
        "/api/enterprise/v1/baselines/profiles/employee/emp_analyst_88/evaluate",
        headers=headers,
        json={
            "dimension": "daily_activity",
            "observed_value": 75.0,  # Massive spike
            "case_id": case_id,
            "historical_samples": history,
            "observation_context": {"channel": "branch_terminal"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["subject_id"] == "emp_analyst_88"
    assert data["dimension"] == "daily_activity"
    assert data["observed_value"] == 75.0
    assert data["baseline_mature"] is True
    assert data["severity"] == "high"
    assert "Behavioral anomaly only" in data["limitations"][0]


def test_list_anomalies_and_filtering(oidc_client, token_factory, seeded_case_with_signals):
    case_id = seeded_case_with_signals
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # Evaluate an anomaly for this case
    oidc_client.post(
        "/api/enterprise/v1/baselines/profiles/employee/emp_filter_test/evaluate",
        headers=headers,
        json={
            "dimension": "beneficiary_changes",
            "observed_value": 30.0,
            "case_id": case_id,
            "historical_samples": [2.0, 2.0, 3.0, 2.0, 2.0, 3.0, 2.0, 2.0, 3.0, 2.0] * 2,
        },
    )

    # Query filtered by case_id
    resp = oidc_client.get(
        f"/api/enterprise/v1/baselines/anomalies?case_id={case_id}",
        headers=headers,
    )
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) >= 1
    assert any(a["dimension"] == "beneficiary_changes" for a in items)


def test_baseline_admission_evaluation(oidc_client, token_factory):
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # Unverified event -> rejected
    resp_unverified = oidc_client.post(
        "/api/enterprise/v1/baselines/admission/evaluate",
        headers=headers,
        json={
            "event_id": "evt_unverified_1",
            "subject_id": "emp_10",
            "event_is_verified": False,
            "event_is_under_investigation": False,
            "event_is_correction": False,
            "event_is_test_data": False,
        },
    )
    assert resp_unverified.status_code == 200
    data_unv = resp_unverified.json()
    assert data_unv["accepted"] is False
    assert data_unv["reason"] == "event_not_verified"

    # Eligible event -> accepted
    resp_ok = oidc_client.post(
        "/api/enterprise/v1/baselines/admission/evaluate",
        headers=headers,
        json={
            "event_id": "evt_verified_1",
            "subject_id": "emp_10",
            "event_is_verified": True,
            "event_is_under_investigation": False,
            "event_is_correction": False,
            "event_is_test_data": False,
        },
    )
    assert resp_ok.status_code == 200
    data_ok = resp_ok.json()
    assert data_ok["accepted"] is True
    assert data_ok["reason"] == "eligible"


def test_case_priority_calculation_endpoint(oidc_client, token_factory, seeded_case_with_signals):
    case_id = seeded_case_with_signals
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # Add an anomaly to this case
    oidc_client.post(
        "/api/enterprise/v1/baselines/profiles/employee/emp_analyst_88/evaluate",
        headers=headers,
        json={
            "dimension": "customer_access",
            "observed_value": 80.0,
            "case_id": case_id,
            "historical_samples": [5.0, 6.0, 5.0, 6.0, 5.0, 6.0, 5.0, 6.0, 5.0, 6.0] * 2,
        },
    )

    resp = oidc_client.get(
        f"/api/enterprise/v1/baselines/cases/{case_id}/priority",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["priority_score"] >= 40.0
    assert data["requires_review"] is True
    assert len(data["reasons"]) >= 1
    assert "Operational triage priority only" in data["triage_notice"]


def test_governance_detection_methods_endpoint(oidc_client, token_factory):
    token = token_factory(sub="inv.user", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = oidc_client.get(
        "/api/enterprise/v1/baselines/governance/methods",
        headers=headers,
    )
    assert resp.status_code == 200
    methods = resp.json()
    assert len(methods) >= 2
    assert any(m["method_id"] == "det_stat_mad_v1" for m in methods)
    assert any(m["status"] == "deterministic" for m in methods)


def test_installation_isolation_and_rbac(oidc_client, token_factory, seeded_case_with_signals):
    case_id = seeded_case_with_signals
    # 1. No token -> 401
    resp_no_token = oidc_client.get("/api/enterprise/v1/baselines/anomalies")
    assert resp_no_token.status_code == 401

    # 2. Token from foreign installation
    token_foreign = token_factory(
        sub="inv.foreign",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "installation_beta"},
    )
    headers_foreign = {"Authorization": f"Bearer {token_foreign}"}

    # Foreign installation should see empty list (isolated from default installation)
    resp_foreign = oidc_client.get(
        "/api/enterprise/v1/baselines/anomalies",
        headers=headers_foreign,
    )
    assert resp_foreign.status_code == 200
    assert len(resp_foreign.json()) == 0
