"""Integration, RBAC, dual control, and tenant isolation tests for Simulation API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.services.intelligence import IntelligenceService


@pytest.fixture
def seeded_simulation_case(db_session):
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
        label="Insider Risk Simulation Case",
        focus="cif_sim_cust",
        snapshot={
            "staff_ref": "emp_sim_staff",
            "customer_ref": "cif_sim_cust",
            "account_ref": "acc_sim_01",
            "focus": "cif_sim_cust",
        },
        principal=investigator,
    )

    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)

    # 1. Customer record access
    e1 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt_sim_01",
        event_type="customer_record_access",
        event_time=t0,
        actor="emp_sim_staff",
        subject="cif_sim_cust",
        source_system="core_banking",
        attributes={"case_id": case.id, "available_at": t0.isoformat()},
    )
    intel_svc.record_event(e1)

    # 2. Sensitive profile change 5 minutes later
    e2 = IntelligenceEvent(
        installation_id=inst_id,
        event_id="evt_sim_02",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=5),
        actor="emp_sim_staff",
        subject="cif_sim_cust",
        source_system="core_banking",
        attributes={"case_id": case.id, "available_at": (t0 + timedelta(minutes=5)).isoformat()},
    )
    intel_svc.record_event(e2)

    return case.id


def test_strategy_lifecycle_and_versioning(oidc_client, token_factory):
    token = token_factory(sub="inv.alice", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create strategy version 1
    create_resp = oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=headers,
        json={
            "strategy_id": "strat_insider_rules",
            "title": "Insider Risk Policy",
            "description": "Monitors rapid sensitive changes after access",
            "rules_enabled": ["employee_access_before_sensitive_change"],
            "parameters": {"window_minutes": 30},
            "min_severity": "medium",
            "min_confidence": 0.6,
        },
    )
    assert create_resp.status_code == 201
    s1 = create_resp.json()
    assert s1["strategy_id"] == "strat_insider_rules"
    assert s1["version"] == 1
    assert s1["status"] == "draft"

    # 2. Create strategy version 2 with updated confidence
    create_resp_v2 = oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=headers,
        json={
            "strategy_id": "strat_insider_rules",
            "title": "Insider Risk Policy (Tuned)",
            "description": "Higher confidence threshold",
            "rules_enabled": ["employee_access_before_sensitive_change"],
            "parameters": {"window_minutes": 30},
            "min_severity": "medium",
            "min_confidence": 0.8,
        },
    )
    assert create_resp_v2.status_code == 201
    s2 = create_resp_v2.json()
    assert s2["strategy_id"] == "strat_insider_rules"
    assert s2["version"] == 2

    # 3. List strategies
    list_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies", headers=headers)
    assert list_resp.status_code == 200
    items = list_resp.json()
    versions = [i["version"] for i in items if i["strategy_id"] == "strat_insider_rules"]
    assert 1 in versions
    assert 2 in versions

    # 4. Get specific version vs latest
    v1_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies/strat_insider_rules?version=1", headers=headers)
    assert v1_resp.status_code == 200
    assert v1_resp.json()["version"] == 1

    latest_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies/strat_insider_rules", headers=headers)
    assert latest_resp.status_code == 200
    assert latest_resp.json()["version"] == 2


def test_case_outcome_adjudication(oidc_client, token_factory, seeded_simulation_case):
    case_id = seeded_simulation_case
    token = token_factory(sub="inv.bob", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Invalid label -> 400
    bad_resp = oidc_client.post(
        "/api/enterprise/v1/simulation/labels",
        headers=headers,
        json={"case_id": case_id, "label": "definitely_guilty"},
    )
    assert bad_resp.status_code == 400

    # 2. Valid adjudication as confirmed_fraud
    adj_resp = oidc_client.post(
        "/api/enterprise/v1/simulation/labels",
        headers=headers,
        json={
            "case_id": case_id,
            "label": "confirmed_fraud",
            "first_fraud_event_time": datetime.now(timezone.utc).isoformat(),
            "notes": "Verified unauthorized beneficiary change corroborated by customer complaint.",
        },
    )
    assert adj_resp.status_code == 200
    adj_data = adj_resp.json()
    assert adj_data["case_id"] == case_id
    assert adj_data["label"] == "confirmed_fraud"
    assert adj_data["adjudicated_by"] == "inv.bob"

    # 3. List labels
    list_resp = oidc_client.get("/api/enterprise/v1/simulation/labels", headers=headers)
    assert list_resp.status_code == 200
    labels = list_resp.json()
    matching = [l for l in labels if l["case_id"] == case_id]
    assert len(matching) == 1
    assert matching[0]["label"] == "confirmed_fraud"


def test_simulation_run_execution_and_comparison(oidc_client, token_factory, seeded_simulation_case):
    case_id = seeded_simulation_case
    inv_token = token_factory(sub="inv.carol", roles=["BANK_INVESTIGATOR"])
    headers = {"Authorization": f"Bearer {inv_token}"}

    # 1. Setup baseline strategy (empty rules)
    oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=headers,
        json={
            "strategy_id": "strat_baseline_empty",
            "title": "Baseline No-Rules",
            "description": "Baseline policy with zero rules",
            "rules_enabled": [],
        },
    )

    # 2. Setup proposed strategy (with employee access rule)
    oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=headers,
        json={
            "strategy_id": "strat_proposed_access",
            "title": "Proposed Access Rule",
            "description": "Proposed strategy with employee access rule",
            "rules_enabled": ["employee_access_before_sensitive_change"],
            "min_severity": "medium",
            "min_confidence": 0.5,
        },
    )

    # 3. Adjudicate case as confirmed_fraud
    oidc_client.post(
        "/api/enterprise/v1/simulation/labels",
        headers=headers,
        json={
            "case_id": case_id,
            "label": "confirmed_fraud",
            "first_fraud_event_time": (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat(),
        },
    )

    # 4. Execute simulation run comparing proposed against baseline
    run_resp = oidc_client.post(
        "/api/enterprise/v1/simulation/runs",
        headers=headers,
        json={
            "strategy_id": "strat_proposed_access",
            "baseline_strategy_id": "strat_baseline_empty",
            "cohort_case_ids": [case_id],
        },
    )
    assert run_resp.status_code == 201
    run_data = run_resp.json()
    sim_id = run_data["simulation_id"]

    assert run_data["strategy_id"] == "strat_proposed_access"
    assert run_data["baseline_strategy_id"] == "strat_baseline_empty"
    assert run_data["executed_by"] == "inv.carol"

    # Proposed metrics should show 1 TP, 0 FN
    assert run_data["metrics"]["true_positives"] == 1
    assert run_data["metrics"]["false_negatives"] == 0
    assert run_data["metrics"]["precision"] == 1.0
    assert run_data["metrics"]["recall"] == 1.0

    # Baseline metrics should show 0 TP, 1 FN
    assert run_data["baseline_metrics"]["true_positives"] == 0
    assert run_data["baseline_metrics"]["false_negatives"] == 1

    # Delta
    assert run_data["delta"]["tp_diff"] == 1
    assert run_data["delta"]["fn_diff"] == -1
    assert "Discovered 1 additional true positive" in run_data["delta"]["summary"]

    # 5. Retrieve run by ID
    get_run_resp = oidc_client.get(f"/api/enterprise/v1/simulation/runs/{sim_id}", headers=headers)
    assert get_run_resp.status_code == 200
    assert get_run_resp.json()["simulation_id"] == sim_id


def test_dual_control_maker_checker_approval(oidc_client, token_factory):
    maker_token = token_factory(sub="inv.maker", roles=["BANK_INVESTIGATOR"])
    maker_headers = {"Authorization": f"Bearer {maker_token}"}

    checker_token = token_factory(sub="auth.checker", roles=["BANK_AUTHORISER"])
    checker_headers = {"Authorization": f"Bearer {checker_token}"}

    # 1. Create a strategy as maker
    oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=maker_headers,
        json={
            "strategy_id": "strat_dual_test",
            "title": "Dual Control Test Strategy",
            "rules_enabled": ["employee_access_before_sensitive_change"],
        },
    )

    # 2. Request approval as maker
    req_resp = oidc_client.post(
        "/api/enterprise/v1/simulation/approvals/request",
        headers=maker_headers,
        json={
            "strategy_id": "strat_dual_test",
            "request_rationale": "Demonstrated 25% recall gain with zero false positive increase.",
        },
    )
    assert req_resp.status_code == 201
    appr_data = req_resp.json()
    appr_id = appr_data["approval_id"]
    assert appr_data["status"] == "pending"
    assert appr_data["requester_subject"] == "inv.maker"

    # Strategy status should now be pending_review
    strat_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies/strat_dual_test", headers=maker_headers)
    assert strat_resp.json()["status"] == "pending_review"

    # 3. DUAL CONTROL VIOLATION: Maker attempts to approve their own request!
    # Even if maker attempts to spoof an authoriser role or calls review, same subject must be rejected:
    maker_as_authoriser_token = token_factory(sub="inv.maker", roles=["BANK_AUTHORISER"])
    maker_as_authoriser_headers = {"Authorization": f"Bearer {maker_as_authoriser_token}"}

    self_review_resp = oidc_client.post(
        f"/api/enterprise/v1/simulation/approvals/{appr_id}/review",
        headers=maker_as_authoriser_headers,
        json={"decision": "approved", "notes": "I approve my own work."},
    )
    assert self_review_resp.status_code == 403
    assert "Dual control violation" in self_review_resp.json()["detail"]

    # 4. Valid Checker approval
    checker_review_resp = oidc_client.post(
        f"/api/enterprise/v1/simulation/approvals/{appr_id}/review",
        headers=checker_headers,
        json={
            "decision": "approved",
            "notes": "Reviewed historical replay validation run; metrics meet risk tolerance.",
        },
    )
    assert checker_review_resp.status_code == 200
    rev_data = checker_review_resp.json()
    assert rev_data["status"] == "approved"
    assert rev_data["reviewer_subject"] == "auth.checker"

    # Strategy status should now be approved
    strat_approved_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies/strat_dual_test", headers=maker_headers)
    assert strat_approved_resp.json()["status"] == "approved"


def test_simulation_tenant_isolation(oidc_client, token_factory):
    token_dom = token_factory(sub="inv.dom", roles=["BANK_INVESTIGATOR"])
    headers_dom = {"Authorization": f"Bearer {token_dom}"}

    # Create strategy in domestic installation
    oidc_client.post(
        "/api/enterprise/v1/simulation/strategies",
        headers=headers_dom,
        json={
            "strategy_id": "strat_dom_secret",
            "title": "Domestic Strategy",
            "rules_enabled": ["employee_access_before_sensitive_change"],
        },
    )

    # Foreign installation token
    token_for = token_factory(
        sub="inv.foreign",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "foreign-tenant-instance"},
    )
    headers_for = {"Authorization": f"Bearer {token_for}"}

    # Foreign installation cannot see domestic strategy -> 404
    get_resp = oidc_client.get("/api/enterprise/v1/simulation/strategies/strat_dom_secret", headers=headers_for)
    assert get_resp.status_code == 404
