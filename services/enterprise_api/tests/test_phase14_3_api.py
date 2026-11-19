"""Tests for Phase 14.3: Multi-Tiered Mule Tracing & Graph Cascade API."""
from decimal import Decimal
import pytest


def test_trigger_mule_cascade_trace_api(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    transfers = [
        {
            "source_account": "ACC_VICTIM_RECIPIENT",
            "target_account": "ACC_TIER2_A",
            "amount": "120000.00",
            "timestamp": "2026-11-19T08:05:00Z",
            "transaction_id": "TX_HOP1_A",
            "payment_rail": "PESALINK",
            "target_bic": "KCBKKENA",
        },
        {
            "source_account": "ACC_VICTIM_RECIPIENT",
            "target_account": "ACC_TIER2_B",
            "amount": "150000.00",
            "timestamp": "2026-11-19T08:12:00Z",
            "transaction_id": "TX_HOP1_B",
            "payment_rail": "PESALINK",
            "target_bic": "EQUAKENA",
        },
    ]

    resp = oidc_client.post(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/trace",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "root_account": "ACC_VICTIM_RECIPIENT",
            "root_fraud_amount": "300000.00",
            "currency": "KES",
            "root_transaction_id": "TX_VICTIM_ROOT",
            "anchor_time": "2026-11-19T08:00:00Z",
            "max_hops": 3,
            "transfers": transfers,
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["trace_id"].startswith("casc_")
    assert data["root_account"] == "ACC_VICTIM_RECIPIENT"
    assert data["total_nodes_identified"] == 3
    assert len(data["nodes"]) == 3
    assert len(data["edges"]) == 2
    assert len(data["directives"]) == 3
    assert data["status"] == "ACTIVE"
    assert float(data["recovery_potential_ratio"]) > 0.0


def test_list_and_get_mule_cascade_traces(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # Create trace
    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/trace",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "root_account": "ACC_LIST_TEST",
            "root_fraud_amount": "150000.00",
            "transfers": [],
        },
    )
    assert create_resp.status_code == 201
    trace_id = create_resp.json()["trace_id"]

    # List traces
    list_resp = oidc_client.get(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/traces",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    traces = list_resp.json()
    assert any(t["trace_id"] == trace_id for t in traces)

    # Get single trace
    get_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/intelligence/mule-cascade/traces/{trace_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    single = get_resp.json()
    assert single["trace_id"] == trace_id
    assert single["root_account"] == "ACC_LIST_TEST"


def test_execute_cascade_directive_local_hold(oidc_client, token_factory):
    token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])

    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/trace",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "root_account": "ACC_HOLD_TARGET",
            "root_fraud_amount": "200000.00",
            "local_bank_bic": "KCBKKENA",
            "transfers": [],
        },
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    trace_id = data["trace_id"]
    directive = data["directives"][0]
    directive_id = directive["directive_id"]
    assert directive["status"] == "PENDING"
    assert directive["is_internal"] is True

    # Execute Hold
    exec_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/intelligence/mule-cascade/traces/{trace_id}/directives/{directive_id}/execute",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "directive_id": directive_id,
            "action": "EXECUTE_LOCAL_HOLD",
            "justification": "Rapid victim fraud report confirmed by branch",
        },
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "EXECUTED"
    assert exec_data["action_taken"] == "EXECUTE_LOCAL_HOLD"

    # Verify updated trace record
    get_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/intelligence/mule-cascade/traces/{trace_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    updated_trace = get_resp.json()
    upd_dir = next(d for d in updated_trace["directives"] if d["directive_id"] == directive_id)
    assert upd_dir["status"] == "EXECUTED"
    assert upd_dir["executed_by"] == "authoriser.bob"
    assert "branch" in upd_dir["justification"]


def test_execute_cascade_directive_camt056_dispatch(oidc_client, token_factory):
    token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])

    transfers = [
        {
            "source_account": "ACC_DISP_ROOT",
            "target_account": "ACC_DISP_EXTERNAL",
            "amount": "180000.00",
            "timestamp": "2026-11-19T09:00:00Z",
            "transaction_id": "TX_DISP_1",
            "payment_rail": "PESALINK",
            "target_bic": "EQUAKENA",
        }
    ]

    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/trace",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "root_account": "ACC_DISP_ROOT",
            "root_fraud_amount": "200000.00",
            "local_bank_bic": "KCBKKENA",
            "anchor_time": "2026-11-19T08:50:00Z",
            "transfers": transfers,
        },
    )
    assert create_resp.status_code == 201
    data = create_resp.json()
    trace_id = data["trace_id"]

    # Find external directive
    ext_dir = next(d for d in data["directives"] if d["is_internal"] is False)
    directive_id = ext_dir["directive_id"]
    assert ext_dir["bank_bic"] == "EQUAKENA"

    # Execute ISO 20022 camt.056 dispatch
    exec_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/intelligence/mule-cascade/traces/{trace_id}/directives/{directive_id}/execute",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "directive_id": directive_id,
            "action": "DISPATCH_CAMT056",
            "justification": "Interbank rapid recall directive dispatched to Equity Bank",
        },
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "EXECUTED"
    assert exec_data["action_taken"] == "DISPATCH_CAMT056"
    assert exec_data["camt056_xml"] is not None
    assert "camt.056.001.10" in exec_data["camt056_xml"]
    assert "EQUAKENA" in exec_data["camt056_xml"]
    assert "FRAD" in exec_data["camt056_xml"]


def test_reject_cascade_directive(oidc_client, token_factory):
    token = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])

    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/trace",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "root_account": "ACC_REJECT_TEST",
            "root_fraud_amount": "50000.00",
            "transfers": [],
        },
    )
    trace_id = create_resp.json()["trace_id"]
    directive_id = create_resp.json()["directives"][0]["directive_id"]

    exec_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/intelligence/mule-cascade/traces/{trace_id}/directives/{directive_id}/execute",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "directive_id": directive_id,
            "action": "REJECT",
            "justification": "Account verified as legitimate business supplier",
        },
    )
    assert exec_resp.status_code == 200
    assert exec_resp.json()["status"] == "REJECTED"


def test_trace_not_found(oidc_client, token_factory):
    token = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    resp = oidc_client.get(
        "/api/enterprise/v1/governance/intelligence/mule-cascade/traces/casc_does_not_exist",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
