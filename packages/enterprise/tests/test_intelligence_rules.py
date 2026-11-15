"""Tests for cross-system correlation rules, explainability, alternative explanations, and missing evidence."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.rules import (
    authentication_anomaly_with_sensitive_action,
    customer_complaint_correlated_employee_activity,
    employee_access_before_sensitive_change,
    employee_activity_before_reversal_or_closure,
    privileged_login_before_unusual_transaction,
    role_change_before_sensitive_activity,
    run_all_correlation_rules,
)


def test_rule_a_access_before_sensitive_change():
    t0 = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    e_access = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-access-1",
        event_type="customer_record_access",
        event_time=t0,
        actor="emp_teller_01",
        subject="cif_cust_99",
        source_system="cbs_audit_trail",
    )
    e_change = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-change-1",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=12),
        actor="emp_teller_01",
        subject="cif_cust_99",
        source_system="core_banking",
    )

    signals = employee_access_before_sensitive_change([e_access, e_change])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "access_before_sensitive_change"
    assert sig.confidence == 0.82
    assert "evt-access-1" in sig.event_ids
    assert "evt-change-1" in sig.event_ids
    assert len(sig.alternative_explanations) >= 2
    assert "customer_service_ticket" in sig.missing_evidence

    # If change happened before access -> rule should NOT trigger
    signals_rev = employee_access_before_sensitive_change([e_change, e_access])
    # e_change is before e_access if times reversed:
    e_change_early = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-change-early",
        event_type="beneficiary_change",
        event_time=t0 - timedelta(minutes=5),
        actor="emp_teller_01",
        subject="cif_cust_99",
    )
    assert len(employee_access_before_sensitive_change([e_access, e_change_early])) == 0


def test_rule_b_privileged_login_before_unusual_transaction():
    t0 = datetime(2026, 11, 16, 11, 0, 0, tzinfo=timezone.utc)
    e_elev = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-elev-1",
        event_type="privileged_login",
        event_time=t0,
        actor="emp_supervisor_02",
        source_system="iam_active_directory",
    )
    e_txn = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-txn-1",
        event_type="cash_balancing_posting",
        event_time=t0 + timedelta(minutes=25),
        actor="emp_supervisor_02",
        source_system="core_banking",
        attributes={"amount": "450000.00"},
    )

    signals = privileged_login_before_unusual_transaction([e_elev, e_txn])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "privileged_login_before_unusual_transaction"
    assert sig.severity == "high"
    assert len(sig.alternative_explanations) >= 1
    assert "dual_control_authorisation_record" in sig.missing_evidence


def test_rule_c_role_change_before_sensitive_activity():
    t0 = datetime(2026, 11, 16, 9, 0, 0, tzinfo=timezone.utc)
    e_role = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-role-1",
        event_type="role_assignment",
        event_time=t0,
        actor="hr_admin",
        subject="emp_promoted_05",
        source_system="iam_active_directory",
        attributes={"role": "SYSTEM_DISBURSER"},
    )
    e_act = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-act-1",
        event_type="bulk_payout",
        event_time=t0 + timedelta(hours=3),
        actor="emp_promoted_05",
        source_system="payment_switch",
    )

    signals = role_change_before_sensitive_activity([e_role, e_act])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "role_change_before_sensitive_activity"
    assert "hr_promotion_or_transfer_letter" in sig.missing_evidence


def test_rule_d_employee_activity_before_reversal_or_closure():
    t0 = datetime(2026, 11, 16, 13, 0, 0, tzinfo=timezone.utc)
    e_act = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-manual-1",
        event_type="manual_posting",
        event_time=t0,
        actor="emp_teller_08",
        entities=("acc_1001",),
        source_system="core_banking",
    )
    e_rev = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-rev-1",
        event_type="transaction_reversal",
        event_time=t0 + timedelta(minutes=15),
        entities=("acc_1001",),
        source_system="core_banking",
    )

    signals = employee_activity_before_reversal_or_closure([e_act, e_rev])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "employee_activity_before_reversal_or_closure"


def test_rule_e_customer_complaint_correlated_lookup():
    t0 = datetime(2026, 11, 16, 15, 0, 0, tzinfo=timezone.utc)
    e_comp = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-complaint-1",
        event_type="customer_complaint",
        event_time=t0,
        subject="cif_vip_007",
        source_system="crm_customer_service",
    )
    e_lookup = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-lookup-1",
        event_type="statement_export",
        event_time=t0 + timedelta(hours=2),
        actor="emp_teller_12",
        subject="cif_vip_007",
        source_system="core_banking",
    )

    signals = customer_complaint_correlated_employee_activity([e_comp, e_lookup])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "customer_complaint_correlated_employee_activity"


def test_rule_f_auth_anomaly_with_sensitive_action():
    t0 = datetime(2026, 11, 16, 16, 0, 0, tzinfo=timezone.utc)
    e_login = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-login-anom-1",
        event_type="new_device_login",
        event_time=t0,
        actor="emp_analyst_03",
        source_system="iam_active_directory",
        attributes={"ip_address": "198.51.100.44"},
    )
    e_action = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-action-1",
        event_type="funds_transfer",
        event_time=t0 + timedelta(minutes=10),
        actor="emp_analyst_03",
        source_system="payment_switch",
    )

    signals = authentication_anomaly_with_sensitive_action([e_login, e_action])
    assert len(signals) == 1
    sig = signals[0]
    assert sig.signal_type == "authentication_anomaly_with_sensitive_action"
    assert sig.severity == "high"


def test_run_all_rules_aggregation():
    t0 = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="e1",
        event_type="customer_record_access",
        event_time=t0,
        actor="emp_1",
        subject="cust_1",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="e2",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=5),
        actor="emp_1",
        subject="cust_1",
    )
    all_signals = run_all_correlation_rules([e1, e2])
    assert len(all_signals) == 1
    assert all_signals[0].signal_type == "access_before_sensitive_change"
