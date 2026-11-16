"""Synthetic investigation scenarios distinguishing legitimate, insider, compromised, and system-error incidents."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.change_vector import build_change_vector
from toroka_enterprise.intelligence.contradictions import detect_evidence_contradictions
from toroka_enterprise.intelligence.scenarios import generate_competing_scenarios
from toroka_enterprise.intelligence.reconstruction_engine import reconstruct


def test_synthetic_scenario_1_legitimate_customer_service():
    """Scenario 1: Legitimate Customer Service Activity

    - Employee authenticates during regular hours from standard workstation.
    - Verified CRM service ticket exists.
    - Customer contact details updated per customer request.
    - Result: Legitimate service scenario has highest relative support.
    """
    t0 = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_legit_01",
            event_type="session_start",
            event_time=t0,
            actor="emp_service_rep",
            source_system="iam",
            attributes={"ip_address": "192.168.10.15", "device": "workstation_terminal_01"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_legit_02",
            event_type="support_ticket_created",
            event_time=t0 + timedelta(minutes=2),
            actor="emp_service_rep",
            subject="cif_vip_client",
            source_system="crm",
            attributes={"ticket_id": "CRM-8812", "request": "phone_update"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_legit_03",
            event_type="customer_contact_update",
            event_time=t0 + timedelta(minutes=5),
            actor="emp_service_rep",
            subject="cif_vip_client",
            source_system="core_banking",
            attributes={"ticket_ref": "CRM-8812"},
        ),
    ]

    cv = build_change_vector(
        subject_id="emp_service_rep",
        observed_attributes={"device": "normal", "ip_address": "normal", "working_hours": "normal"},
    )
    contradictions = detect_evidence_contradictions(events)
    scenarios = generate_competing_scenarios(events, change_vector=cv, contradictions=contradictions)

    legit = next(s for s in scenarios if s.scenario_id == "scenario_legitimate_service")
    insider = next(s for s in scenarios if s.scenario_id == "scenario_insider_misuse")

    # Legitimate customer service has highest relative support
    assert legit.relative_support > insider.relative_support
    assert len(legit.supporting_evidence) >= 2


def test_synthetic_scenario_2_insider_unauthorized_misuse():
    """Scenario 2: Unauthorized Insider Misuse

    - Employee accesses high-balance account with no CRM ticket.
    - Changes beneficiary to external account.
    - Immediately initiates high-value wire transfer.
    - Result: Unauthorized employee intervention has highest relative support.
    """
    t0 = datetime(2026, 11, 15, 14, 0, 0, tzinfo=timezone.utc)
    events = [
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_insider_01",
            event_type="customer_record_access",
            event_time=t0,
            actor="emp_rogue_teller",
            subject="cif_target_acc",
            source_system="core_banking",
            attributes={"ip_address": "192.168.10.22"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_insider_02",
            event_type="beneficiary_change",
            event_time=t0 + timedelta(minutes=3),
            actor="emp_rogue_teller",
            subject="cif_target_acc",
            source_system="core_banking",
            attributes={"new_beneficiary": "acc_mule_88"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_insider_03",
            event_type="transfer_initiated",
            event_time=t0 + timedelta(minutes=6),
            actor="emp_rogue_teller",
            subject="cif_target_acc",
            source_system="payment_switch",
            attributes={"amount": 2500000.0, "destination": "acc_mule_88"},
        ),
    ]

    cv = build_change_vector(
        subject_id="emp_rogue_teller",
        observed_attributes={"device": "normal", "ip_address": "normal"},
    )
    contradictions = detect_evidence_contradictions(events)
    scenarios = generate_competing_scenarios(events, change_vector=cv, contradictions=contradictions)

    insider = next(s for s in scenarios if s.scenario_id == "scenario_insider_misuse")
    legit = next(s for s in scenarios if s.scenario_id == "scenario_legitimate_service")

    # Insider misuse has significantly higher support than legitimate service
    assert insider.relative_support > legit.relative_support
    assert any("Beneficiary modification" in s for s in insider.supporting_evidence)


def test_synthetic_scenario_3_compromised_credentials():
    """Scenario 3: Compromised Employee Credentials

    - Session starts from unknown external IP and new unmanaged device.
    - Unusual hour (02:30 AM).
    - Concurrent session exists on branch terminal.
    - Result: Compromised credentials scenario has highest support.
    """
    t0 = datetime(2026, 11, 15, 2, 30, 0, tzinfo=timezone.utc)
    events = [
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_comp_01",
            event_type="session_start",
            event_time=t0,
            actor="emp_victim",
            source_system="iam",
            attributes={"ip_address": "197.232.14.99", "device": "unknown_android_device", "branch_code": "EXTERNAL"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_comp_02",
            event_type="terminal_login",
            event_time=t0 + timedelta(seconds=20),
            actor="emp_victim",
            source_system="siem",
            attributes={"ip_address": "10.0.1.5", "device": "branch_pc_04", "branch_code": "BRANCH_CENTRAL"},
        ),
    ]

    cv = build_change_vector(
        subject_id="emp_victim",
        observed_attributes={
            "device": {"changed": True, "unusual": True},
            "ip_address": {"changed": True, "unusual": True},
            "working_hours": {"changed": True, "unusual": True},
        },
    )
    contradictions = detect_evidence_contradictions(events)
    assert len(contradictions) >= 1  # Simultaneous branch/IP conflict detected

    scenarios = generate_competing_scenarios(events, change_vector=cv, contradictions=contradictions)
    compromised = next(s for s in scenarios if s.scenario_id == "scenario_compromised_credentials")
    legit = next(s for s in scenarios if s.scenario_id == "scenario_legitimate_service")

    assert compromised.relative_support > legit.relative_support
    assert len(compromised.supporting_evidence) >= 1


def test_synthetic_scenario_4_and_5_system_error_and_delayed_ingestion():
    """Scenario 4 & 5: System Integration Error and Delayed Ingestion

    - Core Banking and Switch record conflicting timestamps or statuses due to retry loop.
    - Contradiction is surfaced without silent resolution.
    - System error scenario captures the technical nature of the discrepancy.
    """
    t0 = datetime(2026, 11, 15, 11, 0, 0, tzinfo=timezone.utc)
    events = [
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_sync_cbs",
            event_type="account_status_check",
            event_time=t0,
            actor="system_batch",
            subject="acc_sync_test",
            source_system="core_banking",
            attributes={"account_status": "active"},
        ),
        IntelligenceEvent(
            installation_id="inst_bank",
            event_id="evt_sync_switch",
            event_type="account_status_check",
            event_time=t0 + timedelta(minutes=5),
            actor="system_batch",
            subject="acc_sync_test",
            source_system="payment_switch",
            attributes={"account_status": "dormant"},
        ),
    ]

    contradictions = detect_evidence_contradictions(events)
    assert len(contradictions) >= 1
    assert any(c.field == "account_status" for c in contradictions)

    scenarios = generate_competing_scenarios(events, contradictions=contradictions)
    sys_err = next(s for s in scenarios if s.scenario_id == "scenario_system_error")
    assert any("drifting" in s.lower() or "conflicting" in s.lower() for s in sys_err.supporting_evidence)
