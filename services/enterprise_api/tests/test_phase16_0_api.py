"""API integration tests for Phase 16: Global Frontier Complete Defenses.

Covers:
- Phase 16.0: Singapore MAS SRF Waterfall Adjudication & 24/7 Customer Kill Switch
- Phase 16.1: South Korea FSS Designated Safe Accounts, 30-min ATM Hold & Ingress Shield
- Phase 16.2: Brazil BCB Limit Increase Cooling-off & Pix MED 2.0 5-Layer Cascading Clawback
- Phase 16.3: India I4C Helpline 1930 Golden Hour Emergency Intake
- Phase 16.4: Hong Kong FPS Scameter High-Risk Proxy Warning & Statutory Liability Shielding
"""
from datetime import datetime, timezone
from decimal import Decimal
import pytest


def test_phase16_0_srf_adjudication_and_kill_switch_api(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}
    account_id = "ACC-SG-SRF-001"

    # 1. Adjudicate SRF Phishing Claim (Bank breached token cooling duty)
    srf_res = oidc_client.post(
        "/api/enterprise/v1/governance/srf/adjudicate",
        headers=headers,
        json={
            "account_id": account_id,
            "disputed_amount": "200000.00",
            "enforced_token_cooling_12h": False,  # Bank breach
            "real_time_alert_dispatched": True,
            "kill_switch_available_24_7": True,
            "fraud_surveillance_active": True,
            "checked_ssir_registry": True,
            "blocked_sender_id_spoofing": True,
            "filtered_malicious_urls": True,
            "consumer_gross_negligence": False,
        },
    )
    assert srf_res.status_code == 200, srf_res.text
    srf_data = srf_res.json()
    assert srf_data["liability_verdict"] == "BANK_100_PERCENT"
    assert srf_data["reimbursement_bank_amount"] == "200000.00"
    assert "TOKEN_COOLING_VIOLATION" in srf_data["identified_breaches"]

    # 2. Activate 24/7 Customer Emergency Kill Switch
    act_res = oidc_client.post(
        f"/api/enterprise/v1/governance/customer-kill-switch/accounts/{account_id}/activate",
        headers=headers,
        json={
            "channel": "MOBILE_PANIC_BUTTON",
            "reason": "Victim phone snatched / credentials compromised",
            "active_sessions_to_revoke": 2,
        },
    )
    assert act_res.status_code == 200, act_res.text
    act_data = act_res.json()
    assert act_data["status"] == "ACTIVE"
    assert act_data["revoked_sessions_count"] == 2

    # 3. Inflight transfer must be hard-blocked by active kill switch
    eval_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-KS-BLOCKED-01",
            "amount": "5000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Panicked Victim",
            "debtor_account": account_id,
            "creditor_name": "Scammer Mule",
            "creditor_account": "ACC-MULE-999",
            "check_kill_switch": True,
            "check_money_lock": False,
        },
    )
    assert eval_res.status_code == 200, eval_res.text
    eval_data = eval_res.json()
    assert eval_data["decision"] == "BLOCK"
    assert eval_data["is_kill_switch_active"] is True
    assert "CUSTOMER_24_7_EMERGENCY_KILL_SWITCH_ACTIVE" in eval_data["triggered_rules"]

    # 4. Deactivate Kill Switch via dual-officer maker-checker
    deact_res = oidc_client.post(
        f"/api/enterprise/v1/governance/customer-kill-switch/accounts/{account_id}/deactivate",
        headers=headers,
        json={
            "maker_officer": "officer.alice",
            "checker_officer": "officer.bob",
            "branch_code": "BR-NAIROBI-HQ",
            "notes": "Customer physically verified with biometric ID in branch",
        },
    )
    assert deact_res.status_code == 200, deact_res.text
    deact_data = deact_res.json()
    assert deact_data["status"] == "INACTIVE"
    assert deact_data["deactivation_branch_code"] == "BR-NAIROBI-HQ"


def test_phase16_1_safe_accounts_and_delayed_atm_api(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}
    account_id = "ACC-KOR-SAFE-001"

    # 1. Register a Designated Safe Account
    reg_res = oidc_client.post(
        f"/api/enterprise/v1/governance/safe-accounts/accounts/{account_id}",
        headers=headers,
        json={
            "payee_account": "ACC-TRUSTED-LANDLORD",
            "payee_institution": "KCBKKENA",
            "label": "Apartment Landlord Rent",
        },
    )
    assert reg_res.status_code == 200, reg_res.text
    assert reg_res.json()["is_active"] is True

    # 2. List designated safe accounts
    list_res = oidc_client.get(
        f"/api/enterprise/v1/governance/safe-accounts/accounts/{account_id}",
        headers=headers,
    )
    assert list_res.status_code == 200, list_res.text
    assert len(list_res.json()) >= 1

    # 3. Transfer to non-designated payee exceeding micro-limit triggers STEP_UP_AUTH
    eval_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-NON-SAFE-01",
            "amount": "80000.00",  # > 10,000 micro-limit
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Careful Saver",
            "debtor_account": account_id,
            "creditor_name": "Stranger Account",
            "creditor_account": "ACC-STRANGER-888",
            "enforce_safe_accounts": True,
            "check_money_lock": False,
        },
    )
    assert eval_res.status_code == 200, eval_res.text
    eval_data = eval_res.json()
    assert eval_data["safe_accounts_breach"] is True
    assert eval_data["is_designated_safe_payee"] is False
    assert "NON_DESIGNATED_SAFE_ACCOUNT_MICRO_LIMIT_EXCEEDED" in eval_data["triggered_rules"]

    # 4. Ingress Shield: Commercial VPN block
    vpn_eval = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-VPN-01",
            "amount": "2000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Careful Saver",
            "debtor_account": account_id,
            "creditor_name": "Utility",
            "creditor_account": "ACC-TRUSTED-LANDLORD",
            "check_ip_ingress": True,
            "client_ip": "185.220.101.4",
            "is_vpn": True,
            "check_money_lock": False,
        },
    )
    assert vpn_eval.status_code == 200, vpn_eval.text
    vpn_data = vpn_eval.json()
    assert vpn_data["decision"] == "BLOCK"
    assert vpn_data["ip_ingress_verdict"] == "BLOCK_VPN_OR_TOR"

    # 5. Delayed ATM Cash-Out: Electronic deposit of 120,000 initiates 30-min hold
    atm_dep = oidc_client.post(
        f"/api/enterprise/v1/governance/delayed-atm/inbound-deposit/{account_id}",
        headers=headers,
        json={"amount": "120000.00", "reference": "INBOUND-RTGS-99"},
    )
    assert atm_dep.status_code == 200, atm_dep.text
    assert atm_dep.json()["allowed"] is False
    assert "anti-runner ATM hold" in atm_dep.json()["reason"]

    # Withdrawal immediately evaluation returns hold active
    atm_eval = oidc_client.post(
        f"/api/enterprise/v1/governance/delayed-atm/evaluate-withdrawal/{account_id}",
        headers=headers,
        json={"amount": "50000.00"},
    )
    assert atm_eval.status_code == 200, atm_eval.text
    assert atm_eval.json()["allowed"] is False
    assert "anti-runner quarantine in effect" in atm_eval.json()["reason"]


def test_phase16_2_limit_increase_cooling_and_med2_clawback_api(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}
    account_id = "ACC-BR-COOL-001"

    # 1. Request Limit Increase enters 24h cooling
    lim_res = oidc_client.post(
        f"/api/enterprise/v1/governance/transfer-limits/accounts/{account_id}/increase-request",
        headers=headers,
        json={"limit_type": "DAILY_P2P", "requested_limit": "250000.00"},
    )
    assert lim_res.status_code == 200, lim_res.text
    lim_data = lim_res.json()
    assert lim_data["is_cooling"] is True
    assert lim_data["requested_limit"] == "250000.00"

    # 2. Execute Brazil BCB Pix MED 2.0 5-Layer Cascading Clawback Trace
    now_iso = datetime.now(timezone.utc).isoformat()
    med2_res = oidc_client.post(
        "/api/enterprise/v1/governance/med2/cascade-clawback",
        headers=headers,
        json={
            "original_tx_id": "PIX-FRAUD-9999",
            "victim_account": "ACC-BRAZIL-VICTIM",
            "total_stolen_amount": "50000.00",
            "incident_timestamp": now_iso,
            "edges": [
                {
                    "edge_id": "MED2-E1",
                    "source_account": "ACC-BRAZIL-VICTIM",
                    "target_account": "ACC-MULE-T1",
                    "target_institution_bic": "ITAU0001",
                    "amount": "50000.00",
                    "hop_tier": 1,
                    "timestamp": now_iso,
                },
                {
                    "edge_id": "MED2-E2",
                    "source_account": "ACC-MULE-T1",
                    "target_account": "ACC-MULE-T2",
                    "target_institution_bic": "BRAD0002",
                    "amount": "30000.00",
                    "hop_tier": 2,
                    "timestamp": now_iso,
                },
                {
                    "edge_id": "MED2-E3",
                    "source_account": "ACC-MULE-T2",
                    "target_account": "ACC-MULE-T3",
                    "target_institution_bic": "NUBK0003",
                    "amount": "20000.00",
                    "hop_tier": 3,
                    "timestamp": now_iso,
                },
            ],
            "account_balances": {
                "ACC-MULE-T1": "10000.00",
                "ACC-MULE-T2": "20000.00",
                "ACC-MULE-T3": "20000.00",
            },
        },
    )
    assert med2_res.status_code == 200, med2_res.text
    med2_data = med2_res.json()
    assert med2_data["is_within_80_day_window"] is True
    # Recovered 10k + 20k + 20k = 50k (100% recovery)
    assert med2_data["total_clawback_holds_placed"] == "50000.00"
    assert med2_data["recovery_rate_pct"] == 100.0
    assert len(med2_data["hops"]) == 3


def test_phase16_3_golden_hour_intake_and_scameter_shield_api(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. India I4C 1930 Helpline Golden Hour Emergency Intake
    now_iso = datetime.now(timezone.utc).isoformat()
    gh_res = oidc_client.post(
        "/api/enterprise/v1/governance/golden-hour/reports",
        headers=headers,
        json={
            "victim_account_id": "ACC-IND-VICTIM-01",
            "victim_phone": "+919876543210",
            "scam_category": "DIGITAL_ARREST_POLICE_FRAUD",
            "incident_timestamp": now_iso,
            "total_amount_lost": "350000.00",
            "transaction_references": ["UPI-REF-001", "UPI-REF-002"],
            "target_recipients": [
                {
                    "recipient_account": "ACC-IND-MULE-01",
                    "recipient_institution_bic": "SBIN0001",
                    "amount_flagged": "350000.00",
                    "freeze_action": "LOCK_ALL_OUTBOUND_AND_ATM",
                }
            ],
        },
    )
    assert gh_res.status_code == 200, gh_res.text
    gh_data = gh_res.json()
    assert gh_data["is_golden_hour"] is True
    assert gh_data["switch_status"] == "BROADCAST_DISPATCHED"
    assert gh_data["target_recipients_count"] == 1

    # 2. Hong Kong FPS Scameter Lookup: Flagged police cybercrime proxy
    scameter_res = oidc_client.post(
        "/api/enterprise/v1/governance/scameter/lookup",
        headers=headers,
        json={"proxy_id": "0712345678", "proxy_type": "PHONE"},
    )
    assert scameter_res.status_code == 200, scameter_res.text
    scam_data = scameter_res.json()
    assert scam_data["risk_level"] == "HIGH_RISK_POLICE_RECORD"
    assert scam_data["unskippable_warning_required"] is True
    assert scam_data["requires_liability_waiver"] is True

    # 3. Execute Statutory Liability Waiver
    waiver_res = oidc_client.post(
        "/api/enterprise/v1/governance/scameter/waivers",
        headers=headers,
        json={
            "account_id": "ACC-HK-SENDER-01",
            "customer_id": "CUST-HK-SENDER-01",
            "proxy_id": "0712345678",
            "risk_level": "HIGH_RISK_POLICE_RECORD",
            "transfer_amount": "25000.00",
            "customer_consent_ack": True,
        },
    )
    assert waiver_res.status_code == 200, waiver_res.text
    w_data = waiver_res.json()
    assert w_data["is_institution_shielded"] is True
    waiver_id = w_data["waiver_id"]

    # 4. Inflight payment with executed waiver succeeds with shielded flag
    eval_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-WAIVER-CLEARED-01",
            "amount": "25000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Informed Customer",
            "debtor_account": "ACC-HK-SENDER-01",
            "creditor_name": "Flagged Recipient",
            "creditor_account": "ACC-HK-MULE-01",
            "check_scameter": True,
            "scameter_proxy_id": "0712345678",
            "scameter_waiver_id": waiver_id,
            "check_money_lock": False,
        },
    )
    assert eval_res.status_code == 200, eval_res.text
    eval_data = eval_res.json()
    assert eval_data["is_scameter_shielded"] is True
    assert "FPS_SCAMETER_STATUTORY_LIABILITY_WAIVER_EXECUTED" in eval_data["triggered_rules"]
