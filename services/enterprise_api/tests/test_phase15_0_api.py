"""API integration tests for Phase 15: Global Frontier Hardening.

Covers:
- Phase 15.0: Singapore MAS Money Lock Vault Partitioning & Anti-Drainage Gate
- Phase 15.1: Brazil BCB Bloqueio Cautelar 72-Hour Hold & Statutory Nighttime Limits
- Phase 15.2: India NPCI Cryptographic SIM & Hardware Integrity Binding
- Phase 15.3: BioCatch Behavioral Biometrics (RAT Detection & Coached Victim Dynamics)
"""
from decimal import Decimal
import pytest


def test_phase15_0_money_lock_lifecycle_and_drainage_blocking(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}
    account_id = "ACC-SG-LOCK-001"

    # 1. Lock KES 450,000 into non-digital vault
    lock_res = oidc_client.post(
        f"/api/enterprise/v1/governance/money-lock/accounts/{account_id}/lock",
        headers=headers,
        json={"amount": "450000.00", "actor": "customer-mobile-app"},
    )
    assert lock_res.status_code == 200, lock_res.text
    data = lock_res.json()
    assert data["status"] == "LOCKED"
    assert data["locked_vault_balance"] == 450000.0
    assert data["available_balance"] == 50000.0

    # 2. Digital drainage attack attempt: Attacker attempts to transfer KES 120,000 > available KES 50,000
    eval_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-DRAIN-001",
            "amount": "120000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Lee Hsien",
            "debtor_account": account_id,
            "creditor_name": "Unknown Mule",
            "creditor_account": "ACC-MULE-TIER1",
            "check_money_lock": True,
            "enforce_nighttime_limits": False,
        },
    )
    assert eval_res.status_code == 200, eval_res.text
    eval_data = eval_res.json()
    assert eval_data["decision"] == "BLOCK"
    assert eval_data["is_money_lock_breach"] is True
    assert "MONEY_LOCK_EXCLUSION_EXCEEDS_LIQUID_AVAILABLE" in eval_data["triggered_rules"]
    assert "REJECT_PAYMENT_MONEY_LOCK_PROTECTED" in eval_data["recommended_action"]

    # 3. Legitimate digital transfer: KES 25,000 <= available KES 50,000 -> Allowed
    legit_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-LEGIT-001",
            "amount": "25000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Lee Hsien",
            "debtor_account": account_id,
            "creditor_name": "Legitimate Merchant",
            "creditor_account": "ACC-MERCHANT-01",
            "check_money_lock": True,
            "enforce_nighttime_limits": False,
        },
    )
    assert legit_res.status_code == 200
    assert legit_res.json()["is_money_lock_breach"] is False

    # 4. Attacker attempts to digitally unlock the vault via API -> 403 Forbidden
    unlock_attempt = oidc_client.post(
        f"/api/enterprise/v1/governance/money-lock/accounts/{account_id}/attempt-digital-unlock",
        headers=headers,
    )
    assert unlock_attempt.status_code == 403
    assert "Digital unlocking is strictly prohibited" in unlock_attempt.json()["detail"]

    # 5. Authorized in-person branch counter unlock with dual-authorization
    branch_unlock = oidc_client.post(
        f"/api/enterprise/v1/governance/money-lock/accounts/{account_id}/branch-unlock",
        headers=headers,
        json={
            "amount": "150000.00",
            "officer_id": "teller-singapore-01",
            "station_id": "STATION-BR-MARINA-01",
            "dual_authorizer_id": "branch-manager-02",
            "channel": "PHYSICAL_BRANCH_COUNTER",
        },
    )
    assert branch_unlock.status_code == 200, branch_unlock.text
    unlocked_data = branch_unlock.json()
    assert unlocked_data["locked_vault_balance"] == 300000.0
    assert unlocked_data["available_balance"] == 200000.0


def test_phase15_1_brazil_nighttime_limits_and_bloqueio_cautelar(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Statutory Nighttime Limit Breach (23:00 local time, KES 60,000 > statutory KES 20,000 cap)
    night_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-NIGHT-001",
            "amount": "60000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Carlos Silva",
            "debtor_account": "ACC-BR-001",
            "creditor_name": "Recipient Store",
            "creditor_account": "ACC-STORE-01",
            "enforce_nighttime_limits": True,
            "client_local_hour": 23,
        },
    )
    assert night_res.status_code == 200, night_res.text
    night_data = night_res.json()
    assert night_data["is_nighttime_breach"] is True
    assert "STATUTORY_NIGHTTIME_LIMIT_EXCEEDED_BCB" in night_data["triggered_rules"]
    assert night_data["recommended_action"] == "DELAY_UNTIL_DAYLIGHT_CLEARING"

    # 2. Create Bloqueio Cautelar 72-Hour Precautionary Hold
    hold_create = oidc_client.post(
        "/api/enterprise/v1/governance/precautionary-holds",
        headers=headers,
        json={
            "tx_id": "TX-BCB-9912",
            "amount": "85000.00",
            "debtor_account": "ACC-VICTIM-01",
            "creditor_account": "ACC-MULE-TIER1",
            "reason": "Severe anomaly in beneficiary velocity; suspect synthetic mule account.",
            "currency": "KES",
            "duration_hours": 72,
        },
    )
    assert hold_create.status_code == 200, hold_create.text
    hold_data = hold_create.json()
    hold_id = hold_data["hold_id"]
    assert hold_data["state"] == "ACTIVE_HOLD_72H"
    assert hold_data["statutory_basis"] == "RESOLUCAO_BCB_493_2025_ART_39"

    # 3. Escalate hold to ISO 20022 camt.056 clawback
    escalate_res = oidc_client.post(
        f"/api/enterprise/v1/governance/precautionary-holds/{hold_id}/escalate",
        headers=headers,
        json={
            "officer_id": "officer-fraud-brazil",
            "resolution_notes": "Confirmed mule syndicate network. Initiating interbank clawback.",
        },
    )
    assert escalate_res.status_code == 200, escalate_res.text
    esc_data = escalate_res.json()
    assert esc_data["state"] == "ESCALATED_CLAWBACK_CAMT056"
    assert esc_data["camt056_xml"] is not None
    assert "FIToFIPmtCxlReq" in esc_data["camt056_xml"]
    assert "<Cd>FRAD</Cd>" in esc_data["camt056_xml"]


def test_phase15_2_india_sim_binding_and_emulator_prohibition(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}
    account_id = "ACC-IN-NPCI-001"

    # 1. Enroll SIM and Hardware anchor
    enroll_res = oidc_client.post(
        "/api/enterprise/v1/governance/sim-binding/enroll",
        headers=headers,
        json={
            "account_id": account_id,
            "device_imei": "352099001761482",
            "sim_iccid": "8991101200003204512",
            "carrier_name": "Safaricom",
        },
    )
    assert enroll_res.status_code == 200, enroll_res.text
    enroll_data = enroll_res.json()
    assert enroll_data["status"] == "BOUND_TRUSTED"
    imei_hash = enroll_data["bound_device_imei_hash"]

    # 2. Test Emulator Execution Prohibited (NPCI standard)
    emu_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-EMU-001",
            "amount": "15000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Rajesh Kumar",
            "debtor_account": account_id,
            "creditor_name": "Merchant",
            "creditor_account": "ACC-MERCHANT-02",
            "sim_is_emulator": True,
            "enforce_nighttime_limits": False,
        },
    )
    assert emu_res.status_code == 200, emu_res.text
    emu_data = emu_res.json()
    assert emu_data["decision"] == "BLOCK"
    assert emu_data["is_emulator_detected"] is True
    assert "EMULATOR_ENVIRONMENT_PROHIBITED_NPCI" in emu_data["triggered_rules"]

    # 3. Test Recent SIM swap cooldown (< 24h)
    swap_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-SWAP-001",
            "amount": "15000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Rajesh Kumar",
            "debtor_account": account_id,
            "creditor_name": "Merchant",
            "creditor_account": "ACC-MERCHANT-02",
            "sim_device_imei_hash": imei_hash,
            "sim_swap_hours_ago": 3.5,
            "enforce_nighttime_limits": False,
        },
    )
    assert swap_res.status_code == 200, swap_res.text
    swap_data = swap_res.json()
    assert swap_data["decision"] == "BLOCK"
    assert swap_data["sim_binding_status"] == "SIM_SWAP_DETECTED_COOLDOWN"
    assert "SIM_SWAP_24H_COOLDOWN_ACTIVE" in swap_data["triggered_rules"]


def test_phase15_3_biocatch_rat_and_coached_victim_detection(oidc_client, token_factory):
    token = token_factory(sub="officer.alice", roles=["BANK_INVESTIGATOR", "BANK_AUTHORISER"])
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Test Remote Access Trojan (RAT) session (straight-line cursor R²=0.99, micro-tremor loss 0.2Hz)
    rat_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-RAT-001",
            "amount": "80000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Victim User",
            "debtor_account": "ACC-VICTIM-RAT",
            "creditor_name": "Remote Fraudster",
            "creditor_account": "ACC-FRAUD-01",
            "biometrics_trajectory_r2": 0.99,
            "biometrics_micro_tremor_hz": 0.2,
            "biometrics_is_remote_software": True,
            "enforce_nighttime_limits": False,
        },
    )
    assert rat_res.status_code == 200, rat_res.text
    rat_data = rat_res.json()
    assert rat_data["decision"] == "BLOCK"
    assert rat_data["is_rat_detected"] is True
    assert rat_data["biometrics_verdict"] == "SUSPECTED_REMOTE_ACCESS_TROJAN"
    assert "REMOTE_ACCESS_TROJAN_CURSOR_LINEARITY_DETECTED" in rat_data["triggered_rules"]
    assert "TERMINATE_SESSION" in rat_data["recommended_action"]
    assert rat_data["precautionary_hold_id"] is not None

    # 2. Test Coached Victim dynamics (Active voice call + 16-second cognitive hesitation + 10 edits)
    coach_res = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers,
        json={
            "end_to_end_id": "E2E-COACH-001",
            "amount": "40000.00",
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Elderly Victim",
            "debtor_account": "ACC-VICTIM-COACH",
            "creditor_name": "Impersonator",
            "creditor_account": "ACC-IMPERSONATOR-01",
            "biometrics_is_active_call": True,
            "biometrics_hesitation_ms": 16000,
            "biometrics_backspaces": 10,
            "enforce_nighttime_limits": False,
        },
    )
    assert coach_res.status_code == 200, coach_res.text
    coach_data = coach_res.json()
    assert coach_data["biometrics_verdict"] == "SUSPECTED_COACHED_VICTIM"
    assert "COACHED_VICTIM_VOICE_CALL_HESITATION_DETECTED" in coach_data["triggered_rules"]
    assert coach_data["decision"] == "STEP_UP_AUTH"
    assert "INTERRUPT_WITH_COACHING_WARNING_MODAL" in coach_data["recommended_action"]
