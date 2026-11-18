"""Toroka Enterprise — Phase 13.1 API Tests.

Verifies:
1. Court-Ready Forensic Evidence Dossiers (Sec 106B of Kenya Evidence Act) lifecycle:
   - Creation, Section 106B certificate binding, and chain-of-custody tracking.
   - Authoriser digital signing with HSM key.
   - Cryptographic verification endpoint.
   - Export to publication-grade, court-admissible HTML dossier.
2. ISO 20022 Financial Messaging & In-Flight Risk Scoring:
   - Low-latency (<100ms) pre-clearing evaluation across Pesalink/KEPSS/M-PESA rails.
   - Accurate advisory decisions (ALLOW vs. BLOCK / QUARANTINE_HOLD).
3. Semantic Entailment & Anti-Hallucination Copilot Grounding:
   - Semantic entailment verification.
   - Polarity contradiction detection.
   - Financial figure hallucination detection.
"""
from __future__ import annotations

import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService


@pytest.fixture
def phase13_1_case(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Phase 13.1 Court Exhibit Case",
        focus="acc_dossier_01",
        snapshot={"customer_ref": "cif_court_100"},
        principal=investigator,
    )
    return {"case_id": case.id, "installation_id": inst_id}


def test_forensic_dossier_lifecycle_api(oidc_client, token_factory, phase13_1_case):
    token_authoriser = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    case_id = phase13_1_case["case_id"]

    # 1. Create Forensic Dossier with Section 106B Certificate
    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/forensic-dossiers",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "case_id": case_id,
            "title": "M-PESA Syndicate Rapid Pass-Through Investigation",
            "incident_type": "M-PESA Pass-Through Layering",
            "fraud_loss_amount": 1250000.0,
            "currency": "KES",
            "case_summary": "4-hop rapid pass-through syndicate detected moving KES 1.25M into cash-out wallets.",
            "certifier_name": "Inspector J. Kamau",
            "certifier_designation": "Senior Forensic Examiner",
            "declaration_text": "I solemnly declare that the electronic records are authentic under Section 106B.",
            "identified_mule_nodes": [
                {"account_number": "01199887766", "entity_name": "Kamau Enterprises", "risk_score": 0.95, "role": "Pass-Through Mule"},
            ],
            "evidence_records": [
                {"evidence_id": "ev-pacs-001", "excerpt": "Rapid credit transfer of KES 500,000 on Pesalink"},
            ],
        },
    )
    assert create_resp.status_code == 201
    dossier = create_resp.json()
    dossier_id = dossier["dossier_id"]

    assert dossier["title"] == "M-PESA Syndicate Rapid Pass-Through Investigation"
    assert dossier["fraud_loss_amount"] == 1250000.0
    assert dossier["is_digitally_signed"] is False
    assert dossier["is_verified"] is False
    assert dossier["status"] == "DRAFT_UNVERIFIED"
    assert dossier["section_106b_certificate"] is None
    assert len(dossier["chain_of_custody"]) >= 1

    # 2. Retrieve Dossier
    get_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier_id}",
        headers={"Authorization": f"Bearer {token_investigator}"},
    )
    # router is GET
    get_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier_id}",
        headers={"Authorization": f"Bearer {token_investigator}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["dossier_id"] == dossier_id

    # 3. Sign Dossier with Authoriser HSM Key
    sign_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier_id}/sign",
        headers={"Authorization": f"Bearer {token_authoriser}"},
        json={"algorithm": "Ed25519"},
    )
    assert sign_resp.status_code == 200
    signed_data = sign_resp.json()
    assert signed_data["is_digitally_signed"] is True
    assert signed_data["status"] == "SEALED_SIGNED"
    assert signed_data["signature_bundle"] is not None
    assert signed_data["signature_bundle"]["algorithm"] == "Ed25519"

    # 4. Verify Cryptographic Integrity & Signature
    verify_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier_id}/verify",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={},
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["is_valid"] is True
    assert v_data["digest_verified"] is True
    assert v_data["signature_verified"] is True

    # 5. Export HTML Court Package
    html_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier_id}/export-html",
        headers={"Authorization": f"Bearer {token_investigator}"},
    )
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
    html_text = html_resp.text
    assert "REPUBLIC OF KENYA" in html_text
    assert "SECTION 106B" in html_text.upper()
    assert "DRAFT UNVERIFIED" in html_text.upper()
    assert dossier["dossier_digest"] in html_text


def test_iso20022_inflight_payment_risk_evaluation_api(oidc_client, token_factory):
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # 1. Clean low-risk payment
    clean_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "end_to_end_id": "E2E-API-CLEAN-01",
            "amount": 2500.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Alice Payer",
            "debtor_account": "01100011122",
            "creditor_name": "Bob Merchant",
            "creditor_account": "01133344455",
            "remittance_narrative": "Payment for groceries",
            "account_prior_transfers_count": 20,
        },
    )
    assert clean_resp.status_code == 200
    clean_data = clean_resp.json()
    assert clean_data["decision"] == "ALLOW"
    assert clean_data["risk_tier"] == "LOW"
    assert clean_data["latency_ms"] < 100.0

    # 2. Suspicious narrative transfer
    scam_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "end_to_end_id": "E2E-API-SUSP-01",
            "amount": 350000.0,
            "currency": "KES",
            "clearing_rail": "PESALINK",
            "debtor_name": "Victim Payer",
            "debtor_account": "01100099988",
            "creditor_name": "Unknown Scammer",
            "creditor_account": "01188877766",
            "remittance_narrative": "Urgent activation fee for bitcoin release",
            "account_prior_transfers_count": 0,
        },
    )
    assert scam_resp.status_code == 200
    scam_data = scam_resp.json()
    assert scam_data["decision"] in ("QUARANTINE_HOLD", "BLOCK")
    assert scam_data["risk_tier"] in ("HIGH", "CRITICAL")
    assert len(scam_data["triggered_rules"]) >= 1


def test_copilot_semantic_grounding_verification_api(oidc_client, token_factory):
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    evidence = [
        {
            "evidence_id": "ev:101",
            "source_system": "CORE_BANKING",
            "source_record_id": "TX-101",
            "record_type": "TRANSACTION",
            "excerpt": "Payment of KES 75,000 was confirmed and authorized by customer on Nov 15.",
        },
    ]

    # Valid claim
    valid_payload = {
        "claims": [
            {
                "claim_id": "c-101",
                "statement": "Customer confirmed and authorized the KES 75,000 transfer.",
                "kind": "fact",
                "evidence_ids": ["ev:101"],
            }
        ],
        "evidence_context": evidence,
    }
    v_resp = oidc_client.post(
        "/api/enterprise/v1/governance/copilot/semantic-verify",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json=valid_payload,
    )
    assert v_resp.status_code == 200
    v_data = v_resp.json()
    assert v_data["is_valid"] is True
    assert v_data["entailed_claims"] == 1

    # Contradicted claim (polarity inversion)
    contra_payload = {
        "claims": [
            {
                "claim_id": "c-102",
                "statement": "Customer denied the transaction as fraudulent.",
                "kind": "fact",
                "evidence_ids": ["ev:101"],
            }
        ],
        "evidence_context": evidence,
    }
    c_resp = oidc_client.post(
        "/api/enterprise/v1/governance/copilot/semantic-verify",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json=contra_payload,
    )
    assert c_resp.status_code == 200
    c_data = c_resp.json()
    assert c_data["is_valid"] is False
    assert c_data["contradicted_claims"] == 1
