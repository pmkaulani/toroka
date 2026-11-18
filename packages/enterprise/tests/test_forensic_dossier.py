"""Tests for Court-Ready Forensic Evidence Dossier & Section 106B Electronic Records Admissibility."""
import json
from datetime import datetime, timezone
import pytest

from toroka_enterprise.governance.deployment import canonical_json
from toroka_enterprise.governance.forensic_dossier import (
    CustodyEvent,
    ForensicDossier,
    Section106BCertificate,
    compute_forensic_dossier_digest,
)
from toroka_enterprise.governance.pki import (
    AsymmetricAlgorithm,
    LocalHSMKeyProvider,
)
from toroka_enterprise.cli_verify import main as cli_main


def test_forensic_dossier_canonical_hashing_and_tamper_evidence():
    now = datetime(2026, 11, 18, 2, 0, 0, tzinfo=timezone.utc)
    custody = CustodyEvent(
        event_id="cust-001",
        timestamp=now,
        actor_subject="examiner_01",
        actor_role="LEAD_EXAMINER",
        action="DOSSIER_COMPILED",
        source_hash="0" * 64,
        destination_hash="1" * 64,
        notes="Initial intake",
    )
    cert = Section106BCertificate(
        certificate_id="cert-106b-001",
        statutory_framework="Kenya Evidence Act (Cap 80) Section 106B",
        certifier_name="Inspector J. Kamau",
        certifier_designation="Senior Forensic Investigator",
        certifier_organization="Toroka Financial Crime Compliance",
        device_identification="TOROKA-NODE-NBO-01",
        operating_condition_statement="System operated properly without malfunction.",
        hash_algorithm="SHA-256",
        merkle_root_hash="1" * 64,
        certified_at=now,
        declaration_text="I certify the electronic record accuracy.",
    )

    dossier = ForensicDossier(
        dossier_id="dos-001",
        case_id="case-100",
        installation_id="inst-test-01",
        title="M-PESA Pass-Through Syndicate Investigation",
        incident_type="M-PESA Pass-Through Layering",
        fraud_loss_amount=1500000.0,
        currency="KES",
        examiner_subject="examiner_01",
        examiner_role="LEAD_EXAMINER",
        created_at=now,
        case_summary="Corroborated 4-hop pass-through velocity anomaly.",
        attack_path_summary={"hops": 4, "total_nodes": 6},
        identified_mule_nodes=(
            {"account_number": "01199887766", "entity_name": "Kamau Enterprises", "risk_score": 0.95},
        ),
        evidence_records=(
            {"evidence_id": "ev-001", "excerpt": "Unusual transfer of KES 500,000"},
        ),
        chain_of_custody=(custody,),
        section_106b_certificate=cert,
    )

    assert dossier.dossier_digest != ""
    assert dossier.verify_dossier_integrity() is True

    # Tampering with fraud amount should invalidate integrity
    tampered = ForensicDossier(
        dossier_id=dossier.dossier_id,
        case_id=dossier.case_id,
        installation_id=dossier.installation_id,
        title=dossier.title,
        incident_type=dossier.incident_type,
        fraud_loss_amount=9999999.0,  # Tampered
        currency=dossier.currency,
        examiner_subject=dossier.examiner_subject,
        examiner_role=dossier.examiner_role,
        created_at=dossier.created_at,
        case_summary=dossier.case_summary,
        attack_path_summary=dossier.attack_path_summary,
        identified_mule_nodes=dossier.identified_mule_nodes,
        evidence_records=dossier.evidence_records,
        chain_of_custody=dossier.chain_of_custody,
        section_106b_certificate=dossier.section_106b_certificate,
        dossier_digest=dossier.dossier_digest,  # Original digest
    )
    assert tampered.verify_dossier_integrity() is False


def test_forensic_dossier_digital_signing_ed25519_and_ecdsa():
    now = datetime.now(timezone.utc)
    dossier = ForensicDossier(
        dossier_id="dos-pki-01",
        case_id="case-200",
        installation_id="inst-test-01",
        title="Forensic Evidence Dossier with PKI Seal",
        incident_type="Advance Fee Fraud",
        fraud_loss_amount=250000.0,
        currency="KES",
        examiner_subject="examiner_lead",
        examiner_role="LEAD_EXAMINER",
        created_at=now,
        case_summary="Fraud ring identified across Pesalink transfers.",
        attack_path_summary={"hops": 2},
        identified_mule_nodes=(),
        evidence_records=(),
        chain_of_custody=(),
    )

    # 1. Sign with Ed25519
    ed_signer = LocalHSMKeyProvider(key_id="hsm-key-examiner-ed25519", algorithm=AsymmetricAlgorithm.ED25519)
    dossier.sign(ed_signer)

    assert dossier.signature_bundle is not None
    assert dossier.signature_bundle.algorithm == "Ed25519"
    assert dossier.verify_digital_signature() is False  # trust anchor required
    assert dossier.verify_digital_signature(trusted_public_key_pem=ed_signer.public_key_pem) is True

    # 2. Sign with ECDSA P-256
    ecdsa_signer = LocalHSMKeyProvider(key_id="hsm-key-examiner-ecdsa", algorithm=AsymmetricAlgorithm.ECDSA_P256)
    dossier.sign(ecdsa_signer)

    assert dossier.signature_bundle.algorithm == "ECDSA_P256"
    assert dossier.verify_digital_signature() is False
    assert dossier.verify_digital_signature(trusted_public_key_pem=ecdsa_signer.public_key_pem) is True


def test_render_html_court_dossier():
    now = datetime(2026, 11, 18, 2, 0, 0, tzinfo=timezone.utc)
    cert = Section106BCertificate(
        certificate_id="cert-106b-test",
        statutory_framework="Kenya Evidence Act (Cap 80) Section 106B",
        certifier_name="Inspector J. Kamau",
        certifier_designation="Senior Forensic Investigator",
        certifier_organization="Banking Fraud Investigations Unit",
        device_identification="TOROKA-NODE-NBO-01",
        operating_condition_statement="Operating properly without malfunction.",
        hash_algorithm="SHA-256",
        merkle_root_hash="a" * 64,
        certified_at=now,
        declaration_text="Solemn affirmation of electronic record accuracy.",
    )
    dossier = ForensicDossier(
        dossier_id="dos-html-01",
        case_id="case-300",
        installation_id="inst-test-01",
        title="Court Dossier HTML Test",
        incident_type="SIM Swap & Layering",
        fraud_loss_amount=750000.0,
        currency="KES",
        examiner_subject="examiner_court",
        examiner_role="LEAD_EXAMINER",
        created_at=now,
        case_summary="Executive findings for court submission.",
        attack_path_summary={"hops": 3},
        identified_mule_nodes=(
            {"account_number": "123456789", "entity_name": "Test Mule", "risk_score": 0.9, "role": "Pass-Through Mule"},
        ),
        evidence_records=(),
        chain_of_custody=(
            CustodyEvent(
                event_id="cust-01",
                timestamp=now,
                actor_subject="examiner_court",
                actor_role="LEAD_EXAMINER",
                action="DOSSIER_COMPILED",
                source_hash="0" * 64,
                destination_hash="b" * 64,
            ),
        ),
        section_106b_certificate=cert,
    )

    signer = LocalHSMKeyProvider(key_id="hsm-court", algorithm=AsymmetricAlgorithm.ED25519)
    dossier.sign(signer)

    html_out = dossier.render_html_dossier()

    assert "DRAFT COMPILATION" in html_out
    assert "NOT A SECTION 106B CERTIFICATE OR COURT FILING" in html_out
    assert "REPUBLIC OF KENYA" not in html_out
    assert "KES 750,000.00" in html_out
    assert dossier.dossier_digest in html_out
    assert dossier.signature_bundle.signature_hex in html_out


def test_cli_verifier_dossier_subcommand(tmp_path):
    now = datetime.now(timezone.utc)
    dossier = ForensicDossier(
        dossier_id="dos-cli-01",
        case_id="case-cli-100",
        installation_id="inst-cli",
        title="CLI Verifier Test Dossier",
        incident_type="M-PESA Pass-Through",
        fraud_loss_amount=300000.0,
        currency="KES",
        examiner_subject="inspector_cli",
        examiner_role="LEAD_EXAMINER",
        created_at=now,
        case_summary="Investigative findings for CLI test.",
        attack_path_summary={},
        identified_mule_nodes=(),
        evidence_records=(),
        chain_of_custody=(),
    )
    signer = LocalHSMKeyProvider(key_id="hsm-cli-key", algorithm=AsymmetricAlgorithm.ED25519)
    dossier.sign(signer)

    dossier_file = tmp_path / "dossier.json"
    pubkey_file = tmp_path / "pubkey.pem"

    dossier_file.write_text(json.dumps(dossier.to_dict()), encoding="utf-8")
    pubkey_file.write_text(signer.public_key_pem, encoding="utf-8")

    # Run CLI verification
    code = cli_main(["dossier", "-f", str(dossier_file), "-k", str(pubkey_file), "--json"])
    assert code == 0
