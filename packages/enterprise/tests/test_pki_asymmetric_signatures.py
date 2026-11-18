"""Tests for Toroka Enterprise PKI, Asymmetric HSM Signatures & Merkle Inclusion Proofs."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from toroka_enterprise.cli_verify import main as cli_main
from toroka_enterprise.governance.deployment import (
    DeploymentEnvironment,
    ProductionReleaseManifest,
    ReleaseStatus,
)
from toroka_enterprise.governance.evidence_passport import TorokaEvidencePassport
from toroka_enterprise.governance.pki import (
    AsymmetricAlgorithm,
    LocalHSMKeyProvider,
    MerkleTree,
    SignatureBundle,
    verify_asymmetric_signature,
    verify_merkle_inclusion_proof,
)


def test_ed25519_signing_and_verification():
    signer = LocalHSMKeyProvider(key_id="bank-hsm-01", algorithm=AsymmetricAlgorithm.ED25519)
    payload = {"message": "High-value suspicious wire transfer", "amount": 1500000.0}

    bundle = signer.sign(payload)
    assert bundle.key_id == "bank-hsm-01"
    assert bundle.algorithm == "Ed25519"
    assert bundle.signature is not None
    assert bundle.content_digest is not None

    # Verification with signer
    assert signer.verify(payload, bundle) is True

    # Standalone verification with trusted public key
    assert verify_asymmetric_signature(payload, bundle, signer.get_public_key_pem()) is True

    # Tampered payload fails
    tampered_payload = {"message": "High-value suspicious wire transfer", "amount": 10.0}
    assert verify_asymmetric_signature(tampered_payload, bundle, signer.get_public_key_pem()) is False

    # Tampered signature fails
    tampered_bundle = SignatureBundle(
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
        signature="dGFtcGVyZWQtc2lnbmF0dXJl",
        public_key_pem=bundle.public_key_pem,
        signed_at=bundle.signed_at,
        digest_algorithm=bundle.digest_algorithm,
        content_digest=bundle.content_digest,
    )
    assert verify_asymmetric_signature(payload, tampered_bundle, signer.get_public_key_pem()) is False


def test_ecdsa_p256_signing_and_verification():
    signer = LocalHSMKeyProvider(key_id="bank-kms-p256", algorithm=AsymmetricAlgorithm.ECDSA_P256)
    payload = {"account": "4401928472", "risk_tier": "critical"}

    bundle = signer.sign(payload)
    assert bundle.algorithm == "ECDSA_P256"
    assert signer.verify(payload, bundle) is True
    assert verify_asymmetric_signature(payload, bundle, signer.get_public_key_pem()) is True
    assert verify_asymmetric_signature(payload, bundle) is False  # no trust anchor

    # Wrong public key fails
    other_signer = LocalHSMKeyProvider(algorithm=AsymmetricAlgorithm.ECDSA_P256)
    assert verify_asymmetric_signature(payload, bundle, other_signer.get_public_key_pem()) is False


def test_evidence_passport_digital_signing():
    passport = TorokaEvidencePassport.create(
        passport_id="pass-bank-test-01",
        finding_id="find-991",
        case_id="case-441",
        installation_id="bank-eu-core",
        component_versions={"detector_mule": "2.4.0", "graph_cluster": "1.8.0"},
    )
    assert passport.verify_integrity() is True
    assert passport.signature_bundle is None

    signer = LocalHSMKeyProvider(key_id="hsm-partition-1")
    signed_passport = passport.sign(signer)

    assert signed_passport.signature_bundle is not None
    assert signed_passport.signing_key_id == "hsm-partition-1"
    assert signed_passport.verify_digital_signature() is False  # trust anchor required
    assert signed_passport.verify_digital_signature(signer.get_public_key_pem()) is True

    # Verification against export dictionary
    passport_dict = signed_passport.to_dict()
    reconstructed = TorokaEvidencePassport.from_payload(
        passport_dict, passport_digest=passport_dict["passport_digest"]
    )
    assert reconstructed.verify_integrity() is True
    assert reconstructed.verify_digital_signature(signer.get_public_key_pem()) is True


def test_production_release_manifest_digital_signing():
    manifest = ProductionReleaseManifest(
        release_id="rel-pilot-prod-01",
        version="2026.11.0",
        environment=DeploymentEnvironment.PILOT,
        status=ReleaseStatus.APPROVED,
        components={"detector_aml": "2.1.0", "core_scorer": "3.0.0"},
        validation_runs=("val-001", "val-002"),
        approval_records=("app-001",),
        created_by="bank.architect@bank.com",
    )
    assert manifest.verify_manifest_integrity() is True
    assert manifest.signature_bundle is None

    signer = LocalHSMKeyProvider(key_id="root-release-key")
    signed_manifest = manifest.sign(signer)

    assert signed_manifest.signature_bundle is not None
    assert signed_manifest.verify_digital_signature() is False  # trust anchor required
    assert signed_manifest.verify_digital_signature(signer.get_public_key_pem()) is True

    manifest_dict = signed_manifest.to_dict()
    assert manifest_dict["signature_bundle"] is not None
    assert manifest_dict["manifest_digest"] == manifest.manifest_digest


def test_rfc6962_merkle_tree_and_inclusion_proofs():
    leaves = [
        {"tx_id": "tx-101", "amount": 5000},
        {"tx_id": "tx-102", "amount": 12000},
        {"tx_id": "tx-103", "amount": 95000},
        {"tx_id": "tx-104", "amount": 3400},
        {"tx_id": "tx-105", "amount": 780000},
    ]

    tree = MerkleTree(leaves)
    assert tree.root_hash is not None
    assert len(tree.root_hash) == 64

    # Verify proof for leaf 2
    proof = tree.generate_inclusion_proof(2)
    assert proof.leaf_index == 2
    assert proof.total_leaves == 5
    assert proof.root_hash == tree.root_hash

    # Proof verifies against original leaf
    assert verify_merkle_inclusion_proof(leaves[2], proof) is True

    # Proof fails against different leaf
    assert verify_merkle_inclusion_proof(leaves[0], proof) is False

    # Proof fails against tampered content
    assert verify_merkle_inclusion_proof({"tx_id": "tx-103", "amount": 99999}, proof) is False


def test_cli_verifier_standalone_execution(capsys):
    signer = LocalHSMKeyProvider(key_id="cli-test-key")
    passport = TorokaEvidencePassport.create(
        passport_id="pass-cli-001",
        finding_id="find-cli",
        case_id="case-cli",
        installation_id="bank-cli",
    ).sign(signer)

    with tempfile.TemporaryDirectory() as tmp_dir:
        pass_file = Path(tmp_dir) / "passport.json"
        pass_file.write_text(json.dumps(passport.to_dict()), encoding="utf-8")

        key_file = Path(tmp_dir) / "public_key.pem"
        key_file.write_text(signer.get_public_key_pem(), encoding="utf-8")

        # 1. Successful passport verification via CLI
        rc = cli_main(["passport", "-f", str(pass_file), "-k", str(key_file), "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        res = json.loads(captured.out)
        assert res["is_valid"] is True
        assert res["digest_verified"] is True
        assert res["signature_verified"] is True

        # 2. Release manifest verification via CLI
        manifest = ProductionReleaseManifest(
            release_id="rel-cli-001",
            version="1.0.0",
            environment=DeploymentEnvironment.PILOT,
            status=ReleaseStatus.APPROVED,
            components={"comp_1": "1.0"},
            validation_runs=("val-1",),
            approval_records=("app-1",),
        ).sign(signer)

        rel_file = Path(tmp_dir) / "release.json"
        rel_file.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

        rc_rel = cli_main(["release", "-f", str(rel_file), "-k", str(key_file), "--json"])
        assert rc_rel == 0
        captured_rel = capsys.readouterr()
        res_rel = json.loads(captured_rel.out)
        assert res_rel["is_valid"] is True
        assert res_rel["signature_verified"] is True
