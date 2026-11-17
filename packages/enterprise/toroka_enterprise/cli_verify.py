"""Toroka Enterprise — Standalone Offline Verifier CLI (toroka-verify).

Provides statutory bank supervisors, internal auditors, law enforcement, and
court inspectors with a zero-dependency CLI tool to verify the cryptographic
authenticity, non-repudiation signature, and evidence lineage of any Toroka
Evidence Passport or Release Manifest offline without requiring database access
or network connectivity.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys
from pathlib import Path
from typing import Any

from toroka_enterprise.governance.deployment import (
    compute_release_manifest_digest,
    release_manifest_payload,
)
from toroka_enterprise.governance.evidence_passport import (
    TorokaEvidencePassport,
    compute_evidence_digest,
)
from toroka_enterprise.governance.pki import (
    SignatureBundle,
    verify_asymmetric_signature,
    verify_merkle_inclusion_proof,
    MerkleInclusionProof,
)


def _load_json(file_path: str) -> dict[str, Any]:
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def verify_passport_file(
    file_path: str,
    trusted_public_key_pem: str | None = None,
) -> dict[str, Any]:
    """Offline verification of an Evidence Passport."""
    data = _load_json(file_path)
    passport_digest = str(data.get("passport_digest", ""))

    try:
        passport = TorokaEvidencePassport.from_payload(data, passport_digest=passport_digest)
    except Exception as exc:
        return {
            "is_valid": False,
            "error": f"Malformed passport payload: {exc}",
            "passport_id": data.get("passport_id", "unknown"),
        }

    # 1. Verify content digest integrity
    is_digest_valid = passport.verify_integrity()

    # 2. Verify digital signature if present
    sig_info = data.get("signature_bundle")
    signature_verified = False
    sig_error: str | None = None

    if sig_info:
        try:
            bundle = SignatureBundle.from_dict(sig_info)
            canonical = passport.canonical_payload()
            signature_verified = verify_asymmetric_signature(
                payload=canonical,
                bundle=bundle,
                trusted_public_key_pem=trusted_public_key_pem,
            )
            if not signature_verified:
                sig_error = "Cryptographic digital signature verification failed against payload"
        except Exception as exc:
            sig_error = f"Signature verification error: {exc}"
    else:
        sig_error = "Passport is unsigned (tamper-evident SHA-256 digest only, no non-repudiation signature)"

    # 3. Verify internal evidence item records
    evidence_records = data.get("evidence_records", [])
    evidence_records_count = len(evidence_records)
    evidence_valid = evidence_records_count == passport.evidence_count

    # 4. Verify Merkle proof if present
    merkle_valid: bool | None = None
    merkle_info = data.get("merkle_proof")
    if merkle_info:
        try:
            proof = MerkleInclusionProof.from_dict(merkle_info)
            merkle_valid = verify_merkle_inclusion_proof(
                leaf_content=passport.canonical_payload(),
                proof=proof,
            )
        except Exception:
            merkle_valid = False

    is_overall_valid = is_digest_valid and (signature_verified if sig_info else True) and evidence_valid
    if merkle_info and merkle_valid is False:
        is_overall_valid = False

    return {
        "is_valid": is_overall_valid,
        "passport_id": passport.passport_id,
        "finding_id": passport.finding_id,
        "case_id": passport.case_id,
        "installation_id": passport.installation_id,
        "finding_type": passport.finding_type,
        "evidence_count": passport.evidence_count,
        "digest_verified": is_digest_valid,
        "passport_digest": passport.passport_digest,
        "is_digitally_signed": bool(sig_info),
        "signature_verified": signature_verified,
        "signing_algorithm": sig_info.get("algorithm") if sig_info else None,
        "signing_key_id": sig_info.get("key_id") if sig_info else None,
        "signature_error": sig_error,
        "merkle_proof_verified": merkle_valid,
    }


def verify_release_manifest_file(
    file_path: str,
    trusted_public_key_pem: str | None = None,
) -> dict[str, Any]:
    """Offline verification of a Production Release Manifest."""
    data = _load_json(file_path)

    release_id = str(data.get("release_id", ""))
    version = str(data.get("version", ""))
    components = dict(data.get("components", data.get("components_manifest", {})))
    validation_runs = list(data.get("validation_runs", []))
    approval_records = list(data.get("approval_records", []))
    readiness_gates = list(data.get("readiness_gates", []))
    created_by = str(data.get("created_by", ""))
    manifest_digest = str(data.get("manifest_digest", ""))

    payload = release_manifest_payload(
        release_id=release_id,
        version=version,
        components=components,
        validation_runs=validation_runs,
        approval_records=approval_records,
        readiness_gates=readiness_gates,
        created_by=created_by,
        created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(timezone.utc),
    )
    expected_digest = compute_release_manifest_digest(payload=payload)
    digest_valid = manifest_digest.lower() == expected_digest.lower()

    # Signature verification
    sig_info = data.get("signature_bundle")
    signature_verified = False
    sig_error: str | None = None
    if sig_info:
        try:
            bundle = SignatureBundle.from_dict(sig_info)
            signature_verified = verify_asymmetric_signature(
                payload=payload,
                bundle=bundle,
                trusted_public_key_pem=trusted_public_key_pem,
            )
            if not signature_verified:
                sig_error = "Digital signature does not match manifest payload"
        except Exception as exc:
            sig_error = f"Signature verification error: {exc}"
    else:
        sig_error = "Manifest is unsigned"

    is_overall_valid = digest_valid and (signature_verified if sig_info else True)

    return {
        "is_valid": is_overall_valid,
        "release_id": release_id,
        "version": version,
        "components_count": len(components),
        "digest_verified": digest_valid,
        "manifest_digest": manifest_digest,
        "expected_digest": expected_digest,
        "is_digitally_signed": bool(sig_info),
        "signature_verified": signature_verified,
        "signing_algorithm": sig_info.get("algorithm") if sig_info else None,
        "signature_error": sig_error,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toroka-verify",
        description="Toroka Enterprise Offline Cryptographic Verifier for Regulators & Auditors",
    )
    parser.add_argument("--json", action="store_true", help="Output verification report in machine-readable JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: passport
    p_pass = subparsers.add_parser("passport", help="Verify an Evidence Passport file")
    p_pass.add_argument("--file", "-f", required=True, help="Path to Evidence Passport JSON file")
    p_pass.add_argument("--key", "-k", help="Path to trusted bank public key PEM file (optional)")

    # Subcommand: release
    p_rel = subparsers.add_parser("release", help="Verify a Production Release Manifest file")
    p_rel.add_argument("--file", "-f", required=True, help="Path to Release Manifest JSON file")
    p_rel.add_argument("--key", "-k", help="Path to trusted bank public key PEM file (optional)")

    # Subcommand: merkle
    p_merk = subparsers.add_parser("merkle", help="Verify a Merkle inclusion proof file")
    p_merk.add_argument("--proof-file", required=True, help="Path to Merkle proof JSON file")
    p_merk.add_argument("--leaf-file", required=True, help="Path to leaf content JSON file")

    for subp in (p_pass, p_rel, p_merk):
        subp.add_argument("--json", action="store_true", help="Output verification report in machine-readable JSON")

    args = parser.parse_args(argv)

    trusted_pem = None
    if getattr(args, "key", None):
        with Path(args.key).open("r", encoding="utf-8") as kf:
            trusted_pem = kf.read()

    if args.command == "passport":
        result = verify_passport_file(args.file, trusted_public_key_pem=trusted_pem)
    elif args.command == "release":
        result = verify_release_manifest_file(args.file, trusted_public_key_pem=trusted_pem)
    elif args.command == "merkle":
        proof_data = _load_json(args.proof_file)
        leaf_data = _load_json(args.leaf_file)
        proof = MerkleInclusionProof.from_dict(proof_data)
        valid = verify_merkle_inclusion_proof(leaf_data, proof)
        result = {
            "is_valid": valid,
            "leaf_index": proof.leaf_index,
            "root_hash": proof.root_hash,
        }
    else:
        result = {"is_valid": False, "error": f"Unknown command: {args.command}"}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status_label = "[VALID]" if result.get("is_valid") else "[INVALID]"
        print(f"\n=======================================================")
        print(f" Toroka Enterprise Offline Verification: {status_label}")
        print(f"=======================================================")
        for k, v in result.items():
            print(f"  {k:22}: {v}")
        print(f"=======================================================\n")

    return 0 if result.get("is_valid") else 1


if __name__ == "__main__":
    sys.exit(main())
