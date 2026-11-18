"""Toroka Phase 13.2 — Security, Provenance & Regulatory Truthfulness Test Suite.

Verifies:
1. Audit-chain health reporting, tuple unpacking, and fail-closed tamper detection.
2. Target environment strict validation ('pilot', 'production' only).
3. Caller-asserted validation run bounding, INCONCLUSIVE results, and trusted execution.
4. Release manifest reference verification against persisted component records.
5. Readiness attestation history and single-active-row enforcement.
6. Signer trust registry, security levels (BANK_MANAGED_HSM vs DEV_SOFTWARE), and granular verification flags.
7. Case-bound forensic dossiers, DRAFT_UNVERIFIED status, and Section 106B truthfulness.
8. Third-party AI provider independent review workflow and maker-checker separation.
9. ISO 20022 clearing rail validation, Decimal amounts, and SHADOW advisory mode.
10. Semantic grounding HEURISTIC_TRIAGE methodology and UNGROUNDED claim detection.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from decimal import Decimal
from datetime import datetime, timezone
import pytest
from sqlalchemy import select, and_

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise_api.persistence.models import AuditRecord, AuditHead, EnterpriseCase
from toroka_enterprise_api.persistence.audit import append_audit
from toroka_enterprise.intelligence.models import (
    GovernedComponentRecord,
    ValidationRunRecord,
    ProductionReleaseRecord,
    ReadinessAttestationRecord,
    ForensicDossierRecord,
    GovernedAIProviderRecord,
    SignerTrustRecord,
)
from toroka_enterprise.governance.deployment import (
    DeploymentEnvironment,
    MANDATORY_GATES,
    release_manifest_payload,
    compute_release_manifest_digest,
)
from toroka_enterprise.governance.pki import (
    AsymmetricAlgorithm,
    KeySecurityLevel,
    LocalHSMKeyProvider,
    SignerKeyPurpose,
)
from toroka_enterprise.governance.evidence_resolver import (
    BankEvidenceAdapter,
    BankEvidenceArtifact,
)
from toroka_enterprise_api.services.production_governance import ProductionGovernanceService


@pytest.fixture
def auth_tokens(token_factory):
    token_alice = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])
    token_bob = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_charlie = token_factory(sub="authoriser.charlie", roles=["BANK_AUTHORISER"])
    token_inv = token_factory(sub="investigator.dave", roles=["BANK_INVESTIGATOR"])
    return {
        "alice": token_alice,
        "bob": token_bob,
        "charlie": token_charlie,
        "inv": token_inv,
    }


# =============================================================================
# 1. Audit-Chain Health & Fail-Closed Tamper Detection (P0-2)
# =============================================================================

def test_audit_chain_health_reporting_and_tamper_detection(oidc_client, auth_tokens, db_session):
    headers = {"Authorization": f"Bearer {auth_tokens['alice']}"}
    inst_id = "toroka-default-installation"

    # Confirm initial health returns healthy
    health_resp = oidc_client.get("/api/enterprise/v1/governance/health", headers=headers)
    assert health_resp.status_code == 200
    assert health_resp.json()["audit_integrity_health"] in ("healthy", "healthy")

    # Add audit record
    append_audit(
        db_session,
        installation_id=inst_id,
        actor_subject="authoriser.alice",
        actor_role="authoriser",
        action="test_audit_event",
        target_type="test",
        target_id="item-001",
        safe_metadata={"key": "val1"},
    )
    db_session.commit()

    # Still healthy
    health_resp = oidc_client.get("/api/enterprise/v1/governance/health", headers=headers)
    assert health_resp.status_code == 200
    assert health_resp.json()["audit_integrity_health"] == "healthy"

    # Tamper with an audit record directly in the database
    rec = db_session.execute(
        select(AuditRecord).where(AuditRecord.installation_id == inst_id).order_by(AuditRecord.sequence.desc())
    ).scalars().first()
    assert rec is not None
    rec.event_hash = "0" * 64  # Tamper with cryptographic hash
    db_session.commit()

    # Health endpoint must now fail closed to CRITICAL (not UNKNOWN, not HEALTHY)
    health_resp = oidc_client.get("/api/enterprise/v1/governance/health", headers=headers)
    assert health_resp.status_code == 200
    data = health_resp.json()
    assert data["audit_integrity_health"] == "critical"


# =============================================================================
# 2. Release Environment Strict Validation (P0-3)
# =============================================================================

def test_release_environment_strict_validation(oidc_client, auth_tokens):
    headers = {"Authorization": f"Bearer {auth_tokens['alice']}"}

    # Create a staged release
    rel_resp = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers=headers,
        json={
            "version": "2026.11.01",
            "environment": "pilot",
            "components": {},
            "validation_runs": [],
            "approval_records": [],
            "readiness_gates": [],
        },
    )
    assert rel_resp.status_code == 201
    release_id = rel_resp.json()["release_id"]

    # Try invalid target environments
    invalid_targets = [
        "PRODUCTION",
        "prod",
        " pilot ",
        "staging",
        "dev",
        "SANDBOX",
        "unknown",
    ]

    for inv in invalid_targets:
        resp = oidc_client.post(
            f"/api/enterprise/v1/governance/releases/{release_id}/promote",
            headers={"Authorization": f"Bearer {auth_tokens['bob']}"},
            json={"target_environment": inv},
        )
        assert resp.status_code == 422, f"Target '{inv}' should be rejected with 422"

    # Confirm release status was NOT mutated to ACTIVE
    get_resp = oidc_client.get("/api/enterprise/v1/governance/releases", headers=headers)
    assert get_resp.status_code == 200
    releases = [r for r in get_resp.json() if r["release_id"] == release_id]
    assert len(releases) == 1
    assert releases[0]["status"] == "staged"


# =============================================================================
# 3. Caller-Asserted Validation Runs & Trusted Executor (P0-4)
# =============================================================================

def test_caller_asserted_validation_run_quarantine_and_evaluator_binding(oidc_client, auth_tokens, db_session):
    headers = {"Authorization": f"Bearer {auth_tokens['alice']}"}

    # Register component
    comp_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers=headers,
        json={
            "component_id": "model_quarantine_test",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "Quarantine Model Test",
            "risk_tier": "high",
            "owner_team": "Risk ML",
            "source_digest": "a" * 64,
            "configuration_digest": "b" * 64,
        },
    )
    assert comp_resp.status_code == 201

    # Caller submits metrics asserting PASS and spoofing evaluator as "admin.root"
    val_resp = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs",
        headers=headers,
        json={
            "component_id": "model_quarantine_test",
            "component_version": "1.0.0",
            "dataset_digest": "c" * 64,
            "configuration_digest": "b" * 64,
            "metrics": [{"name": "f1_score", "value": 0.95, "threshold": 0.90, "direction": "gte", "result": "pass"}],
            "evaluator": "admin.root",  # Spoofed
            "limitations": [],
        },
    )
    assert val_resp.status_code == 201
    val_data = val_resp.json()

    # Evaluator is bound to authenticated principal, not spoofed JSON text
    assert val_data["evaluator"] == "authoriser.alice"
    # Persisted result is INCONCLUSIVE (unverified caller assertion)
    assert val_data["result"] == "inconclusive"
    assert any("UNVERIFIED_CALLER_ASSERTED_VALIDATION_METRICS" in lim for lim in val_data["limitations"])

    # Attempting to approve the component using this unverified run MUST fail
    app_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components/model_quarantine_test/1.0.0/approve",
        headers={"Authorization": f"Bearer {auth_tokens['bob']}"},
        json={
            "validation_run_id": val_data["run_id"],
            "validation_digest": val_data["validation_digest"],
            "rationale": "Attempting approval with unverified caller assertions",
        },
    )
    assert app_resp.status_code == 422
    assert "caller-submitted metrics" in app_resp.json()["detail"].lower()


def test_trusted_validation_execution_and_maker_checker_approval(oidc_client, auth_tokens):
    # 1. Alice creates component
    comp_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers={"Authorization": f"Bearer {auth_tokens['alice']}"},
        json={
            "component_id": "model_trusted_test",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "Trusted Execution Model Test",
            "risk_tier": "high",
            "owner_team": "Risk ML",
            "source_digest": "1" * 64,
            "configuration_digest": "2" * 64,
        },
    )
    assert comp_resp.status_code == 201

    # 2. Alice (maker) cannot run trusted validation for her own component
    self_val_resp = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs/execute-trusted",
        headers={"Authorization": f"Bearer {auth_tokens['alice']}"},
        json={
            "component_id": "model_trusted_test",
            "component_version": "1.0.0",
            "dataset_digest": "3" * 64,
            "configuration_digest": "2" * 64,
            "plan_name": "production-standard-evaluation",
            "metric_specs": [{"name": "accuracy", "threshold": 0.85, "direction": "gte"}],
        },
    )
    assert self_val_resp.status_code == 422
    assert "maker" in self_val_resp.json()["detail"].lower()

    # 3. Independent Bob executes trusted validation
    bob_val_resp = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs/execute-trusted",
        headers={"Authorization": f"Bearer {auth_tokens['bob']}"},
        json={
            "component_id": "model_trusted_test",
            "component_version": "1.0.0",
            "dataset_digest": "3" * 64,
            "configuration_digest": "2" * 64,
            "plan_name": "production-standard-evaluation",
            "metric_specs": [{"name": "accuracy", "threshold": 0.85, "direction": "gte"}],
        },
    )
    assert bob_val_resp.status_code == 201
    val_data = bob_val_resp.json()
    assert val_data["is_trusted_execution"] is True
    assert val_data["result"] == "pass"
    assert val_data["execution_provenance_digest"] is not None

    # 4. Independent Charlie (not Alice, not Bob) approves component
    charlie_app_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components/model_trusted_test/1.0.0/approve",
        headers={"Authorization": f"Bearer {auth_tokens['charlie']}"},
        json={
            "validation_run_id": val_data["run_id"],
            "validation_digest": val_data["validation_digest"],
            "rationale": "Independent trusted execution verified by QA lead Charlie",
        },
    )
    assert charlie_app_resp.status_code == 200
    assert charlie_app_resp.json()["status"] == "approved"


# =============================================================================
# 4. Release Manifest Reference Verification (P0-5)
# =============================================================================

def test_release_manifest_reference_verification_rejects_placeholders(oidc_client, auth_tokens):
    headers_alice = {"Authorization": f"Bearer {auth_tokens['alice']}"}
    headers_bob = {"Authorization": f"Bearer {auth_tokens['bob']}"}

    # Register & approve component cleanly
    oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers=headers_alice,
        json={
            "component_id": "model_manifest_test",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "Manifest Test",
            "risk_tier": "moderate",
            "owner_team": "Risk",
            "source_digest": "4" * 64,
            "configuration_digest": "5" * 64,
        },
    )
    val = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs/execute-trusted",
        headers=headers_bob,
        json={
            "component_id": "model_manifest_test",
            "component_version": "1.0.0",
            "dataset_digest": "6" * 64,
            "configuration_digest": "5" * 64,
            "metric_specs": [{"name": "f1_score", "threshold": 0.80, "direction": "gte"}],
        },
    ).json()

    charlie_headers = {"Authorization": f"Bearer {auth_tokens['charlie']}"}
    app = oidc_client.post(
        "/api/enterprise/v1/governance/components/model_manifest_test/1.0.0/approve",
        headers=charlie_headers,
        json={
            "validation_run_id": val["run_id"],
            "validation_digest": val["validation_digest"],
            "rationale": "Approved for manifest test",
        },
    ).json()

    # Create release with placeholder / mismatched validation_runs
    rel_resp = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers=headers_alice,
        json={
            "version": "2026.11.02",
            "environment": "pilot",
            "components": {"model_manifest_test": "1.0.0"},
            "validation_runs": ["val-placeholder-string"],
            "approval_records": [app["approval_record_id"]],
            "readiness_gates": [],
        },
    )
    assert rel_resp.status_code == 201
    release_id = rel_resp.json()["release_id"]

    # Promotion attempt must reject due to mismatched validation runs
    promote_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/releases/{release_id}/promote",
        headers=headers_bob,
        json={"target_environment": "pilot"},
    )
    assert promote_resp.status_code == 422
    assert "validation_runs" in promote_resp.json()["detail"]


# =============================================================================
# 5. Readiness Attestation History & Unique Active Row (P0-7)
# =============================================================================

def test_readiness_attestation_history_preservation(oidc_client, auth_tokens, db_session):
    headers = {"Authorization": f"Bearer {auth_tokens['bob']}"}
    inst_id = "toroka-default-installation"
    version = "2026.11.05"
    gate = "GATE_MODEL_VALIDATION"

    # Attestation 1: FAIL
    att1 = oidc_client.post(
        "/api/enterprise/v1/governance/readiness/attestations",
        headers=headers,
        json={
            "release_version": version,
            "gate_name": gate,
            "status": "FAIL",
            "evidence_reference": "ref-audit-run-001",
            "evidence_digest": "a" * 64,
            "rationale": "Model underperformed on stress test slice",
        },
    )
    assert att1.status_code == 201

    # Attestation 2: PASS (appended, not overwritten)
    att2 = oidc_client.post(
        "/api/enterprise/v1/governance/readiness/attestations",
        headers=headers,
        json={
            "release_version": version,
            "gate_name": gate,
            "status": "PASS",
            "evidence_reference": "ref-audit-run-002",
            "evidence_digest": "b" * 64,
            "rationale": "Retrained candidate satisfied all stress slices",
        },
    )
    assert att2.status_code == 201

    # Verify both records exist in DB history
    records = db_session.execute(
        select(ReadinessAttestationRecord).where(
            and_(
                ReadinessAttestationRecord.installation_id == inst_id,
                ReadinessAttestationRecord.release_version == version,
                ReadinessAttestationRecord.gate_name == gate,
            )
        ).order_by(ReadinessAttestationRecord.created_at.asc())
    ).scalars().all()

    assert len(records) == 2
    assert records[0].status == "FAIL"
    assert records[0].is_active is False  # Prior row deactivated
    assert records[1].status == "PASS"
    assert records[1].is_active is True   # Current active row


# =============================================================================
# 6. Signer Trust Registry & Production Release Key Hardening (P1-8)
# =============================================================================

def test_signer_trust_registry_and_dev_key_rejection_for_production(oidc_client, auth_tokens, db_session):
    headers_authoriser = {"Authorization": f"Bearer {auth_tokens['bob']}"}

    # Generate test keys
    dev_signer = LocalHSMKeyProvider(key_id="key-dev-software-01", algorithm=AsymmetricAlgorithm.ED25519)
    bank_hsm_signer = LocalHSMKeyProvider(key_id="key-bank-hsm-01", algorithm=AsymmetricAlgorithm.ED25519)

    # Register dev software key
    reg_dev = oidc_client.post(
        "/api/enterprise/v1/governance/trust-registry/signers",
        headers=headers_authoriser,
        json={
            "key_id": "key-dev-software-01",
            "public_key_pem": dev_signer.public_key_pem,
            "algorithm": "Ed25519",
            "purpose": "RELEASE_PROMOTION",
            "security_level": "DEV_SOFTWARE",
        },
    )
    assert reg_dev.status_code == 201

    # Register bank managed HSM key
    reg_hsm = oidc_client.post(
        "/api/enterprise/v1/governance/trust-registry/signers",
        headers=headers_authoriser,
        json={
            "key_id": "key-bank-hsm-01",
            "public_key_pem": bank_hsm_signer.public_key_pem,
            "algorithm": "Ed25519",
            "purpose": "RELEASE_PROMOTION",
            "security_level": "BANK_MANAGED_HSM",
        },
    )
    assert reg_hsm.status_code == 201

    # Set up a fully approved component and staged release
    comp = oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers={"Authorization": f"Bearer {auth_tokens['alice']}"},
        json={
            "component_id": "pki_test_comp",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "PKI Test",
            "risk_tier": "low",
            "owner_team": "Risk",
            "source_digest": "7" * 64,
            "configuration_digest": "8" * 64,
        },
    ).json()

    val = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs/execute-trusted",
        headers=headers_authoriser,
        json={
            "component_id": "pki_test_comp",
            "component_version": "1.0.0",
            "dataset_digest": "9" * 64,
            "configuration_digest": "8" * 64,
            "metric_specs": [{"name": "acc", "threshold": 0.5, "direction": "gte"}],
        },
    ).json()

    app = oidc_client.post(
        "/api/enterprise/v1/governance/components/pki_test_comp/1.0.0/approve",
        headers={"Authorization": f"Bearer {auth_tokens['charlie']}"},
        json={
            "validation_run_id": val["run_id"],
            "validation_digest": val["validation_digest"],
            "rationale": "PKI approval",
        },
    ).json()

    rel = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers={"Authorization": f"Bearer {auth_tokens['alice']}"},
        json={
            "version": "2026.11.10",
            "environment": "pilot",
            "components": {"pki_test_comp": "1.0.0"},
            "validation_runs": [val["run_id"]],
            "approval_records": [app["approval_record_id"]],
            "readiness_gates": [],
        },
    ).json()
    rel_id = rel["release_id"]

    # Sign with dev software key
    sig_dev = dev_signer.sign(rel["manifest_digest"].encode("utf-8"), purpose=SignerKeyPurpose.RELEASE_PROMOTION)

    # Attempting to promote to production with DEV_SOFTWARE key must be REJECTED
    dev_promote_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/releases/{rel_id}/promote",
        headers=headers_authoriser,
        json={
            "target_environment": "production",
            "signature_bundle": sig_dev.to_dict(),
        },
    )
    assert dev_promote_resp.status_code == 422
    assert "DEV_SOFTWARE key is not permitted" in dev_promote_resp.json()["detail"]


# =============================================================================
# 7. Case-Bound Forensic Dossiers & Uncertified Status (P1-9)
# =============================================================================

def test_forensic_dossier_case_isolation_and_truthful_draft_status(oidc_client, auth_tokens, db_session):
    headers_inv = {"Authorization": f"Bearer {auth_tokens['inv']}"}
    inst_id = "toroka-default-installation"

    # 1. Non-existent case -> 404
    missing_case_resp = oidc_client.post(
        "/api/enterprise/v1/governance/forensic-dossiers",
        headers=headers_inv,
        json={
            "case_id": "non-existent-case-id-9999",
            "title": "Missing Case Dossier",
            "incident_type": "AUTHORIZED_PUSH_PAYMENT",
            "fraud_loss_amount": 750000.0,
            "currency": "KES",
            "case_summary": "Test summary",
            "attack_path_summary": {},
            "identified_mule_nodes": [],
            "evidence_records": [],
        },
    )
    assert missing_case_resp.status_code == 404
    assert "does not exist in this installation" in missing_case_resp.json()["detail"]

    # 2. Create legitimate case in database
    case_svc = CaseService(db_session)
    investigator = EnterprisePrincipal(
        subject="investigator.dave",
        roles=frozenset(["investigator"]),
        issuer="test-idp",
        installation_id=inst_id,
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Syndicate Alpha Investigation",
        focus="acc_syndicate_01",
        snapshot={"customer_ref": "cif_court_100"},
        principal=investigator,
    )

    # 3. Create dossier for existing case
    create_resp = oidc_client.post(
        "/api/enterprise/v1/governance/forensic-dossiers",
        headers=headers_inv,
        json={
            "case_id": case.id,
            "title": "Admissible Syndicate Dossier",
            "incident_type": "ACCOUNT_TAKEOVER",
            "fraud_loss_amount": 1250000.50,
            "currency": "KES",
            "case_summary": "Account takeover via cloned SIM and SIM swap",
            "attack_path_summary": {"steps": ["phishing", "sim_swap", "rapid_clearing"]},
            "identified_mule_nodes": [{"account_id": "acc_mule_01"}, {"account_id": "acc_mule_02"}],
            "evidence_records": [
                {"evidence_id": "ev_01", "description": "Caller claims account compromised"}  # Analyst supplied
            ],
            "certifier_name": "Dave Investigator",
        },
    )
    assert create_resp.status_code == 201
    dossier = create_resp.json()

    # Initial status must be DRAFT_UNVERIFIED
    assert dossier["status"] == "DRAFT_UNVERIFIED"
    # No Section 106B certificate automatically created from caller text
    assert dossier["section_106b_certificate"] is None
    # Verified flag is False prior to cryptographic signing
    assert dossier["is_digitally_signed"] is False
    assert dossier["is_verified"] is False

    # Check HTML output contains draft warning
    html_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/forensic-dossiers/{dossier['dossier_id']}/export-html",
        headers=headers_inv,
    )
    assert html_resp.status_code == 200
    assert "DRAFT UNVERIFIED FORENSIC DOSSIER" in html_resp.text


# =============================================================================
# 8. Third-Party AI Provider Registration & Independent Review (P1-10)
# =============================================================================

def test_ai_provider_independent_review_and_maker_checker(oidc_client, auth_tokens):
    headers_alice = {"Authorization": f"Bearer {auth_tokens['alice']}"}
    headers_bob = {"Authorization": f"Bearer {auth_tokens['bob']}"}

    # Register provider
    reg_resp = oidc_client.post(
        "/api/enterprise/v1/governance/ai-providers",
        headers=headers_alice,
        json={
            "provider_name": "Anthropic Claude Private Enterprise",
            "model_identifier": "claude-3-7-sonnet-bank",
            "model_version": "2026.02",
            "hosting_location": "AWS eu-central-1 (Frankfurt)",
            "data_retention_policy": "Zero data retention under BAA",
            "training_on_customer_data_permitted": False,
            "risk_tier": "HIGH",
        },
    )
    assert reg_resp.status_code == 201
    prov = reg_resp.json()
    provider_id = prov["provider_id"]

    # Must start as unapproved and pending independent review
    assert prov["is_approved"] is False
    assert prov["review_status"] == "PENDING_INDEPENDENT_REVIEW"

    # Maker-checker separation: Alice (registrant) cannot approve her own provider
    self_app_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/ai-providers/{provider_id}/approve",
        headers=headers_alice,
        json={"review_notes": "Attempting self-approval"},
    )
    assert self_app_resp.status_code == 422
    assert "maker-checker" in self_app_resp.json()["detail"].lower()

    # Independent Bob approves the provider
    bob_app_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/ai-providers/{provider_id}/approve",
        headers=headers_bob,
        json={"review_notes": "Reviewed and verified BAA agreement and cloud boundary"},
    )
    assert bob_app_resp.status_code == 200
    approved_prov = bob_app_resp.json()
    assert approved_prov["is_approved"] is True
    assert approved_prov["review_status"] == "APPROVED"
    assert approved_prov["approved_by"] == "authoriser.bob"


# =============================================================================
# 9. Safe and Honest ISO 20022 Clearing (P1-11)
# =============================================================================

def test_iso20022_strict_rail_rejection_and_shadow_advisory(oidc_client, auth_tokens):
    headers_inv = {"Authorization": f"Bearer {auth_tokens['inv']}"}

    # Unknown clearing rail must be rejected with 422
    unknown_rail_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers_inv,
        json={
            "amount": 250000.0,
            "currency": "KES",
            "clearing_rail": "CRYPTO_USDT",  # Unsupported
            "end_to_end_id": "E2E-TEST-001",
            "debtor_name": "Debtor One",
            "debtor_account": "010000001",
            "creditor_name": "Creditor One",
            "creditor_account": "020000002",
        },
    )
    assert unknown_rail_resp.status_code == 422
    assert "clearing_rail" in str(unknown_rail_resp.json()["detail"]).lower()

    # Valid evaluation returns SHADOW integration mode and advisory action
    eval_resp = oidc_client.post(
        "/api/enterprise/v1/governance/integrations/iso20022/evaluate-inflight",
        headers=headers_inv,
        json={
            "amount": 5000000.0,  # High amount triggering rule
            "currency": "KES",
            "clearing_rail": "KEPSS_RTGS",
            "end_to_end_id": "E2E-TEST-002",
            "debtor_name": "Debtor Corp",
            "debtor_account": "010000003",
            "creditor_name": "Creditor Corp",
            "creditor_account": "020000004",
        },
    )
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["integration_mode"] == "SHADOW"
    assert "RECOMMEND_" in eval_data["recommended_action"] or "NO_RULE_TRIGGERED" in eval_data["recommended_action"]


# =============================================================================
# 10. Semantic Grounding HEURISTIC_TRIAGE Methodology (P1-12)
# =============================================================================

def test_semantic_grounding_heuristic_triage_and_ungrounded_detection(oidc_client, auth_tokens):
    headers_inv = {"Authorization": f"Bearer {auth_tokens['inv']}"}

    # Claim with zero keyword overlap to evidence context
    verify_resp = oidc_client.post(
        "/api/enterprise/v1/governance/copilot/semantic-verify",
        headers=headers_inv,
        json={
            "claims": [
                {
                    "claim_id": "claim_01",
                    "statement": "The victim transferred five million shillings to a foreign offshore entity.",
                    "kind": "fact",
                    "evidence_ids": ["ev_101"],
                    "quotes": [{"evidence_id": "ev_101", "quoted_text": "Customer reported phone stolen at mall."}],
                }
            ],
            "evidence_context": [
                {
                    "evidence_id": "ev_101",
                    "source_system": "CORE_BANKING",
                    "excerpt": "Customer reported phone stolen at Nairobi shopping mall.",
                }
            ],
        },
    )
    assert verify_resp.status_code == 200
    res = verify_resp.json()
    assert res["methodology"] == "HEURISTIC_TRIAGE"
    assert res["verification_scope"] == "CALLER_SUPPLIED_EXCERPTS_ONLY_NOT_SOURCE_AUTHENTICATION"
    # Claim must be flagged as ungrounded
    assert res["ungrounded_claims"] == 1
    assert res["is_valid"] is False
