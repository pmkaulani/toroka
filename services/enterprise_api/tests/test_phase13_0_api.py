"""Toroka Enterprise — Phase 13.0 API Tests.

Verifies:
1. Asymmetric PKI Digital Signatures for Evidence Passports & Release Manifests.
2. In-API and offline cryptographic verification endpoints.
3. Quantitative Model Risk Governance (OCC SR 11-7 / Fed SR 15-18) & PSI evaluations.
4. Operational health degradation upon critical quantitative drift detection.
5. Champion-Challenger Shadow evaluation tracking and non-inferiority promotion gates.
"""
from __future__ import annotations

from datetime import datetime, timezone
import pytest
from sqlalchemy import select

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService
from toroka_enterprise.intelligence.models import (
    IntelligenceEventRecord,
    IntelligenceSignalRecord,
    GovernedComponentRecord,
    ValidationRunRecord,
)


def _utc_now():
    return datetime.now(timezone.utc)


@pytest.fixture
def phase13_case_with_events(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Phase 13.0 Subject Case",
        focus="acc_pki_01",
        snapshot={"customer_ref": "cif_pki_100"},
        principal=investigator,
    )

    ev1 = IntelligenceEventRecord(
        event_id="ev_wire_pki_01",
        installation_id=inst_id,
        source_system="CORE_BANKING",
        source_record_id="tx_wire_901",
        event_type="CROSS_BORDER_WIRE",
        event_time=_utc_now(),
        actor="acc_pki_01",
        subject="acc_offshore_88",
        attributes={"case_id": case.id, "amount": 250000.0, "currency": "EUR"},
        provenance_digest="1" * 64,
    )
    sig1 = IntelligenceSignalRecord(
        signal_id="sig_pki_finding_01",
        installation_id=inst_id,
        case_id=case.id,
        signal_type="SANCTION_EVASION_PATTERN",
        severity="critical",
        title="Sanction Evasion via Multi-Jurisdiction Wires",
        explanation="Layered high-value cross-border wires executed within 3 minutes.",
        event_ids=["ev_wire_pki_01"],
        confidence=0.96,
        created_at=_utc_now(),
    )
    comp = GovernedComponentRecord(
        component_id="detector_sanctions_v2",
        version="2.1.0",
        installation_id=inst_id,
        component_type="detector",
        name="Sanctions Evasion Detector",
        status="approved",
        risk_tier="critical",
        owner_team="Financial Crime Analytics",
        source_digest="a" * 64,
        configuration_digest="b" * 64,
        created_by="maker.alice",
    )
    db_session.add_all([ev1, sig1, comp])
    db_session.commit()

    return {"case_id": case.id, "finding_id": sig1.signal_id, "installation_id": inst_id}


def test_passport_digital_signing_and_verification_api(oidc_client, token_factory, phase13_case_with_events):
    token_authoriser = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    case_id = phase13_case_with_events["case_id"]
    finding_id = phase13_case_with_events["finding_id"]

    # 1. Generate evidence passport
    gen_resp = oidc_client.post(
        "/api/enterprise/v1/governance/passports",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={"finding_id": finding_id, "case_id": case_id},
    )
    assert gen_resp.status_code == 201
    pass_data = gen_resp.json()
    passport_id = pass_data["passport_id"]
    assert pass_data["is_digitally_signed"] is False
    assert pass_data["signature_bundle"] is None

    # 2. Investigator cannot sign (Authoriser required)
    inv_sign_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/passports/{passport_id}/sign",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={"algorithm": "Ed25519"},
    )
    assert inv_sign_resp.status_code == 403

    # 3. Authoriser signs with HSM
    sign_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/passports/{passport_id}/sign",
        headers={"Authorization": f"Bearer {token_authoriser}"},
        json={"algorithm": "Ed25519"},
    )
    assert sign_resp.status_code == 200
    signed_data = sign_resp.json()
    assert signed_data["is_digitally_signed"] is True
    assert signed_data["signature_bundle"] is not None
    assert signed_data["signature_bundle"]["algorithm"] == "Ed25519"

    # 4. In-API verification of digital signature
    verify_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/passports/{passport_id}/verify",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={"trusted_public_key_pem": signed_data["signature_bundle"]["public_key_pem"]},
    )
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data["is_valid"] is True
    assert v_data["digest_verified"] is True
    assert v_data["is_digitally_signed"] is True
    assert v_data["signature_verified"] is True
    assert v_data["signing_algorithm"] == "Ed25519"

    # 5. Signing already-signed passport fails with 409
    dup_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/passports/{passport_id}/sign",
        headers={"Authorization": f"Bearer {token_authoriser}"},
        json={"algorithm": "Ed25519"},
    )
    assert dup_resp.status_code == 409


def test_release_digital_signing_and_verification_api(oidc_client, token_factory):
    token_authoriser = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # 1. Create a staged release
    rel_resp = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers={"Authorization": f"Bearer {token_authoriser}"},
        json={
            "version": "2026.13.0",
            "environment": "validation",
            "components": {"detector_sanctions_v2": "2.1.0"},
            "validation_runs": ["val-test-01"],
            "approval_records": ["app-test-01"],
            "readiness_gates": [],
        },
    )
    assert rel_resp.status_code == 201
    rel_data = rel_resp.json()
    release_id = rel_data["release_id"]
    assert rel_data["is_digitally_signed"] is False

    # 2. Sign release manifest
    sign_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/releases/{release_id}/sign",
        headers={"Authorization": f"Bearer {token_authoriser}"},
        json={"algorithm": "ECDSA_P256"},
    )
    assert sign_resp.status_code == 200
    signed_rel = sign_resp.json()
    assert signed_rel["is_digitally_signed"] is True
    assert signed_rel["signature_bundle"]["algorithm"] == "ECDSA_P256"

    # 3. Verify release manifest
    v_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/releases/{release_id}/verify",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={"trusted_public_key_pem": signed_rel["signature_bundle"]["public_key_pem"]},
    )
    assert v_resp.status_code == 200
    v_res = v_resp.json()
    assert v_res["is_valid"] is True
    assert v_res["digest_verified"] is True
    assert v_res["signature_verified"] is True


def test_quantitative_drift_evaluations_and_health_integration_api(oidc_client, token_factory, phase13_case_with_events):
    token_authoriser = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    # 1. Stable evaluation (PSI < 0.10)
    baseline = [float(i) for i in range(100)]
    current = [float(i) for i in range(100)]
    subgroups = {
        "grp_1": [True] * 80 + [False] * 20,
        "grp_2": [True] * 75 + [False] * 25,
    }

    eval_resp = oidc_client.post(
        "/api/enterprise/v1/governance/model-risk/drift-evaluations",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "component_id": "core_matcher_v1",
            "component_version": "1.0.0",
            "baseline_scores": baseline,
            "current_scores": current,
            "subgroup_predictions": subgroups,
        },
    )
    assert eval_resp.status_code == 201
    data = eval_resp.json()
    assert data["psi_severity"] == "STABLE"
    assert data["is_compliant"] is True
    assert data["requires_mitigation"] is False

    # 2. Critical drift evaluation (PSI >= 0.25)
    shifted_current = [float(i + 40) for i in range(100)]
    crit_resp = oidc_client.post(
        "/api/enterprise/v1/governance/model-risk/drift-evaluations",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "component_id": "core_matcher_v1",
            "component_version": "1.0.0",
            "baseline_scores": baseline,
            "current_scores": shifted_current,
        },
    )
    assert crit_resp.status_code == 201
    crit_data = crit_resp.json()
    assert crit_data["psi_severity"] == "SIGNIFICANT"
    assert crit_data["requires_mitigation"] is True
    assert crit_data["is_compliant"] is False

    # 3. Check health endpoint reflects critical quantitative drift
    health_resp = oidc_client.get(
        "/api/enterprise/v1/governance/health",
        headers={"Authorization": f"Bearer {token_investigator}"},
    )
    assert health_resp.status_code == 200
    h_data = health_resp.json()
    assert h_data["detection_health"].lower() == "critical"


def test_champion_challenger_shadow_governance_api(oidc_client, token_factory):
    token_investigator = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])

    champ_metrics = {
        "sample_size": 1000,
        "true_positives": 180,
        "false_positives": 20,
        "true_negatives": 780,
        "false_negatives": 20,
        "latency_ms_p50": 15.0,
        "latency_ms_p95": 40.0,
    }

    # 1. Non-inferior candidate
    chall_metrics_good = {
        "sample_size": 1000,
        "true_positives": 185,
        "false_positives": 15,
        "true_negatives": 785,
        "false_negatives": 15,
        "latency_ms_p50": 14.0,
        "latency_ms_p95": 38.0,
    }

    eval_good = oidc_client.post(
        "/api/enterprise/v1/governance/model-risk/champion-challenger",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "component_id": "model_graph_risk",
            "champion_version": "1.0.0",
            "challenger_version": "1.1.0",
            "champion_metrics": champ_metrics,
            "challenger_metrics": chall_metrics_good,
        },
    )
    assert eval_good.status_code == 201
    g_data = eval_good.json()
    assert g_data["is_promotable"] is True
    assert g_data["decision"] == "APPROVED_FOR_PROMOTION"

    # 2. Candidate with excessive FDR (+5% > 2% cap)
    chall_metrics_bad = {
        "sample_size": 1000,
        "true_positives": 180,
        "false_positives": 35,
        "true_negatives": 765,
        "false_negatives": 20,
        "latency_ms_p50": 15.0,
        "latency_ms_p95": 40.0,
    }

    eval_bad = oidc_client.post(
        "/api/enterprise/v1/governance/model-risk/champion-challenger",
        headers={"Authorization": f"Bearer {token_investigator}"},
        json={
            "component_id": "model_graph_risk",
            "champion_version": "1.0.0",
            "challenger_version": "1.2.0",
            "champion_metrics": champ_metrics,
            "challenger_metrics": chall_metrics_bad,
        },
    )
    assert eval_bad.status_code == 201
    b_data = eval_bad.json()
    assert b_data["is_promotable"] is False
    assert b_data["decision"] == "REJECTED_EXCESSIVE_FDR"

    # 3. List evaluations
    list_resp = oidc_client.get(
        "/api/enterprise/v1/governance/model-risk/champion-challenger",
        headers={"Authorization": f"Bearer {token_investigator}"},
    )
    assert list_resp.status_code == 200
    runs = list_resp.json()
    assert len(runs) >= 2
