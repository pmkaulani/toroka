from __future__ import annotations

import pytest
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.services.cases import CaseService


@pytest.fixture
def governance_test_case(db_session):
    inst_id = "toroka-default-installation"
    case_svc = CaseService(db_session)
    investigator = EnterprisePrincipal(
        subject="inv.lead",
        roles=frozenset({"investigator"}),
        issuer="test-idp",
    )
    case = case_svc.create_case(
        installation_id=inst_id,
        label="Governance Subject Case",
        focus="acc_subject_01",
        snapshot={
            "customer_ref": "cif_100",
            "events": [
                {"event_id": "e1", "source_system": "CORE_BANKING", "event_type": "TRANSFER"},
                {"event_id": "e2", "source_system": "IAM", "event_type": "LOGIN"},
            ],
            "findings": ["f_rule_rapid_flow"],
        },
        principal=investigator,
    )
    db_session.commit()
    return {"case_id": case.id, "installation_id": inst_id}


def test_component_registry_and_maker_checker_approval(oidc_client, token_factory):
    token_author_a = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])
    token_author_b = token_factory(sub="authoriser.bob", roles=["BANK_AUTHORISER"])
    token_validator = token_factory(sub="validator.charlie", roles=["BANK_AUTHORISER"])
    token_steward = token_factory(sub="steward.charlie", roles=["BANK_DATA_STEWARD"])

    # 1. Non-privileged data steward cannot register component
    steward_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers={"Authorization": f"Bearer {token_steward}"},
        json={
            "component_id": "det_rapid_flow",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "Rapid Multi-Hop Detector",
            "risk_tier": "high",
            "owner_team": "Financial Crime Analytics",
            "source_digest": "a" * 64,
            "configuration_digest": "b" * 64,
        },
    )
    assert steward_resp.status_code == 403

    # 2. Authoriser Alice registers component
    reg_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers={"Authorization": f"Bearer {token_author_a}"},
        json={
            "component_id": "det_rapid_flow",
            "version": "1.0.0",
            "component_type": "detector",
            "name": "Rapid Multi-Hop Detector",
            "risk_tier": "high",
            "owner_team": "Financial Crime Analytics",
            "source_digest": "a" * 64,
            "configuration_digest": "b" * 64,
            "parameters": {"threshold_secs": 180},
        },
    )
    assert reg_resp.status_code == 201
    comp = reg_resp.json()
    assert comp["component_id"] == "det_rapid_flow"
    assert comp["status"] == "draft"
    assert comp["created_by"] == "authoriser.alice"

    # Move component to validation via validation run
    val_resp = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs",
        headers={"Authorization": f"Bearer {token_validator}"},
        json={
            "component_id": "det_rapid_flow",
            "component_version": "1.0.0",
            "dataset_digest": "d" * 64,
            "configuration_digest": "b" * 64,
            "metrics": [
                {"name": "precision", "value": 0.95, "threshold": 0.85, "direction": "gte", "result": "pass"},
            ],
            "evaluator": "independent_model_validation_team",
        },
    )
    assert val_resp.status_code == 201
    val_data = val_resp.json()

    # 3. Maker-checker violation: Alice cannot approve her own high-risk component
    self_approve_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components/det_rapid_flow/1.0.0/approve",
        headers={"Authorization": f"Bearer {token_author_a}"},
        json={
            "validation_run_id": val_data["run_id"],
            "validation_digest": val_data["validation_digest"],
            "rationale": "Self approval should fail",
        },
    )
    assert self_approve_resp.status_code == 422
    assert "cannot approve" in self_approve_resp.json()["detail"].lower()

    # 4. Independent Authoriser Bob approves
    bob_approve_resp = oidc_client.post(
        "/api/enterprise/v1/governance/components/det_rapid_flow/1.0.0/approve",
        headers={"Authorization": f"Bearer {token_author_b}"},
        json={
            "validation_run_id": val_data["run_id"],
            "validation_digest": val_data["validation_digest"],
            "rationale": "Independent validation verified across synthetic test datasets",
        },
    )
    assert bob_approve_resp.status_code == 422
    assert "passing validation run" in bob_approve_resp.json()["detail"].lower()


def test_validation_run_recording_and_listing(oidc_client, token_factory):
    token = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])

    # 1. Record validation run
    val_resp = oidc_client.post(
        "/api/enterprise/v1/governance/validation-runs",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "component_id": "det_rapid_flow",
            "component_version": "1.0.0",
            "dataset_digest": "d" * 64,
            "configuration_digest": "e" * 64,
            "metrics": [
                {"name": "precision", "value": 0.94, "threshold": 0.85, "direction": "gte", "result": "pass"},
                {"name": "recall", "value": 0.91, "threshold": 0.80, "direction": "gte", "result": "pass"},
                {"name": "latency_ms", "value": 45.0, "threshold": 100.0, "direction": "lte", "result": "pass"},
            ],
            "evaluator": "independent_model_validation_team",
            "limitations": ["Evaluated only on core payment transactions"],
        },
    )
    assert val_resp.status_code == 201
    val_data = val_resp.json()
    assert val_data["result"] == "inconclusive"
    assert all(metric["result"] == "inconclusive" for metric in val_data["metrics"])
    assert any("UNVERIFIED_CALLER_SUBMITTED_METRICS" in item for item in val_data["limitations"])

    # 2. List validation runs
    list_resp = oidc_client.get(
        "/api/enterprise/v1/governance/validation-runs?component_id=det_rapid_flow",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_resp.status_code == 200
    runs = list_resp.json()
    assert len(runs) >= 1
    assert runs[0]["component_id"] == "det_rapid_flow"


def test_production_release_and_rollback(oidc_client, token_factory):
    token = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])

    # 1. Create a staged release
    rel_resp = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "version": "2026.11.0",
            "environment": "validation",
            "components": {"det_rapid_flow": "1.0.0"},
            "validation_runs": ["val_123"],
            "approval_records": ["app_456"],
            "readiness_gates": [{"gate_name": "SECURITY", "status": "pass"}],
        },
    )
    assert rel_resp.status_code == 201
    rel = rel_resp.json()
    release_id_1 = rel["release_id"]
    assert rel["status"] == "staged"

    # 2. Create another release to test rollback
    rel_resp_2 = oidc_client.post(
        "/api/enterprise/v1/governance/releases",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "version": "2026.11.1",
            "environment": "validation",
            "components": {"det_rapid_flow": "1.0.1"},
            "validation_runs": ["val_124"],
            "approval_records": ["app_457"],
            "readiness_gates": [{"gate_name": "SECURITY", "status": "pass"}],
        },
    )
    assert rel_resp_2.status_code == 201
    release_id_2 = rel_resp_2.json()["release_id"]

    # 3. Rollback release 2 to release 1
    rollback_resp = oidc_client.post(
        f"/api/enterprise/v1/governance/releases/{release_id_2}/rollback",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_release_id": release_id_1,
            "reason": "Observed anomaly in detector threshold v1.0.1",
        },
    )
    assert rollback_resp.status_code == 200
    rolled = rollback_resp.json()
    assert rolled["status"] == "rolled_back"
    assert rolled["rollback_target_id"] == release_id_1


def test_kill_switch_granular_suspension(oidc_client, token_factory):
    token = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])

    # Register component first
    oidc_client.post(
        "/api/enterprise/v1/governance/components",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "component_id": "rule_suspicious_device",
            "version": "1.0.0",
            "component_type": "rule",
            "name": "Suspicious Device Rule",
            "risk_tier": "moderate",
            "owner_team": "Device Intelligence",
            "source_digest": "x" * 64,
            "configuration_digest": "y" * 64,
        },
    )

    # 1. Suspend component
    susp_resp = oidc_client.post(
        "/api/enterprise/v1/governance/kill-switch/suspend",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "component_id": "rule_suspicious_device",
            "version": "1.0.0",
            "reason": "High false positive rate detected in production mobile banking traffic",
        },
    )
    assert susp_resp.status_code == 200
    susp = susp_resp.json()
    assert susp["is_active"] is True
    assert susp["component_id"] == "rule_suspicious_device"

    # Verify component status in registry is suspended
    comp_resp = oidc_client.get(
        "/api/enterprise/v1/governance/components/rule_suspicious_device/1.0.0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert comp_resp.status_code == 200
    assert comp_resp.json()["status"] == "suspended"

    # 2. Resume component
    resume_resp = oidc_client.post(
        "/api/enterprise/v1/governance/kill-switch/resume",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "component_id": "rule_suspicious_device",
            "version": "1.0.0",
            "reason": "Configuration updated and downstream device telemetry stabilized",
        },
    )
    assert resume_resp.status_code == 200
    resumed = resume_resp.json()
    assert resumed["is_active"] is False

    # Verify component status is active
    comp_resp_after = oidc_client.get(
        "/api/enterprise/v1/governance/components/rule_suspicious_device/1.0.0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert comp_resp_after.json()["status"] == "active"


def test_incident_management(oidc_client, token_factory, governance_test_case):
    token = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])
    case_id = governance_test_case["case_id"]

    # 1. Create incident
    inc_resp = oidc_client.post(
        "/api/enterprise/v1/governance/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": "Core Payment Gateway Payload Corruption",
            "category": "data_pipeline",
            "severity": "high",
            "affected_components": ["det_rapid_flow"],
            "affected_case_ids": [case_id],
            "owner": "data_engineering_ops",
        },
    )
    assert inc_resp.status_code == 201
    inc = inc_resp.json()
    incident_id = inc["incident_id"]
    assert inc["status"] == "triaged"
    assert case_id in inc["affected_case_ids"]

    # 2. Update status to contained
    patch_resp = oidc_client.patch(
        f"/api/enterprise/v1/governance/incidents/{incident_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "status": "contained",
            "remediation_notes": "Ingress queue paused and payload schema validation applied",
        },
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "contained"
    assert patch_resp.json()["contained_at"] is not None


def test_drift_and_system_health(oidc_client, token_factory):
    token = token_factory(sub="admin.dan", roles=["BANK_SYSADMIN"])

    # 1. Record drift
    drift_resp = oidc_client.post(
        "/api/enterprise/v1/governance/drift",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "drift_type": "model_output",
            "component_id": "det_rapid_flow",
            "metric_name": "psi_score",
            "baseline_value": 0.05,
            "observed_value": 0.28,
            "threshold": 0.20,
            "recommended_response": "Retrain model with recent transaction distributions",
        },
    )
    assert drift_resp.status_code == 201
    drift = drift_resp.json()
    assert drift["severity"] in ("high", "moderate", "critical")

    # 2. Check system health
    health_resp = oidc_client.get(
        "/api/enterprise/v1/governance/health",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert health_resp.status_code == 200
    health = health_resp.json()
    assert health["active_drift_count"] >= 1
    assert "governed bank controls" in health["summary_message"]


def test_evidence_passport_generation_and_verification(oidc_client, token_factory, governance_test_case):
    token = token_factory(sub="inv.lead", roles=["BANK_INVESTIGATOR"])
    case_id = governance_test_case["case_id"]

    # Generate passport
    pass_resp = oidc_client.post(
        "/api/enterprise/v1/governance/passports",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "finding_id": "find_rapid_pass_through_01",
            "case_id": case_id,
        },
    )
    assert pass_resp.status_code == 201
    passport = pass_resp.json()
    assert passport["is_verified"] is True
    assert passport["evidence_count"] == 2
    assert "CORE_BANKING" in passport["source_systems"]
    assert len(passport["passport_digest"]) == 64

    # Fetch passport by ID
    get_resp = oidc_client.get(
        f"/api/enterprise/v1/governance/passports/{passport['passport_id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["passport_id"] == passport["passport_id"]


def test_ai_provider_governance_policy(oidc_client, token_factory):
    token = token_factory(sub="authoriser.alice", roles=["BANK_AUTHORISER"])

    # 1. Compliant provider (training_on_customer_data_permitted = False)
    compliant_resp = oidc_client.post(
        "/api/enterprise/v1/governance/ai-providers",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider_name": "Internal Banking LLM Host",
            "model_identifier": "bank-copilot-model",
            "model_version": "v2.1",
            "hosting_location": "on_premise_bank_datacenter",
            "data_retention_policy": "zero_retention_ephemeral",
            "training_on_customer_data_permitted": False,
            "risk_tier": "high",
        },
    )
    assert compliant_resp.status_code == 201
    assert compliant_resp.json()["is_approved"] is False
    assert compliant_resp.json()["evaluation_summary"]["review_status"] == "PENDING_INDEPENDENT_BANK_REVIEW"

    # 2. Non-compliant provider (training_on_customer_data_permitted = True) -> Must be rejected
    rejected_resp = oidc_client.post(
        "/api/enterprise/v1/governance/ai-providers",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "provider_name": "Public Cloud Consumer AI",
            "model_identifier": "public-model",
            "model_version": "v1.0",
            "hosting_location": "public_cloud_multi_tenant",
            "data_retention_policy": "indefinite_logs",
            "training_on_customer_data_permitted": True,
            "risk_tier": "critical",
        },
    )
    assert rejected_resp.status_code == 422
    assert "training on customer data" in rejected_resp.json()["detail"].lower()


def test_production_readiness_and_validation_package(oidc_client, token_factory):
    token = token_factory(sub="auditor.eve", roles=["BANK_AUDITOR"])

    # 1. Evaluate 13 readiness gates
    gates = [
        {"gate_name": "SECURITY", "status": "pass", "verified_by": "sec_team", "rationale": "Static and dynamic analysis pass"},
        {"gate_name": "DATA_CONTRACT", "status": "pass", "verified_by": "data_gov", "rationale": "Schema contract verified"},
        {"gate_name": "MIGRATIONS", "status": "pass", "verified_by": "dba", "rationale": "011 migration applied"},
        {"gate_name": "AUDIT", "status": "pass", "verified_by": "audit", "rationale": "Hash chain verified"},
        {"gate_name": "DETECTOR_VALIDATION", "status": "pass", "verified_by": "mrm", "rationale": "Validation runs complete"},
        {"gate_name": "AI_EVALUATION", "status": "pass", "verified_by": "ai_gov", "rationale": "Copilot benchmark pass"},
        {"gate_name": "DR_TEST", "status": "pass", "verified_by": "ops", "rationale": "RTO < 1h verified"},
        {"gate_name": "BACKUP_RESTORE", "status": "pass", "verified_by": "ops", "rationale": "Restore tested"},
        {"gate_name": "MONITORING", "status": "pass", "verified_by": "sre", "rationale": "Telemetry active"},
        {"gate_name": "ACCESS_CONTROL", "status": "pass", "verified_by": "iam", "rationale": "RBAC verified"},
        {"gate_name": "INCIDENT_RESPONSE", "status": "pass", "verified_by": "sec_ops", "rationale": "Runbooks verified"},
        {"gate_name": "DOCUMENTATION", "status": "pass", "verified_by": "tech_writers", "rationale": "Release notes ready"},
        {"gate_name": "APPROVAL", "status": "pass", "verified_by": "risk_committee", "rationale": "Sign-off recorded"},
    ]

    readiness_resp = oidc_client.post(
        "/api/enterprise/v1/governance/readiness/evaluate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "release_version": "2026.11.0",
            "gates": gates,
        },
    )
    assert readiness_resp.status_code == 200
    assessment = readiness_resp.json()
    assert assessment["is_production_ready"] is True
    assert assessment["overall_status"] == "PASS"

    # 2. Generate Bank Validation Package
    pkg_resp = oidc_client.get(
        "/api/enterprise/v1/governance/readiness/validation-package/2026.11.0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert pkg_resp.status_code == 200
    pkg = pkg_resp.json()
    assert pkg["release_version"] == "2026.11.0"
    assert "executive_summary" in pkg
    assert "model_inventory" in pkg["document_sections"]
    assert pkg["document_sections"]["controls_and_governance"]["maker_checker_enforced"] is True
