"""Regression tests for enterprise audit hardening items 1-8 (API & services layer)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from toroka_enterprise.integrations.federated_mule import get_federation_salt
from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app
from toroka_enterprise_api.persistence.audit import verify_audit_chain
from toroka_enterprise_api.persistence.models import AuditRecord


# ---------------------------------------------------------------------------
# Items 1 & 2: Federation salt + staging/production guardrails
# ---------------------------------------------------------------------------


def test_federation_salt_fails_closed_in_staging_and_unconfigured(monkeypatch):
    monkeypatch.delenv("TOROKA_FEDERATED_MULE_SALT", raising=False)
    monkeypatch.delenv("TOROKA_ENV", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("TOROKA_ENT_ENV", raising=False)

    # Empty / staging / production fail closed when salt unset
    with pytest.raises(RuntimeError, match="explicit TOROKA_FEDERATED_MULE_SALT"):
        get_federation_salt()
    with pytest.raises(RuntimeError, match="explicit TOROKA_FEDERATED_MULE_SALT"):
        get_federation_salt(environment="staging")
    with pytest.raises(RuntimeError, match="explicit TOROKA_FEDERATED_MULE_SALT"):
        get_federation_salt(environment="production")

    # Dev salt sample rejected outside dev/test
    for bad_salt in (
        "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_V1",
        "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_DEV",
    ):
        monkeypatch.setenv("TOROKA_FEDERATED_MULE_SALT", bad_salt)
        with pytest.raises(RuntimeError, match="default or sample consortium salt"):
            get_federation_salt(environment="staging")

    # Explicitly development allows fallback when unset
    monkeypatch.delenv("TOROKA_FEDERATED_MULE_SALT", raising=False)
    assert get_federation_salt(environment="development").endswith("_DEV")


def test_staging_settings_enforces_hardening_guards(monkeypatch):
    monkeypatch.setenv("TOROKA_FEDERATED_MULE_SALT", "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_DEV")
    bad_salt_cfg = EnterpriseSettings(
        environment="staging",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/jwks.json",
    )
    with pytest.raises(RuntimeError, match="default sample federation salt"):
        bad_salt_cfg.validate()

    monkeypatch.delenv("TOROKA_FEDERATED_MULE_SALT", raising=False)
    bad_http_cfg = EnterpriseSettings(
        environment="staging",
        auth_mode="oidc",
        oidc_issuer="http://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/jwks.json",
    )
    with pytest.raises(RuntimeError, match="must use HTTPS in staging"):
        bad_http_cfg.validate()

    bad_ckpt_cfg = EnterpriseSettings(
        environment="staging",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/jwks.json",
        audit_checkpoint_dir="/tmp/ckpts",
        audit_checkpoint_hmac_key="too-short-key",
    )
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        bad_ckpt_cfg.validate()


def test_runtime_blocks_development_auth_in_staging(dev_app, dev_client):
    object.__setattr__(dev_app.state.settings, "environment", "staging")
    resp = dev_client.get(
        "/api/enterprise/v1/me",
        headers={"X-Dev-User": "inv.alice", "X-Dev-Roles": "investigator"},
    )
    assert resp.status_code == 403
    assert "outside local development" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Items 3, 5, 8: Dual-role bypass closed, reveal denials audited, min 20 chars
# ---------------------------------------------------------------------------


def test_dual_role_cannot_bypass_assignment_and_denials_are_audited(
    test_case_service, test_reveal_service, test_vault_repo
):
    alice = EnterprisePrincipal("inv.alice", frozenset({"investigator"}), "test-idp")
    dual_unassigned = EnterprisePrincipal(
        "dual.unassigned", frozenset({"investigator", "authoriser"}), "test-idp"
    )
    pure_auth = EnterprisePrincipal("auth.carol", frozenset({"authoriser"}), "test-idp")
    other_inv = EnterprisePrincipal("inv.other", frozenset({"investigator"}), "test-idp")

    case = test_case_service.create_case(
        alice,
        installation_id="toroka-default-installation",
        label="insider_review",
        focus="STF-DUAL-01",
        snapshot={},
        assign_to_subject="inv.alice",
    )
    test_vault_repo.store("STF-DUAL-01", "EMP-REAL-01")

    # Dual investigator+authoriser not assigned to the case is rejected & audited
    with pytest.raises(PermissionError, match="not assigned"):
        test_reveal_service.request_reveal(
            dual_unassigned,
            case_id=case.id,
            pseudonym="STF-DUAL-01",
            reason="Attempting to inspect case without assignment.",
        )

    # Pure authoriser attempting request_reveal is rejected & audited
    with pytest.raises(PermissionError, match="Only investigators"):
        test_reveal_service.request_reveal(
            pure_auth,
            case_id=case.id,
            pseudonym="STF-DUAL-01",
            reason="Authoriser should not request reveals.",
        )

    # Assigned investigator creates valid reveal request
    req = test_reveal_service.request_reveal(
        alice,
        case_id=case.id,
        pseudonym="STF-DUAL-01",
        reason="Confirm employee identity for formal HR inquiry.",
    )

    # Non-authoriser approve/reject denied & audited
    with pytest.raises(PermissionError, match="Only authorisers"):
        test_reveal_service.approve_reveal(other_inv, request_id=req.id)
    with pytest.raises(PermissionError, match="Only authorisers"):
        test_reveal_service.reject_reveal(other_inv, request_id=req.id, rejection_reason="nope")

    # Self-approval denied & audited
    dual_alice = EnterprisePrincipal(
        "inv.alice", frozenset({"investigator", "authoriser"}), "test-idp"
    )
    with pytest.raises(PermissionError, match="Self-approval blocked"):
        test_reveal_service.approve_reveal(dual_alice, request_id=req.id)

    # Approve properly and test wrong-consumer denial & audit
    test_reveal_service.approve_reveal(pure_auth, request_id=req.id)
    with pytest.raises(PermissionError, match="original requesting investigator"):
        test_reveal_service.consume_reveal(other_inv, request_id=req.id)

    actions = [
        r.action
        for r in test_reveal_service.db.query(AuditRecord)
        .filter(AuditRecord.installation_id == "toroka-default-installation")
        .all()
    ]
    assert "reveal_denied_unassigned" in actions
    assert actions.count("reveal_denied_role") == 3
    assert "reveal_denied_self_approval" in actions
    assert "reveal_denied_wrong_consumer" in actions

    valid, _, _ = verify_audit_chain(test_reveal_service.db, "toroka-default-installation")
    assert valid is True


def test_reveal_api_enforces_20_char_reason(oidc_client, token_factory, test_case_service):
    alice = EnterprisePrincipal("investigator.alice", frozenset({"investigator"}), "test-idp")
    case = test_case_service.create_case(
        alice,
        installation_id="toroka-default-installation",
        label="insider_review",
        focus="STF-MINLEN-01",
        snapshot={},
        assign_to_subject="investigator.alice",
    )
    tok = token_factory(sub="investigator.alice", roles=["BANK_INVESTIGATOR"])
    resp = oidc_client.post(
        f"/api/enterprise/v1/cases/{case.id}/reveal-requests",
        headers={"Authorization": f"Bearer {tok}"},
        json={"pseudonym": "STF-MINLEN-01", "reason": "Too short 15ch"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Items 4 & 7: Installation mismatch in staging/prod, reveals, JWT typ/azp/leeway
# ---------------------------------------------------------------------------


def test_staging_production_rejects_mismatched_inst_claim(
    oidc_app, oidc_client, token_factory
):
    object.__setattr__(oidc_app.state.settings, "environment", "staging")
    bad_tok = token_factory(
        sub="inv.foreign",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "foreign-bank-tenant"},
    )
    for path in ("/api/enterprise/v1/copilot/status", "/api/enterprise/v1/governance/components"):
        resp = oidc_client.get(path, headers={"Authorization": f"Bearer {bad_tok}"})
        assert resp.status_code == 403
        assert "Token installation does not match" in resp.json()["detail"]

    ok_tok = token_factory(
        sub="inv.local",
        roles=["BANK_INVESTIGATOR"],
        extra_claims={"inst": "toroka-default-installation"},
    )
    ok_resp = oidc_client.get(
        "/api/enterprise/v1/copilot/status",
        headers={"Authorization": f"Bearer {ok_tok}"},
    )
    assert ok_resp.status_code == 200


def test_reveal_service_blocks_cross_installation_access(
    test_case_service, test_reveal_service
):
    alice_default = EnterprisePrincipal(
        "inv.alice", frozenset({"investigator"}), "test-idp", installation_id="toroka-default-installation"
    )
    alice_foreign = EnterprisePrincipal(
        "inv.alice", frozenset({"investigator"}), "test-idp", installation_id="bank-beta"
    )
    case = test_case_service.create_case(
        alice_default,
        installation_id="toroka-default-installation",
        label="insider_review",
        focus="STF-INST-01",
        snapshot={},
        assign_to_subject="inv.alice",
    )
    with pytest.raises(PermissionError, match="Installation mismatch"):
        test_reveal_service.request_reveal(
            alice_foreign,
            case_id=case.id,
            pseudonym="STF-INST-01",
            reason="Cross installation reveal attempt should fail.",
        )


def test_jwt_typ_azp_and_leeway_validation(
    oidc_app, oidc_client, token_factory, primary_key
):
    import time
    import jwt as pyjwt

    # 1. Invalid typ rejected
    now = int(time.time())
    bad_typ_tok = pyjwt.encode(
        {
            "sub": "inv.alice",
            "iss": "https://idp.bank.local",
            "aud": "toroka-enterprise",
            "iat": now,
            "exp": now + 300,
            "groups": ["BANK_INVESTIGATOR"],
        },
        primary_key,
        algorithm="RS256",
        headers={"kid": "key-primary", "typ": "refresh+jwt"},
    )
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {bad_typ_tok}"},
        ).status_code
        == 401
    )

    # 2. Valid at+jwt accepted
    at_typ_tok = pyjwt.encode(
        {
            "sub": "inv.alice",
            "iss": "https://idp.bank.local",
            "aud": "toroka-enterprise",
            "iat": now,
            "exp": now + 300,
            "groups": ["BANK_INVESTIGATOR"],
        },
        primary_key,
        algorithm="RS256",
        headers={"kid": "key-primary", "typ": "at+jwt"},
    )
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {at_typ_tok}"},
        ).status_code
        == 200
    )

    # 3. Clock skew leeway allows 15s-expired token; rejects 60s-expired token
    near_exp = token_factory(exp_offset=-15, iat_offset=-120, roles=["BANK_INVESTIGATOR"])
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {near_exp}"},
        ).status_code
        == 200
    )
    far_exp = token_factory(exp_offset=-60, iat_offset=-120, roles=["BANK_INVESTIGATOR"])
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {far_exp}"},
        ).status_code
        == 401
    )

    # 4. Empty azp rejected; configured oidc_authorized_party enforced
    blank_azp = token_factory(roles=["BANK_INVESTIGATOR"], extra_claims={"azp": "  "})
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {blank_azp}"},
        ).status_code
        == 401
    )

    object.__setattr__(oidc_app.state.settings, "oidc_authorized_party", "toroka-workbench")
    wrong_azp = token_factory(roles=["BANK_INVESTIGATOR"], extra_claims={"azp": "other-client"})
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {wrong_azp}"},
        ).status_code
        == 401
    )
    right_azp = token_factory(roles=["BANK_INVESTIGATOR"], extra_claims={"azp": "toroka-workbench"})
    assert (
        oidc_client.get(
            "/api/enterprise/v1/me",
            headers={"Authorization": f"Bearer {right_azp}"},
        ).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# Item 6: Audit checkpoint runtime endpoints
# ---------------------------------------------------------------------------


def test_audit_checkpoint_endpoints_end_to_end(
    tmp_path, db_engine, vault_engine, mock_jwks, test_vault_key, test_vault_cipher, token_factory
):
    ckpt_dir = tmp_path / "checkpoints"
    settings = EnterpriseSettings(
        environment="test",
        auth_mode="oidc",
        oidc_issuer="https://idp.bank.local",
        oidc_audience="toroka-enterprise",
        oidc_jwks_url="https://idp.bank.local/.well-known/jwks.json",
        role_claim="groups",
        algorithms=("RS256",),
        role_map={"BANK_AUDITOR": "auditor", "BANK_INVESTIGATOR": "investigator", "BANK_AUTHORISER": "authoriser"},
        database_url="sqlite:///:memory:",
        vault_database_url="sqlite:///:memory:",
        vault_key=test_vault_key,
        installation_id="toroka-default-installation",
        audit_checkpoint_dir=str(ckpt_dir),
        audit_checkpoint_hmac_key="super-secret-bank-checkpoint-hmac-key-32b",
    )
    app = create_app(settings)
    app.state.jwks_client = mock_jwks
    app.state.engine = db_engine
    app.state.session_factory = sessionmaker(bind=db_engine, class_=Session, autoflush=False, expire_on_commit=False)
    app.state.vault_engine = vault_engine
    app.state.vault_session_factory = sessionmaker(bind=vault_engine, class_=Session, autoflush=False, expire_on_commit=False)
    app.state.vault_cipher = test_vault_cipher

    client = TestClient(app, client=("127.0.0.1", 50000))
    auditor_tok = token_factory(sub="aud.carol", roles=["BANK_AUDITOR"])
    inv_tok = token_factory(sub="inv.alice", roles=["BANK_INVESTIGATOR"])
    auth_tok = token_factory(sub="auth.bob", roles=["BANK_AUTHORISER"])

    # Seed at least one audit record via intake
    from toroka_enterprise_api.persistence.models import RunRecord

    with app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="toroka-default-installation",
                manifest_id="ckpt-man-1",
                manifest={"manifest_id": "ckpt-man-1", "leads": [{"focus": "STF-CKPT-1"}]},
                created_by="system",
            )
        )
        db.commit()

    intake_r = client.post(
        "/api/enterprise/v1/cases/intake",
        headers={"Authorization": f"Bearer {auth_tok}"},
        json={"manifest_id": "ckpt-man-1", "leads": [{"label": "REVIEW", "focus": "STF-CKPT-1"}]},
    )
    assert intake_r.status_code == 201

    # Investigator cannot create or list checkpoints
    assert (
        client.post(
            "/api/enterprise/v1/audit/checkpoints",
            headers={"Authorization": f"Bearer {inv_tok}"},
        ).status_code
        == 403
    )

    # Auditor creates checkpoint
    create_r = client.post(
        "/api/enterprise/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {auditor_tok}"},
    )
    assert create_r.status_code == 201
    envelope = create_r.json()
    assert envelope["key_id"] == "ent-hmac-v1"
    assert envelope["data"]["head_sequence"] >= 1

    # Duplicate checkpoint at same sequence is conflict (409)
    dup_r = client.post(
        "/api/enterprise/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {auditor_tok}"},
    )
    assert dup_r.status_code == 409

    # List stored checkpoints
    list_r = client.get(
        "/api/enterprise/v1/audit/checkpoints",
        headers={"Authorization": f"Bearer {auditor_tok}"},
    )
    assert list_r.status_code == 200
    assert len(list_r.json()) == 1

    # Verify latest checkpoint (empty body) and explicit envelope
    ver_latest = client.post(
        "/api/enterprise/v1/audit/checkpoints/verify",
        headers={"Authorization": f"Bearer {auditor_tok}"},
    )
    assert ver_latest.status_code == 200
    assert ver_latest.json()["valid"] is True

    tampered = dict(envelope, signature="AAAA" + envelope["signature"][4:])
    ver_bad = client.post(
        "/api/enterprise/v1/audit/checkpoints/verify",
        headers={"Authorization": f"Bearer {auditor_tok}"},
        json=tampered,
    )
    assert ver_bad.status_code == 200
    assert ver_bad.json()["valid"] is False
