"""Follow-up review regressions: mandatory audit checkpoints, write-once checkpoint store, denial-audit installation."""
import pathlib

import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.persistence.checkpoints import DirectoryImmutableCheckpointStore

OIDC = dict(auth_mode="oidc", oidc_issuer="https://idp.bank.example", oidc_audience="toroka",
            oidc_jwks_url="https://idp.bank.example/jwks")


@pytest.mark.parametrize("env", ["staging", "production"])
def test_checkpoints_are_mandatory_outside_development(env):
    with pytest.raises(RuntimeError, match="Signed audit checkpoints are required"):
        EnterpriseSettings(environment=env, **OIDC).validate()
    with pytest.raises(RuntimeError, match="Signed audit checkpoints are required"):
        EnterpriseSettings(environment=env, audit_checkpoint_dir="/tmp/c", **OIDC).validate()
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        EnterpriseSettings(environment=env, audit_checkpoint_dir="/tmp/c", audit_checkpoint_hmac_key="short", **OIDC).validate()


def test_staging_with_valid_checkpoint_settings_validates():
    EnterpriseSettings(environment="staging", audit_checkpoint_dir="/tmp/c", audit_checkpoint_hmac_key="k" * 32, **OIDC).validate()


def test_development_does_not_need_checkpoints():
    EnterpriseSettings(environment="development", auth_mode="development").validate()


def test_checkpoint_store_is_write_once_even_if_the_exists_check_races(tmp_path, monkeypatch):
    store = DirectoryImmutableCheckpointStore(tmp_path)
    store.put_if_absent("cp-1.json", b"original")
    real_exists = pathlib.Path.exists
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: False if self.name == "cp-1.json" else real_exists(self))
    with pytest.raises(FileExistsError):
        store.put_if_absent("cp-1.json", b"forged")
    monkeypatch.undo()
    assert store.get("cp-1.json") == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["cp-1.json"]       # no stray temp files


def test_role_denial_is_audited_under_the_cases_installation(test_case_service, test_reveal_service):
    alice = EnterprisePrincipal(subject="investigator.alice", roles=frozenset({"investigator"}), issuer="t")
    mallory = EnterprisePrincipal(subject="auth.mallory", roles=frozenset({"authoriser"}), issuer="t")
    case = test_case_service.create_case(alice, installation_id="bank-b", label="x", focus="STF-1", snapshot={},
                                         manifest_id="m", assign_to_subject="investigator.alice")
    with pytest.raises(PermissionError):
        test_reveal_service.request_reveal(mallory, case_id=case.id, pseudonym="STF-1", reason="a long enough reason text")
    from toroka_enterprise_api.persistence.models import AuditRecord
    rows = test_reveal_service.db.query(AuditRecord).filter(AuditRecord.action == "reveal_denied_role").all()
    assert [r.installation_id for r in rows] == ["bank-b"]
