"""Regression tests for the 2026-11 follow-up review (federation environment precedence, pseudonym migration helper)."""
import pytest

from toroka_enterprise.integrations.federated_mule import get_federation_salt
from toroka_enterprise.pseudonym import Pseudonymiser

ENV_VARS = ("TOROKA_ENV", "ENVIRONMENT", "TOROKA_ENT_ENV", "TOROKA_FEDERATED_MULE_SALT")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_one_non_dev_environment_variable_keeps_the_strict_behaviour(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")      # a generic variable some hosts/shells set
    monkeypatch.setenv("TOROKA_ENT_ENV", "production")
    with pytest.raises(RuntimeError):
        get_federation_salt()


def test_unknown_or_unset_environment_is_not_dev(monkeypatch):
    with pytest.raises(RuntimeError):
        get_federation_salt()
    monkeypatch.setenv("TOROKA_ENV", "prod")
    with pytest.raises(RuntimeError):
        get_federation_salt()


def test_all_dev_variables_allow_the_dev_salt(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("TOROKA_ENT_ENV", "test")
    assert get_federation_salt().endswith("_DEV")


def test_explicit_environment_argument_wins_over_variables(monkeypatch):
    monkeypatch.setenv("TOROKA_ENT_ENV", "production")
    assert get_federation_salt(environment="test").endswith("_DEV")
    monkeypatch.setenv("TOROKA_ENT_ENV", "development")
    with pytest.raises(RuntimeError):
        get_federation_salt(environment="staging")


def test_configured_distinct_salt_is_returned(monkeypatch):
    monkeypatch.setenv("TOROKA_ENT_ENV", "production")
    monkeypatch.setenv("TOROKA_FEDERATED_MULE_SALT", "x" * 40)
    assert get_federation_salt() == "x" * 40


SECRET = b"s" * 32


def test_ref_is_case_insensitive():
    p = Pseudonymiser(SECRET)
    assert p.ref("stf", "JKamau") == p.ref("stf", " jkamau ")


def test_legacy_ref_matches_the_pre_casefold_scheme():
    p = Pseudonymiser(SECRET)
    assert p.legacy_ref("stf", "jkamau") == p.ref("stf", "jkamau")        # lower-case values never changed
    assert p.legacy_ref("stf", "JKamau") != p.ref("stf", "JKamau")        # mixed-case values did
    assert p.legacy_ref("stf", "JKamau") != p.legacy_ref("stf", "jkamau")  # which is why a migration map is needed


def test_legacy_ref_has_no_side_effects_and_validates_input():
    p = Pseudonymiser(SECRET)
    assert p.legacy_ref("stf", "  ") is None and p.legacy_ref("stf", None) is None
    p.legacy_ref("stf", "JKamau")
    assert p.vault == {}
    with pytest.raises(ValueError):
        p.legacy_ref("nope", "x")
