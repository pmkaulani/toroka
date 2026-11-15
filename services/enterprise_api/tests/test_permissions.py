"""Tests for role permissions, casework adapters, and dual-approval enforcement."""
from __future__ import annotations

import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal
from toroka_enterprise_api.permissions import (
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
    assert_dual_approval,
    to_domain_principal,
)


def test_to_domain_principal_success():
    principal = EnterprisePrincipal(
        subject="investigator.alice",
        roles=frozenset({ROLE_INVESTIGATOR, ROLE_AUTHORISER}),
        issuer="test-idp",
    )
    domain_p = to_domain_principal(principal, ROLE_INVESTIGATOR)
    assert domain_p.user_id == "investigator.alice"
    assert domain_p.role == "investigator"


def test_to_domain_principal_rejects_unheld_role():
    principal = EnterprisePrincipal(
        subject="investigator.alice",
        roles=frozenset({ROLE_INVESTIGATOR}),
        issuer="test-idp",
    )
    with pytest.raises(PermissionError, match="does not hold"):
        to_domain_principal(principal, ROLE_AUTHORISER)


def test_to_domain_principal_rejects_sysadmin_casework_override():
    principal = EnterprisePrincipal(
        subject="admin.root",
        roles=frozenset({ROLE_SYSTEM_ADMINISTRATOR}),
        issuer="test-idp",
    )
    with pytest.raises(PermissionError, match="System administrators do not have casework"):
        to_domain_principal(principal, ROLE_SYSTEM_ADMINISTRATOR)


def test_assert_dual_approval_allows_different_users():
    assert_dual_approval("user-inv-01", "user-auth-02")


def test_assert_dual_approval_blocks_self_approval():
    with pytest.raises(PermissionError, match="Self-approval blocked"):
        assert_dual_approval("user-inv-01", "user-inv-01")


def test_assert_dual_approval_requires_both_ids():
    with pytest.raises(PermissionError, match="Both investigator and authoriser IDs are required"):
        assert_dual_approval("", "user-auth-02")
