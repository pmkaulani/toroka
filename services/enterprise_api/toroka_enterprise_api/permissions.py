"""Role definitions, permission checks, and domain principal adapters."""
from __future__ import annotations

from toroka_enterprise.casework import Principal as DomainPrincipal

from .auth import EnterprisePrincipal
from .config import VALID_ROLES

ROLE_INVESTIGATOR = "investigator"
ROLE_AUTHORISER = "authoriser"
ROLE_AUDITOR = "auditor"
ROLE_DATA_STEWARD = "data_steward"
ROLE_SYSTEM_ADMINISTRATOR = "system_administrator"

ALL_ENTERPRISE_ROLES = frozenset(VALID_ROLES)

# Roles with operational read-access to data contract & capabilities
BANK_ROLES = (
    ROLE_INVESTIGATOR,
    ROLE_AUTHORISER,
    ROLE_AUDITOR,
    ROLE_DATA_STEWARD,
    ROLE_SYSTEM_ADMINISTRATOR,
)

# Operational roles allowed to participate in casework workflows
CASEWORK_ROLES = frozenset({ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR})


def to_domain_principal(
    api_principal: EnterprisePrincipal,
    effective_role: str,
) -> DomainPrincipal:
    """Explicit adapter from an authenticated API principal to a domain Principal.

    Enforces that:
    1. The API principal actually possesses the requested role.
    2. System administrators cannot pose as caseworkers to override investigator/authoriser controls.
    3. The resulting domain role is recognised by the underlying CaseStore.
    """
    if effective_role not in api_principal.roles:
        raise PermissionError(
            f"User '{api_principal.subject}' does not hold the '{effective_role}' role."
        )

    if effective_role == ROLE_SYSTEM_ADMINISTRATOR:
        raise PermissionError(
            "System administrators do not have casework or identity-reveal authority."
        )

    if effective_role not in CASEWORK_ROLES:
        raise PermissionError(
            f"Role '{effective_role}' cannot act as a casework principal."
        )

    return DomainPrincipal(
        user_id=api_principal.subject,
        role=effective_role,
    )


def assert_dual_approval(investigator_id: str, authoriser_id: str) -> None:
    """Enforce strict separation between investigator requester and authoriser.

    Holding multiple roles does not permit self-approval.
    """
    if not investigator_id or not authoriser_id:
        raise PermissionError("Both investigator and authoriser IDs are required.")

    if investigator_id.strip() == authoriser_id.strip():
        raise PermissionError(
            "Self-approval blocked: an investigator cannot approve their own identity reveal."
        )
