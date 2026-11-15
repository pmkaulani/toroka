"""Bank-controlled OIDC authentication and role enforcement."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jwt.exceptions import (
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWTError,
)

from .config import VALID_ROLES

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class EnterprisePrincipal:
    subject: str
    roles: frozenset[str]
    issuer: str


def _claim_values(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _resolve_roles(claims: dict, settings) -> frozenset[str]:
    raw_roles = _claim_values(claims.get(settings.role_claim))
    resolved = set()
    for role in raw_roles:
        if role in settings.role_map:
            resolved.add(settings.role_map[role])
        elif not settings.role_map and role in VALID_ROLES:
            resolved.add(role)
    return frozenset(resolved & VALID_ROLES)


def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> EnterprisePrincipal:
    settings = request.app.state.settings

    # Isolated local development adapter.
    # This must never be enabled in a production deployment.
    if settings.auth_mode == "development":
        client = request.client
        if not client or not client.host:
            raise HTTPException(403, "Development access denied")
        try:
            peer = ipaddress.ip_address(client.host)
        except (ValueError, AttributeError):
            raise HTTPException(403, "Development access denied")
        if not peer.is_loopback:
            raise HTTPException(403, "Development access is local only")

        subject = request.headers.get("X-Dev-User", "").strip()
        raw_roles = [r.strip() for r in request.headers.get("X-Dev-Roles", "").split(",") if r.strip()]
        roles = frozenset(r for r in raw_roles if r in VALID_ROLES)
        if not subject or not roles:
            raise HTTPException(401, "Development identity required")
        return EnterprisePrincipal(
            subject=subject,
            roles=roles,
            issuer="local-development",
        )

    if credentials is None:
        raise HTTPException(401, "Authentication required")

    token = credentials.credentials
    jwks = getattr(request.app.state, "jwks_client", None)
    if jwks is None:
        raise HTTPException(
            503,
            "Identity provider verification is temporarily unavailable",
        )

    try:
        signing_key = jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(settings.algorithms),
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={
                "require": [
                    "iss",
                    "aud",
                    "sub",
                    "iat",
                    "exp",
                ]
            },
        )
    except PyJWKClientConnectionError:
        raise HTTPException(
            503,
            "Identity provider verification is temporarily unavailable",
        )
    except (PyJWKClientError, PyJWTError):
        raise HTTPException(401, "Invalid or expired access token")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(401, "Invalid identity subject")

    roles = _resolve_roles(claims, settings)
    if not roles:
        raise HTTPException(
            403,
            "No recognised Enterprise role is assigned",
        )

    return EnterprisePrincipal(
        subject=subject,
        roles=roles,
        issuer=claims["iss"],
    )


def require_roles(*required_roles: str) -> Callable:
    if not required_roles:
        raise ValueError("At least one role must be specified")

    def permission_check(
        principal: EnterprisePrincipal = Depends(get_current_principal),
    ) -> EnterprisePrincipal:
        if not principal.roles.intersection(required_roles):
            raise HTTPException(
                403,
                "You do not have permission to perform this action",
            )
        return principal

    return permission_check
