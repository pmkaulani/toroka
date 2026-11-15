"""Internal service authentication for the Identity Vault."""
from __future__ import annotations

import hmac
from fastapi import Header, HTTPException, Request, status


def require_internal_service_auth(
    request: Request,
    x_internal_service_token: str = Header(..., alias="X-Internal-Service-Token"),
) -> None:
    """Verify that the caller is the authorised Enterprise API service.
    
    Uses constant-time comparison to prevent timing attacks.
    """
    settings = getattr(request.app.state, "settings", None)
    expected_token = getattr(settings, "service_token", "") if settings else ""

    if not expected_token or not hmac.compare_digest(x_internal_service_token.encode("utf-8"), expected_token.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid or missing internal service token",
        )
