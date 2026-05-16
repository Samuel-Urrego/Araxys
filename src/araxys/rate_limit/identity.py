"""Identity extraction for per-user and per-API-key rate limiting.

Pure functions that extract identity claims from incoming requests
without coupling the rate limiter to any specific auth middleware.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def extract_user_id(request: Request) -> str | None:
    """Extract user identity from a JWT Bearer token's ``sub`` claim.

    Decodes the token *without* signature verification — the request
    chain is expected to have already verified the JWT (if needed) by
    the time it reaches this middleware.

    Returns ``None`` when:
    * No ``Authorization`` header is present.
    * The header is not a ``Bearer`` token.
    * The token is malformed or has no ``sub`` claim.
    """
    import jwt

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ")
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        sub: str | None = payload.get("sub")
        return sub
    except Exception:
        return None


def extract_api_key(request: Request) -> str | None:
    """Extract an API key from the ``X-API-Key`` request header."""
    return request.headers.get("x-api-key")
