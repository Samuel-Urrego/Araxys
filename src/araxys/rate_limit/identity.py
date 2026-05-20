"""Identity extraction for per-user and per-API-key rate limiting.

Pure functions that extract identity claims from incoming requests
without coupling the rate limiter to any specific auth middleware.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def extract_user_id(request: Request) -> str | None:
    """Extract a stable identity from a JWT Bearer token for rate limiting.

    Returns a SHA-256 hash (first 16 hex chars) of the raw Bearer token.
    This provides **per-credential** rate limiting without trusting the
    unverified ``sub`` claim.  Because this middleware runs *before*
    authentication, we cannot safely decode the JWT (an attacker could
    forge an unsigned token with any ``sub`` to exhaust another user's
    rate limit).

    Using the token hash guarantees a unique, stable bucket per token
    while preventing cross-user rate-limit exhaustion via forged JWTs.

    Returns ``None`` when:
    * No ``Authorization`` header is present.
    * The header is not a ``Bearer`` token.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.removeprefix("Bearer ")
    # Hash the raw token — the sub claim is untrusted here.
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def extract_api_key(request: Request) -> str | None:
    """Extract an API key from the ``X-API-Key`` request header."""
    return request.headers.get("x-api-key")
