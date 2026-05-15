"""CSRF token generation, validation, and cookie creation.

Implements the double-submit cookie pattern using cryptographically
secure tokens via the ``secrets`` stdlib module.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import CSRFConfig


class CSRFHandler:
    """Stateless CSRF token handler.

    Generates secure tokens, validates them using constant-time
    comparison, and creates ``Set-Cookie`` header values for the
    double-submit cookie pattern.
    """

    @staticmethod
    def generate_token() -> str:
        """Generate a cryptographically secure random token.

        Uses ``secrets.token_urlsafe(32)`` which produces a 43-character
        URL-safe base64-encoded string with 256 bits of entropy.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_token(request_token: str, stored_token: str) -> bool:
        """Validate a CSRF token using constant-time comparison.

        Both the header token and the cookie token must match for
        validation to succeed.

        Parameters
        ----------
        request_token:
            The token from the ``X-CSRF-Token`` request header.
        stored_token:
            The token from the ``csrf_token`` cookie.
        """
        return secrets.compare_digest(request_token, stored_token)

    @staticmethod
    def create_cookie(token: str, config: CSRFConfig) -> str:
        """Build a ``Set-Cookie`` header value for the CSRF token.

        The cookie is **not** ``HttpOnly`` because the frontend JavaScript
        must read it for the double-submit pattern. ``Secure`` is set
        based on *config.secure_cookie*. ``SameSite=Strict`` prevents
        the cookie from being sent on cross-site requests.

        Parameters
        ----------
        token:
            The CSRF token value.
        config:
            The CSRF configuration.
        """
        parts = [
            f"{config.cookie_name}={token}",
            "Path=/",
            "SameSite=Strict",
        ]
        if config.secure_cookie:
            parts.append("Secure")
        parts.append("HttpOnly=False")
        return "; ".join(parts)
