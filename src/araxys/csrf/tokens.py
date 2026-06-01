"""CSRF token generation, validation, and cookie creation.

Implements the double-submit cookie pattern using cryptographically
secure tokens via the ``secrets`` stdlib module.  Tokens include an
embedded expiry timestamp so that ``token_expiry_seconds`` (from
``CSRFConfig``) is actually enforced.
"""

from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import CSRFConfig


def _make_expiring_token(expiry_seconds: int) -> tuple[str, str]:
    """Return ``(full_token, raw_random_part)``.

    The full token has the format ``<expiry_timestamp>.<random>`` so
    that ``validate_token`` can check expiry before comparing the
    random part in constant time.
    """
    raw = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + expiry_seconds
    return f"{expires_at}.{raw}", raw


def _extract_raw(token: str) -> tuple[int, str] | None:
    """Parse a token and return ``(expiry_timestamp, raw_random)``.

    Returns ``None`` for tokens in the legacy (no-dot) format so that
    they are rejected — all tokens must be in the expiring format.
    """
    if "." not in token:
        return None
    parts = token.split(".", 1)
    try:
        return int(parts[0]), parts[1]
    except (ValueError, IndexError):
        return None


class CSRFHandler:
    """Stateless CSRF token handler.

    Generates secure tokens, validates them using constant-time
    comparison, and creates ``Set-Cookie`` header values for the
    double-submit cookie pattern.

    Tokens embed an expiry timestamp (the first component before the
    dot) so that ``CSRFConfig.token_expiry_seconds`` is enforced at
    validation time.
    """

    @staticmethod
    def generate_token(expiry_seconds: int = 3600) -> str:
        """Generate a cryptographically secure token with embedded expiry.

        Returns a token in the format ``<expiry_ts>.<random>`` where
        *expiry_ts* is a Unix timestamp and *random* is a 43-char
        URL-safe base64 string.
        """
        token, _ = _make_expiring_token(expiry_seconds)
        return token

    @staticmethod
    def validate_token(request_token: str, stored_token: str) -> bool:
        """Validate a CSRF token using constant-time comparison.

        Both tokens must be in the expiring format (``<ts>.<random>``).
        Tokens past their expiry are rejected.  Legacy tokens without
        an expiry prefix are also rejected so that old tokens are
        force-rotated.

        Parameters
        ----------
        request_token:
            The token from the ``X-CSRF-Token`` request header.
        stored_token:
            The token from the ``csrf_token`` cookie.
        """
        req = _extract_raw(request_token)
        stored = _extract_raw(stored_token)
        if req is None or stored is None:
            return False

        req_expiry, req_raw = req
        stored_expiry, stored_raw = stored

        now = int(time.time())
        if now >= req_expiry or now >= stored_expiry:
            return False

        return secrets.compare_digest(req_raw, stored_raw)

    @staticmethod
    def create_cookie(token: str, config: CSRFConfig) -> str:
        """Build a ``Set-Cookie`` header value for the CSRF token.

        The cookie is **not** ``HttpOnly`` by default because the frontend
        JavaScript must read it for the double-submit pattern. ``Secure``
        is set based on *config.secure_cookie*. ``SameSite`` defaults to
        ``strict`` for CSRF protection.

        Parameters
        ----------
        token:
            The CSRF token value.
        config:
            The CSRF configuration.
        """
        parts = [
            f"{config.cookie_name}={token}",
            f"Path={config.cookie_path}",
            f"SameSite={config.cookie_samesite}",
        ]
        if config.cookie_domain:
            parts.append(f"Domain={config.cookie_domain}")
        if config.secure_cookie:
            parts.append("Secure")
        parts.append(f"HttpOnly={'True' if config.cookie_httponly else 'False'}")
        return "; ".join(parts)
