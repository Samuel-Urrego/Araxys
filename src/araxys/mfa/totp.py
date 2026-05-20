"""TOTP — RFC 6238 Time-Based One-Time Password.

Pure-Python implementation with zero external dependencies beyond the
stdlib.  Uses HMAC-SHA1 with a 30-second time step and 6-digit codes
by default.

Usage::

    from araxys.mfa.totp import TOTP

    # Generate a secret for a user
    secret = TOTP.generate_secret()  # base32 string

    # Generate QR code URI for Google Authenticator / Authy
    uri = TOTP.qr_uri(secret, "alice@example.com", issuer="MyApp")

    # Verify a code
    if TOTP.verify(secret, "123456"):
        print("Valid!")
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse
from typing import Literal


class TOTP:
    """RFC 6238 TOTP implementation.

    All methods are static — no state, no external dependencies.
    """

    DEFAULT_DIGITS = 6
    DEFAULT_PERIOD = 30  # seconds
    DEFAULT_ALGORITHM: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    SECRET_BYTES = 20  # 160 bits of entropy

    # ── Secret Generation ──────────────────────────────────────────

    @staticmethod
    def generate_secret() -> str:
        """Generate a cryptographically secure base32-encoded secret.

        Returns a base32 string (uppercase, no padding) suitable for
        manual entry or QR code encoding.
        """
        raw = secrets.token_bytes(TOTP.SECRET_BYTES)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    # ── QR Code URI ───────────────────────────────────────────────

    @staticmethod
    def qr_uri(
        secret: str,
        account: str,
        *,
        issuer: str = "",
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
    ) -> str:
        """Build an ``otpauth://`` URI for QR code generation.

        Parameters
        ----------
        secret:
            Base32-encoded shared secret.
        account:
            User identifier (e.g. email or username).
        issuer:
            Service name displayed in the authenticator app.
        digits:
            Number of digits in the OTP (6 or 8).
        period:
            Time step in seconds (default 30).
        """
        label = urllib.parse.quote(f"{issuer}:{account}" if issuer else account)
        params = urllib.parse.urlencode(
            {
                "secret": secret,
                "issuer": issuer,
                "algorithm": "SHA1",
                "digits": digits,
                "period": period,
            }
        )
        return f"otpauth://totp/{label}?{params}"

    # ── Code Verification ─────────────────────────────────────────

    @staticmethod
    def verify(
        secret: str,
        code: str,
        *,
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
        window: int = 1,
    ) -> bool:
        """Verify a TOTP code against *secret*.

        Parameters
        ----------
        secret:
            Base32-encoded shared secret.
        code:
            The 6-digit (or 8-digit) code to verify.
        digits:
            Number of digits (6 or 8).
        period:
            Time step in seconds.
        window:
            Number of adjacent time steps to check (default 1 means
            current ± 1 step = ~90 seconds of validity).  Increase
            to account for clock drift.

        Returns
        -------
        bool
            ``True`` if the code is valid for any time step in the
            window.
        """
        now = int(time.time())
        for offset in range(-window, window + 1):
            expected = TOTP._compute(secret, now + offset * period, digits, period)
            if hmac.compare_digest(expected, code):
                return True
        return False

    # ── Internal ──────────────────────────────────────────────────

    @staticmethod
    def _compute(
        secret: str,
        timestamp: int,
        digits: int,
        period: int,
    ) -> str:
        """Compute the TOTP code for *timestamp*."""
        counter = timestamp // period
        key = TOTP._decode_secret(secret)
        counter_bytes = counter.to_bytes(8, "big")
        digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = (
            ((digest[offset] & 0x7F) << 24)
            | ((digest[offset + 1] & 0xFF) << 16)
            | ((digest[offset + 2] & 0xFF) << 8)
            | (digest[offset + 3] & 0xFF)
        )
        return str(binary % (10**digits)).zfill(digits)

    @staticmethod
    def _decode_secret(secret: str) -> bytes:
        """Decode a base32 secret, adding padding if needed."""
        secret = secret.upper().replace(" ", "")
        # Add base32 padding
        remainder = len(secret) % 8
        if remainder:
            secret += "=" * (8 - remainder)
        return base64.b32decode(secret)
