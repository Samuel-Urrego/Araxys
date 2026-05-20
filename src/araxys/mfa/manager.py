"""MFA Manager — TOTP setup, verification, and recovery codes.

Manages the full MFA lifecycle: initial setup (secret generation),
code verification, and one-time recovery codes stored as SHA-256
hashes.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import TYPE_CHECKING

from araxys.mfa.totp import TOTP

if TYPE_CHECKING:
    from araxys.core.config import MFAConfig


class MFAManager:
    """Manages TOTP-based multi-factor authentication.

    Parameters
    ----------
    config:
        MFA configuration.
    secret_key:
        Master secret key for encrypting TOTP secrets at rest.
    """

    def __init__(self, config: MFAConfig, secret_key: str) -> None:
        self._config = config
        self._secret_key = secret_key

    # ── Setup ───────────────────────────────────────────────────────

    def setup(self, user_id: str) -> tuple[str, str, list[str]]:
        """Generate a new TOTP secret and recovery codes.

        Returns ``(secret, qr_uri, recovery_codes)``.  The caller
        must store the encrypted secret and hashed recovery codes.
        """
        secret = TOTP.generate_secret()
        qr_uri = TOTP.qr_uri(
            secret,
            user_id,
            issuer=self._config.issuer,
            digits=self._config.digits,
            period=self._config.period_seconds,
        )
        recovery_codes = [
            self._generate_recovery_code()
            for _ in range(self._config.recovery_code_count)
        ]
        return secret, qr_uri, recovery_codes

    # ── Verification ────────────────────────────────────────────────

    def verify(self, secret: str, code: str) -> bool:
        """Verify a TOTP code against the stored secret."""
        return TOTP.verify(
            secret,
            code,
            digits=self._config.digits,
            period=self._config.period_seconds,
            window=self._config.window,
        )

    # ── Recovery Codes ──────────────────────────────────────────────

    def _generate_recovery_code(self) -> str:
        """Generate a human-friendly recovery code (e.g. 'ABCD-EFGH-IJKL')."""
        raw = secrets.token_hex(self._config.recovery_code_bytes)
        # Format as groups of 4: xxxx-xxxx-xxxx-xxxx
        code = raw.upper()
        return "-".join(code[i : i + 4] for i in range(0, len(code), 4))

    @staticmethod
    def hash_recovery_code(code: str) -> str:
        """SHA-256 hash a recovery code for storage."""
        return hashlib.sha256(code.encode()).hexdigest()

    @staticmethod
    def verify_recovery_code(
        code: str, hashed_codes: list[str]
    ) -> tuple[bool, list[str]]:
        """Check a recovery code and remove it if valid.

        Returns ``(valid, remaining_codes)``.  On match, the used
        code is removed from the list so it cannot be reused.
        """
        code_hash = MFAManager.hash_recovery_code(code)
        for i, stored in enumerate(hashed_codes):
            if stored == code_hash:
                remaining = hashed_codes[:i] + hashed_codes[i + 1 :]
                return True, remaining
        return False, hashed_codes
