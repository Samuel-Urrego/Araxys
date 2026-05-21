"""Custom exceptions for the WebAuthn / Passkeys module."""

from __future__ import annotations

from araxys.core.exceptions import AraxysError


class WebAuthnError(AraxysError):
    """Raised when a WebAuthn ceremony verification fails."""

    def __init__(self, message: str = "WebAuthn verification failed") -> None:
        super().__init__(message)


class COSEAlgorithmError(WebAuthnError):
    """Raised when a COSE algorithm is unsupported or unknown."""

    def __init__(self, alg: int) -> None:
        self.alg = alg
        super().__init__(f"Unsupported COSE algorithm: {alg}")
