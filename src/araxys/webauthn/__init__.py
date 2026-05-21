"""WebAuthn / Passkeys module for Araxys.

Provides WebAuthn/FIDO2 ceremony verification for passkey-based
authentication — both registration and authentication.
"""

from __future__ import annotations

from araxys.webauthn.manager import WebAuthnManager
from araxys.webauthn.models import CredentialRecord, RelyingPartyConfig

__all__ = [
    "CredentialRecord",
    "RelyingPartyConfig",
    "WebAuthnManager",
]
