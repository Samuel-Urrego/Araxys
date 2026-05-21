"""Data models for the WebAuthn / Passkeys module."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True)
class RelyingPartyConfig:
    """Configuration for the WebAuthn Relying Party.

    Attributes:
        rp_id: The relying party identifier (e.g. "example.com").
        rp_name: Human-readable name for the RP (e.g. "Example Corp").
        expected_origin: The expected origin from clientDataJSON
            (e.g. "https://example.com").
    """

    rp_id: str
    rp_name: str
    expected_origin: str


@dataclass
class CredentialRecord:
    """A stored WebAuthn credential.

    Attributes:
        credential_id: The raw credential ID bytes.
        user_id: The user identifier this credential belongs to.
        public_key_cbor: Raw COSE_Key CBOR bytes for signature verification.
        sign_count: The current authenticator sign count (monotonic).
        alg: COSE algorithm identifier (e.g. -7 for ES256, -257 for RS256).
        created_at: When this credential was first stored.
        credential_type: Always "public-key" for WebAuthn.
        attestation_type: The attestation format ("none" or "packed").
    """

    credential_id: bytes
    user_id: str
    public_key_cbor: bytes
    sign_count: int
    alg: int
    created_at: datetime
    credential_type: str = field(default="public-key")
    attestation_type: str = field(default="none")

    def __post_init__(self) -> None:
        """Normalize created_at to UTC."""
        if self.created_at.tzinfo is None:
            object.__setattr__(
                self, "created_at", self.created_at.replace(tzinfo=UTC)
            )
