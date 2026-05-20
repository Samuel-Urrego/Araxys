"""MFA data models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class MFASetupResponse(BaseModel):
    """Returned when a user initiates MFA setup."""

    secret: str = Field(description="Base32-encoded TOTP secret")
    qr_uri: str = Field(description="otpauth:// URI for QR code generation")
    recovery_codes: list[str] = Field(
        description="One-time recovery codes — store securely"
    )


class MFAVerifyRequest(BaseModel):
    """Request to verify a TOTP code during setup or login."""

    code: str = Field(
        min_length=6, max_length=8, description="6 or 8 digit TOTP code"
    )


class MFARecord(BaseModel):
    """Stored MFA configuration for a user."""

    user_id: str = Field(description="User identifier")
    secret_hash: str = Field(
        description="SHA-256 hash of the TOTP secret (encrypted at rest)"
    )
    encrypted_secret: str = Field(
        description="AES-256-GCM encrypted TOTP secret"
    )
    recovery_codes: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashed recovery codes (remaining)",
    )
    enabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.now)
