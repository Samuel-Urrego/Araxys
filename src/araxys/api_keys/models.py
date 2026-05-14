"""API Key data models."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from araxys.core.types import Scope


class APIKeyRecord(BaseModel):
    """Stored representation of an API key.

    The raw key is never stored — only its SHA-256 hash. The ``prefix``
    (first 8 characters) is used for lookup.
    """

    key_hash: str = Field(description="SHA-256 hash of the raw API key")
    prefix: str = Field(
        min_length=8,
        max_length=8,
        description="First 8 characters of the key for identification",
    )
    scopes: list[Scope] = Field(default_factory=list)
    expires_at: datetime | None = Field(
        default=None,
        description="Expiration timestamp (None = never expires)",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    owner: str = Field(description="Owner identifier for the key")
    is_active: bool = Field(default=True)
    label: str | None = Field(
        default=None,
        description="Optional human-readable label for the key",
    )


class APIKeyResponse(BaseModel):
    """Response model returned when creating a new API key.

    Contains the raw key — this is the ONLY time it is available.
    """

    raw_key: str = Field(description="The full API key — store it securely, shown only once")
    prefix: str = Field(description="Key prefix for future reference")
    scopes: list[Scope]
    expires_at: datetime | None
    owner: str
