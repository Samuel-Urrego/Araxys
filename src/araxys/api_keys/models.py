"""API Key data models."""


from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from araxys.core.types import Scope  # noqa: TC001


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
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    owner: str = Field(description="Owner identifier for the key")
    is_active: bool = Field(default=True)
    last_used_at: datetime | None = Field(
        default=None,
        description="Timestamp of last successful verification",
    )
    label: str | None = Field(
        default=None,
        description="Optional human-readable label for the key",
    )
    key_type: Literal["secret", "public"] = Field(
        default="secret",
        description="Key type — secret keys have full access, public keys are read-only",
    )


class APIKeyResponse(BaseModel):
    """Response model returned when creating a new API key.

    Contains the raw key — this is the ONLY time it is available.
    """

    raw_key: str = Field(
        description="The full API key — store it securely, shown only once"
    )
    prefix: str = Field(description="Key prefix for future reference")
    key_type: Literal["secret", "public"] = Field(
        default="secret",
        description="Type of the key",
    )
    scopes: list[Scope]
    expires_at: datetime | None
    owner: str
