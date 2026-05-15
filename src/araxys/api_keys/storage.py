"""API Key storage protocol and in-memory implementation.

The user can implement the ``APIKeyStorage`` protocol with their own
database backend (SQLAlchemy, MongoDB, etc.).
"""


from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from araxys.api_keys.models import APIKeyRecord


@runtime_checkable
class APIKeyStorage(Protocol):
    """Interface for API key persistence."""

    async def store(self, record: APIKeyRecord) -> None:
        """Persist a new API key record."""
        ...

    async def get_by_prefix(self, prefix: str) -> APIKeyRecord | None:
        """Retrieve an API key record by its prefix."""
        ...

    async def revoke(self, prefix: str) -> bool:
        """Revoke an API key. Returns True if the key was found and revoked."""
        ...

    async def list_keys(self, owner: str | None = None) -> list[APIKeyRecord]:
        """List all active keys, optionally filtered by owner."""
        ...


class InMemoryAPIKeyStorage:
    """In-memory API key storage for development and testing."""

    def __init__(self) -> None:
        self._keys: dict[str, APIKeyRecord] = {}

    async def store(self, record: APIKeyRecord) -> None:
        self._keys[record.prefix] = record

    async def get_by_prefix(self, prefix: str) -> APIKeyRecord | None:
        record = self._keys.get(prefix)
        if record is None:
            return None
        # Check expiration
        if record.expires_at and record.expires_at < datetime.now(UTC):
            record = record.model_copy(update={"is_active": False})
            self._keys[prefix] = record
        return record if record.is_active else None

    async def revoke(self, prefix: str) -> bool:
        if prefix not in self._keys:
            return False
        self._keys[prefix] = self._keys[prefix].model_copy(update={"is_active": False})
        return True

    async def list_keys(self, owner: str | None = None) -> list[APIKeyRecord]:
        keys = [k for k in self._keys.values() if k.is_active]
        if owner:
            keys = [k for k in keys if k.owner == owner]
        return keys
