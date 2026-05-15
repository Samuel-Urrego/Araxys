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


class RedisAPIKeyStorage:
    """Redis-backed API key storage for persistence across processes."""

    def __init__(self, redis_url: str, key_prefix: str = "araxys:apikey:") -> None:
        try:
            from redis.asyncio import Redis
        except ImportError:
            raise ImportError(
                "The 'redis' extra is required to use RedisAPIKeyStorage. "
                "Run 'pip install araxys[redis]'"
            ) from None

        self._redis = Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix

    def _get_key(self, prefix: str) -> str:
        return f"{self._prefix}{prefix}"

    async def store(self, record: APIKeyRecord) -> None:
        from araxys.api_keys.models import APIKeyRecord # Avoid circular import

        key = self._get_key(record.prefix)
        await self._redis.set(key, record.model_dump_json())

    async def get_by_prefix(self, prefix: str) -> APIKeyRecord | None:
        from araxys.api_keys.models import APIKeyRecord

        data = await self._redis.get(self._get_key(prefix))
        if not data:
            return None

        record = APIKeyRecord.model_validate_json(data)

        # Check expiration
        if record.expires_at and record.expires_at < datetime.now(UTC):
            record = record.model_copy(update={"is_active": False})
            await self.store(record)

        return record if record.is_active else None

    async def revoke(self, prefix: str) -> bool:
        record = await self.get_by_prefix(prefix)
        if not record:
            return False

        record = record.model_copy(update={"is_active": False})
        await self.store(record)
        return True

    async def list_keys(self, owner: str | None = None) -> list[APIKeyRecord]:
        from araxys.api_keys.models import APIKeyRecord

        keys = []
        async for key in self._redis.scan_iter(match=f"{self._prefix}*"):
            data = await self._redis.get(key) # type: ignore
            if data:
                record = APIKeyRecord.model_validate_json(data)
                if record.is_active and (not owner or record.owner == owner):
                    keys.append(record)
        return keys
