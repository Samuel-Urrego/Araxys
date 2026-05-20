"""API Key storage protocol and in-memory implementation.

The user can implement the ``APIKeyStorage`` protocol with their own
database backend (SQLAlchemy, MongoDB, etc.).
"""


from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from araxys.api_keys.models import APIKeyRecord
    from araxys.db_security.pool import ConnectionPool


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

    def __init__(
        self,
        redis_url: str | None = None,
        key_prefix: str = "araxys:apikey:",
        *,
        pool: ConnectionPool | None = None,
    ) -> None:
        self._pool = pool
        self._redis: Redis | None = None
        self._prefix = key_prefix
        if pool is None and redis_url:
            try:
                from redis.asyncio import Redis
            except ImportError:
                raise ImportError(
                    "The 'redis' extra is required to use RedisAPIKeyStorage. "
                    "Run 'pip install araxys[redis]'"
                ) from None

            self._redis = Redis.from_url(redis_url, decode_responses=True)

    def _get_key(self, prefix: str) -> str:
        return f"{self._prefix}{prefix}"

    async def store(self, record: APIKeyRecord) -> None:
        key = self._get_key(record.prefix)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                await conn.set(key, record.model_dump_json())
                if record.expires_at:
                    ttl = int(
                        (record.expires_at - datetime.now(UTC)).total_seconds()
                    )
                    if ttl > 0:
                        await conn.expire(key, ttl)
                return
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        await self._redis.set(key, record.model_dump_json())
        if record.expires_at:
            ttl = int((record.expires_at - datetime.now(UTC)).total_seconds())
            if ttl > 0:
                await self._redis.expire(key, ttl)

    async def get_by_prefix(self, prefix: str) -> APIKeyRecord | None:
        from araxys.api_keys.models import APIKeyRecord

        key = self._get_key(prefix)
        data: str | None
        if self._pool:
            conn = await self._pool.acquire()
            try:
                data = await conn.get(key)
            finally:
                await self._pool.release(conn)
        else:
            assert self._redis is not None
            data = await self._redis.get(key)

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

        if self._pool:
            conn = await self._pool.acquire()
            try:
                keys = await self._scan_list_keys(conn, owner)
                return keys
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        return await self._scan_list_keys(self._redis, owner)

    async def _scan_list_keys(
        self, conn: Redis, owner: str | None,
    ) -> list[APIKeyRecord]:
        from araxys.api_keys.models import APIKeyRecord

        keys: list[APIKeyRecord] = []
        async for key in conn.scan_iter(match=f"{self._prefix}*"):
            data = await conn.get(key)
            if data:
                record = APIKeyRecord.model_validate_json(data)
                if record.is_active and (not owner or record.owner == owner):
                    keys.append(record)
        return keys
