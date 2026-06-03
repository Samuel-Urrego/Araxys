from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from fakeredis.aioredis import FakeRedis

from araxys.api_keys.models import APIKeyRecord
from araxys.api_keys.storage import RedisAPIKeyStorage
from araxys.core.types import Scope
from araxys.db_security.query_validator import QueryValidationResult

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from araxys.jwt_auth.storage import RedisTokenStorage
    from araxys.rate_limit.backends import RedisBackend
    from araxys.sessions.storage import RedisSessionBackend


@pytest.fixture
async def redis_storage() -> RedisAPIKeyStorage:
    storage = RedisAPIKeyStorage("redis://localhost")
    # Replace real redis with fakeredis
    storage._redis = FakeRedis(decode_responses=True)
    return storage

@pytest.mark.asyncio
class TestRedisAPIKeyStorage:
    async def test_store_and_retrieve(self, redis_storage: RedisAPIKeyStorage) -> None:
        record = APIKeyRecord(
            prefix="testpref",
            key_hash="somehash",
            owner="test-owner",
            scopes=[Scope.READ],
            is_active=True
        )
        
        await redis_storage.store(record)
        
        retrieved = await redis_storage.get_by_prefix("testpref")
        assert retrieved is not None
        assert retrieved.owner == "test-owner"
        assert retrieved.prefix == "testpref"

    async def test_revoke_key(self, redis_storage: RedisAPIKeyStorage) -> None:
        record = APIKeyRecord(
            prefix="revokeme",
            key_hash="somehash",
            owner="test-owner",
            scopes=[Scope.READ],
            is_active=True
        )
        await redis_storage.store(record)
        
        success = await redis_storage.revoke("revokeme")
        assert success
        
        retrieved = await redis_storage.get_by_prefix("revokeme")
        assert retrieved is None # Should return None if is_active is False

    async def test_list_keys(self, redis_storage: RedisAPIKeyStorage) -> None:
        await redis_storage.store(APIKeyRecord(
            prefix="key00001", key_hash="h1", owner="user1", scopes=[], is_active=True
        ))
        await redis_storage.store(APIKeyRecord(
            prefix="key00002", key_hash="h2", owner="user1", scopes=[], is_active=True
        ))
        await redis_storage.store(APIKeyRecord(
            prefix="key00003", key_hash="h3", owner="user2", scopes=[], is_active=True
        ))
        
        all_keys = await redis_storage.list_keys()
        assert len(all_keys) == 3
        
        user1_keys = await redis_storage.list_keys(owner="user1")
        assert len(user1_keys) == 2

    async def test_expiration(self, redis_storage: RedisAPIKeyStorage) -> None:
        past_date = datetime.now(UTC) - timedelta(days=1)
        record = APIKeyRecord(
            prefix="expired1",
            key_hash="somehash",
            owner="test-owner",
            scopes=[],
            expires_at=past_date,
            is_active=True
        )
        await redis_storage.store(record)
        
        retrieved = await redis_storage.get_by_prefix("expired1")
        assert retrieved is None


# ══════════════════════════════════════════════════════════════════════════════
# Pool injection tests — each backend with optional `pool: ConnectionPool`
# ══════════════════════════════════════════════════════════════════════════════


class _FakePool:
    """Minimal ConnectionPool wrapping a shared ``FakeRedis`` for testing.

    Returns the same ``FakeRedis`` instance on every ``acquire()`` so data
    written in one acquire is visible in another. Tracks counts for
    acquire/release lifecycle verification.
    """

    def __init__(self) -> None:
        self._redis: Redis = FakeRedis(decode_responses=True)
        self.acquire_count: int = 0
        self.release_count: int = 0

    async def acquire(self) -> Redis:
        self.acquire_count += 1
        return self._redis

    async def release(self, conn: Redis) -> None:
        self.release_count += 1

    async def health(self) -> bool:
        return True

    def get_redis_client(self) -> Redis:
        return self._redis

    async def reload_url(self, url: str) -> None:
        """No-op: test pool doesn't support credential rotation."""

    async def close(self) -> None:
        await self._redis.aclose()

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """No-op: test pool always returns passed."""
        return QueryValidationResult(passed=True, reason=None)


# ══════════════════════════════════════════════════════════════════════════════
# RedisBackend (rate_limit/backends.py)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestRedisBackendWithPool:
    """RedisBackend — pool injection tests."""

    @pytest.fixture
    def pool(self) -> _FakePool:
        return _FakePool()

    @pytest.fixture
    def backend(self, pool: _FakePool) -> RedisBackend:
        from araxys.rate_limit.backends import RedisBackend

        return RedisBackend(pool=pool)

    async def test_increment_via_pool(self, backend: RedisBackend) -> None:
        count = await backend.increment("pool_incr", 60)
        assert count == 1
        count = await backend.increment("pool_incr", 60)
        assert count == 2

    async def test_get_count_via_pool(self, backend: RedisBackend) -> None:
        await backend.increment("pool_cnt", 60)
        await backend.increment("pool_cnt", 60)
        count = await backend.get_count("pool_cnt")
        assert count == 2

    async def test_ban_via_pool(self, backend: RedisBackend) -> None:
        await backend.ban("10.0.0.1", 30)
        assert await backend.is_banned("10.0.0.1") is True

    async def test_is_banned_via_pool(self, backend: RedisBackend) -> None:
        assert await backend.is_banned("nonexistent") is False
        await backend.ban("10.0.0.2", 30)
        assert await backend.is_banned("10.0.0.2") is True

    async def test_get_ban_expiry_via_pool(self, backend: RedisBackend) -> None:
        expiry = await backend.get_ban_expiry("nonexistent")
        assert expiry == 0
        await backend.ban("10.0.0.3", 60)
        expiry = await backend.get_ban_expiry("10.0.0.3")
        assert 0 < expiry <= 60

    async def test_get_violation_count_via_pool(self, backend: RedisBackend) -> None:
        count = await backend.get_violation_count("10.0.0.4")
        assert count == 0

    async def test_increment_violations_via_pool(
        self, backend: RedisBackend,
    ) -> None:
        count = await backend.increment_violations("10.0.0.5")
        assert count == 1
        count = await backend.increment_violations("10.0.0.5")
        assert count == 2

    async def test_legacy_path_no_pool(self) -> None:
        from araxys.rate_limit.backends import RedisBackend

        backend = RedisBackend(redis_url="redis://localhost")
        backend._redis = FakeRedis(decode_responses=True)
        count = await backend.increment("legacy_incr", 60)
        assert count == 1

    async def test_acquire_release_lifecycle(self, pool: _FakePool) -> None:
        from araxys.rate_limit.backends import RedisBackend

        backend = RedisBackend(pool=pool)
        await backend.increment("lifecycle", 60)
        assert pool.acquire_count == 1
        assert pool.release_count == 1
        await backend.get_count("lifecycle")
        assert pool.acquire_count == 2
        assert pool.release_count == 2


# ══════════════════════════════════════════════════════════════════════════════
# RedisTokenStorage (jwt_auth/storage.py)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestRedisTokenStorageWithPool:
    """RedisTokenStorage — pool injection tests."""

    @pytest.fixture
    def pool(self) -> _FakePool:
        return _FakePool()

    @pytest.fixture
    def storage(self, pool: _FakePool) -> RedisTokenStorage:
        from araxys.jwt_auth.storage import RedisTokenStorage

        return RedisTokenStorage(pool=pool)

    async def test_blacklist_jti_via_pool(
        self, storage: RedisTokenStorage,
    ) -> None:
        await storage.blacklist_jti("jti-pool-001", 300)
        assert await storage.is_blacklisted("jti-pool-001") is True

    async def test_is_blacklisted_via_pool(
        self, storage: RedisTokenStorage,
    ) -> None:
        assert await storage.is_blacklisted("nonexistent") is False
        await storage.blacklist_jti("jti-pool-002", 300)
        assert await storage.is_blacklisted("jti-pool-002") is True

    async def test_legacy_path_no_pool(self) -> None:
        from araxys.jwt_auth.storage import RedisTokenStorage

        storage = RedisTokenStorage(redis_url="redis://localhost")
        storage._redis = FakeRedis(decode_responses=True)
        await storage.blacklist_jti("jti-legacy-001", 300)
        assert await storage.is_blacklisted("jti-legacy-001") is True


# ══════════════════════════════════════════════════════════════════════════════
# RedisAPIKeyStorage (api_keys/storage.py)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestRedisAPIKeyStorageWithPool:
    """RedisAPIKeyStorage — pool injection tests."""

    @pytest.fixture
    def pool(self) -> _FakePool:
        return _FakePool()

    @pytest.fixture
    def storage(self, pool: _FakePool) -> RedisAPIKeyStorage:
        from araxys.api_keys.storage import RedisAPIKeyStorage

        return RedisAPIKeyStorage(pool=pool)

    async def test_store_via_pool(self, storage: RedisAPIKeyStorage) -> None:
        record = APIKeyRecord(
            prefix="poolprf_",
            key_hash="hash1",
            owner="owner1",
            scopes=[Scope.READ],
            is_active=True,
        )
        await storage.store(record)
        retrieved = await storage.get_by_prefix("poolprf_")
        assert retrieved is not None
        assert retrieved.owner == "owner1"
        assert retrieved.prefix == "poolprf_"

    def _make_record(self, prefix: str) -> APIKeyRecord:
        return APIKeyRecord(
            prefix=prefix,
            key_hash="hash2",
            owner="owner1",
            scopes=[Scope.READ],
            is_active=True,
        )

    async def test_revoke_via_pool(self, storage: RedisAPIKeyStorage) -> None:
        record = self._make_record("pool_rev")
        await storage.store(record)
        success = await storage.revoke("pool_rev")
        assert success
        assert await storage.get_by_prefix("pool_rev") is None

    async def test_legacy_path_no_pool(self) -> None:
        from araxys.api_keys.storage import RedisAPIKeyStorage

        storage = RedisAPIKeyStorage(redis_url="redis://localhost")
        storage._redis = FakeRedis(decode_responses=True)
        record = APIKeyRecord(
            prefix="legacypr",
            key_hash="hash3",
            owner="legacy",
            scopes=[Scope.READ],
            is_active=True,
        )
        await storage.store(record)
        retrieved = await storage.get_by_prefix("legacypr")
        assert retrieved is not None
        assert retrieved.owner == "legacy"


# ══════════════════════════════════════════════════════════════════════════════
# RedisSessionBackend (sessions/storage.py)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestRedisSessionBackendWithPool:
    """RedisSessionBackend — pool injection tests."""

    @pytest.fixture
    def pool(self) -> _FakePool:
        return _FakePool()

    @pytest.fixture
    def backend(self, pool: _FakePool) -> RedisSessionBackend:
        from araxys.sessions.storage import RedisSessionBackend

        return RedisSessionBackend(pool=pool)

    async def test_create_session_via_pool(
        self, backend: RedisSessionBackend,
    ) -> None:
        sid = await backend.create_session("user1", "jti-101")
        assert sid is not None
        assert len(sid) > 0

    async def test_get_session_via_pool(
        self, backend: RedisSessionBackend,
    ) -> None:
        sid = await backend.create_session("user2", "jti-102")
        record = await backend.get_session(sid)
        assert record is not None
        assert record.user_id == "user2"
        assert record.jti == "jti-102"

    async def test_revoke_session_via_pool(
        self, backend: RedisSessionBackend,
    ) -> None:
        sid = await backend.create_session("user3", "jti-103")
        revoked = await backend.revoke_session(sid)
        assert revoked is True
        assert await backend.get_session(sid) is None

    async def test_legacy_path_no_pool(self) -> None:
        from araxys.sessions.storage import RedisSessionBackend

        backend = RedisSessionBackend(redis_url="redis://localhost")
        backend._redis = FakeRedis(decode_responses=True)
        sid = await backend.create_session("legacy", "jti-legacy")
        record = await backend.get_session(sid)
        assert record is not None
        assert record.user_id == "legacy"
