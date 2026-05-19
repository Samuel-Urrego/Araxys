"""Tests for the Session Management module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from redis.asyncio import Redis

    from araxys.sessions.storage import SessionBackend


# ── SessionRecord Tests ──────────────────────────────────────────────────


class TestSessionRecord:
    """Tests for SessionRecord dataclass."""

    def test_session_record_creation(self) -> None:
        """SessionRecord should store session_id, user_id, jti, created_at, metadata."""
        from araxys.sessions.storage import SessionRecord

        now = datetime.now(UTC)
        record = SessionRecord(
            session_id="sess_abc123",
            user_id="user_1",
            jti="jti_xyz",
            created_at=now,
            metadata={"ip": "127.0.0.1"},
        )
        assert record.session_id == "sess_abc123"
        assert record.user_id == "user_1"
        assert record.jti == "jti_xyz"
        assert record.created_at == now
        assert record.metadata == {"ip": "127.0.0.1"}

    def test_session_record_default_metadata(self) -> None:
        """SessionRecord metadata should default to empty dict."""
        from araxys.sessions.storage import SessionRecord

        record = SessionRecord(
            session_id="sess_1",
            user_id="user_1",
            jti="jti_1",
            created_at=datetime.now(UTC),
        )
        assert record.metadata == {}

    def test_expires_at_defaults_to_none(self) -> None:
        """SessionRecord.expires_at should default to None."""
        from araxys.sessions.storage import SessionRecord

        record = SessionRecord(
            session_id="sess_1",
            user_id="user_1",
            jti="jti_1",
            created_at=datetime.now(UTC),
        )
        assert record.expires_at is None

    def test_expires_at_can_be_set(self) -> None:
        """SessionRecord.expires_at can be set to a float timestamp."""
        from araxys.sessions.storage import SessionRecord

        now = datetime.now(UTC)
        future = time.time() + 3600
        record = SessionRecord(
            session_id="sess_1",
            user_id="user_1",
            jti="jti_1",
            created_at=now,
            expires_at=future,
        )
        assert record.expires_at == future
        assert isinstance(record.expires_at, float)


# ── SessionConfig Tests ──────────────────────────────────────────────────


class TestSessionConfig:
    """Tests for SessionConfig."""

    def test_session_ttl_seconds_default(self) -> None:
        """SessionConfig.session_ttl_seconds should default to 3600."""
        from araxys.core.config import SessionConfig

        config = SessionConfig()
        assert config.session_ttl_seconds == 3600

    def test_session_ttl_seconds_can_be_set(self) -> None:
        """SessionConfig.session_ttl_seconds can be overridden."""
        from araxys.core.config import SessionConfig

        config = SessionConfig(session_ttl_seconds=7200)
        assert config.session_ttl_seconds == 7200


# ── InMemory Backend Tests ───────────────────────────────────────────────


class TestInMemorySessionBackend:
    """Tests for InMemorySessionBackend."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend()

    async def test_create_session_returns_session_id(
        self, backend: SessionBackend
    ) -> None:
        """create_session should return a session_id string."""
        session_id = await backend.create_session("user_1", "jti_abc")
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    async def test_get_session_returns_record(
        self, backend: SessionBackend
    ) -> None:
        """get_session should return the SessionRecord after creation."""
        session_id = await backend.create_session(
            "user_1", "jti_abc", {"ip": "1.2.3.4"}
        )
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.session_id == session_id
        assert record.user_id == "user_1"
        assert record.jti == "jti_abc"
        assert record.metadata == {"ip": "1.2.3.4"}

    async def test_get_session_unknown_returns_none(
        self, backend: SessionBackend
    ) -> None:
        """get_session should return None for unknown session_id."""
        record = await backend.get_session("nonexistent")
        assert record is None

    async def test_list_sessions_returns_user_sessions(
        self, backend: SessionBackend
    ) -> None:
        """list_sessions should return all sessions for a user."""
        await backend.create_session("user_1", "jti_1")
        await backend.create_session("user_1", "jti_2")
        await backend.create_session("user_2", "jti_3")

        sessions = await backend.list_sessions("user_1")
        assert len(sessions) == 2
        assert all(s.user_id == "user_1" for s in sessions)
        jtis = {s.jti for s in sessions}
        assert jtis == {"jti_1", "jti_2"}

    async def test_list_sessions_empty_for_unknown_user(
        self, backend: SessionBackend
    ) -> None:
        """list_sessions should return empty list for user with no sessions."""
        sessions = await backend.list_sessions("nobody")
        assert sessions == []

    async def test_count_sessions_returns_correct_count(
        self, backend: SessionBackend
    ) -> None:
        """count_sessions should return the number of sessions per user."""
        await backend.create_session("user_1", "jti_1")
        await backend.create_session("user_1", "jti_2")
        await backend.create_session("user_2", "jti_3")

        assert await backend.count_sessions("user_1") == 2
        assert await backend.count_sessions("user_2") == 1
        assert await backend.count_sessions("nobody") == 0

    async def test_revoke_session_removes_session(
        self, backend: SessionBackend
    ) -> None:
        """revoke_session should remove the session and return True."""
        session_id = await backend.create_session("user_1", "jti_abc")
        assert await backend.get_session(session_id) is not None

        result = await backend.revoke_session(session_id)
        assert result is True
        assert await backend.get_session(session_id) is None

    async def test_revoke_session_unknown_returns_false(
        self, backend: SessionBackend
    ) -> None:
        """revoke_session should return False for unknown session_id."""
        result = await backend.revoke_session("nonexistent")
        assert result is False

    async def test_revoke_session_removes_from_user_list(
        self, backend: SessionBackend
    ) -> None:
        """After revoke, the session should not appear in list_sessions."""
        sid1 = await backend.create_session("user_1", "jti_1")
        await backend.create_session("user_1", "jti_2")

        await backend.revoke_session(sid1)
        sessions = await backend.list_sessions("user_1")
        assert len(sessions) == 1
        assert sessions[0].jti == "jti_2"

    async def test_revoke_oldest_removes_earliest_session(
        self, backend: SessionBackend
    ) -> None:
        """revoke_oldest should remove the session with the oldest created_at."""
        sid1 = await backend.create_session("user_1", "jti_1")
        await backend.create_session("user_1", "jti_2")
        await backend.create_session("user_1", "jti_3")

        # sid1 should be oldest since it was created first
        revoked = await backend.revoke_oldest("user_1")
        assert revoked == sid1

        remaining = await backend.list_sessions("user_1")
        assert len(remaining) == 2
        assert all(s.session_id != sid1 for s in remaining)

    async def test_revoke_oldest_returns_none_for_empty_user(
        self, backend: SessionBackend
    ) -> None:
        """revoke_oldest should return None when user has no sessions."""
        result = await backend.revoke_oldest("nobody")
        assert result is None


class TestInMemorySessionBackendWithTTL:
    """Tests for InMemorySessionBackend with session_ttl_seconds."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend(session_ttl_seconds=3600)

    async def test_create_session_sets_expires_at(
        self, backend: SessionBackend
    ) -> None:
        """create_session should set expires_at with TTL when configured."""
        before = time.time()
        session_id = await backend.create_session("user_1", "jti_abc")
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.expires_at is not None
        # expires_at should be approximately before + 3600
        assert record.expires_at >= before + 3550  # allow small timing diff
        assert record.expires_at <= before + 3650

    async def test_create_session_no_ttl_still_sets_expires_at(
        self, backend: SessionBackend
    ) -> None:
        """create_session always sets expires_at; zero TTL means immediate expiry."""
        from araxys.sessions.storage import InMemorySessionBackend

        zero_ttl = InMemorySessionBackend(session_ttl_seconds=0)
        session_id = await zero_ttl.create_session("user_1", "jti_abc")
        record = await zero_ttl.get_session(session_id)
        assert record is not None
        assert record.expires_at is not None


# ── SessionManager Tests ────────────────────────────────────────────────


class TestSessionManager:
    """Tests for SessionManager."""

    @pytest.fixture
    def config(self) -> object:
        from araxys.core.config import SessionConfig

        return SessionConfig(max_concurrent_per_user=2, cleanup_interval_seconds=300)

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend()

    @pytest.fixture
    def event_bus(self) -> MagicMock:
        bus = MagicMock()
        bus.emit = AsyncMock()
        return bus

    async def test_create_returns_session_id(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.create should return a session_id string."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        session_id = await manager.create("user_1", "jti_abc")
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    async def test_create_emits_session_created_event(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.create should emit SESSION_CREATED SecurityEvent."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        await manager.create("user_1", "jti_abc")

        event_bus.emit.assert_awaited_once()
        call_call = event_bus.emit.await_args
        assert call_call is not None
        call_args, call_kwds = call_call
        event = call_args[0]
        assert event.event_type.value == "session_created"
        assert event.metadata.get("user_id") == "user_1"

    async def test_create_enforces_max_concurrent_revokes_oldest(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """When max_concurrent reached, SessionManager should revoke oldest session."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        # max_concurrent_per_user = 2
        await manager.create("user_1", "jti_1")
        await manager.create("user_1", "jti_2")

        # Reset mock to ignore previous emits
        event_bus.emit.reset_mock()

        # Third session should trigger revocation of the oldest
        session_id = await manager.create("user_1", "jti_3")

        sessions = await backend.list_sessions("user_1")
        assert len(sessions) == 2  # Only 2 remain
        # The third session should be in the list
        assert any(s.session_id == session_id for s in sessions)

        # A SECURITY event should have been emitted for the revoke
        # emit was called for SESSION_REVOKED (from revoke) + SESSION_CREATED
        assert event_bus.emit.await_count == 2

    async def test_revoke_emits_session_revoked_event(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.revoke should emit SESSION_REVOKED SecurityEvent."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        session_id = await manager.create("user_1", "jti_abc")
        event_bus.emit.reset_mock()

        result = await manager.revoke(session_id)
        assert result is True

        event_bus.emit.assert_awaited_once()
        call_call = event_bus.emit.await_args
        assert call_call is not None
        call_args, call_kwds = call_call
        event = call_args[0]
        assert event.event_type.value == "session_revoked"

    async def test_revoke_returns_false_for_unknown(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.revoke should return False for unknown session."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        result = await manager.revoke("nonexistent")
        assert result is False
        event_bus.emit.assert_not_called()

    async def test_list_returns_user_sessions(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.list should return sessions for a user."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        await manager.create("user_1", "jti_1")
        await manager.create("user_1", "jti_2")

        sessions = await manager.list("user_1")
        assert len(sessions) == 2

    async def test_count_returns_correct_number(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.count should return number of sessions."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        await manager.create("user_1", "jti_1")
        await manager.create("user_1", "jti_2")

        assert await manager.count("user_1") == 2

    async def test_start_stop_cleanup(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager cleanup task should start and stop gracefully."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        await manager.start_cleanup()
        # Should be running
        assert manager._cleanup_task is not None
        assert not manager._cleanup_task.done()

        await manager.stop_cleanup()
        # Should be stopped/cancelled
        assert manager._cleanup_task is None or manager._cleanup_task.done()

    async def test_refresh_session_returns_bool(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.refresh_session should return True for valid session."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        session_id = await manager.create("user_1", "jti_abc")
        result = await manager.refresh_session(session_id)
        assert result is True

    async def test_refresh_session_unknown_returns_false(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """SessionManager.refresh_session should return False for unknown."""
        from araxys.sessions.manager import SessionManager

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]
        result = await manager.refresh_session("nonexistent")
        assert result is False


# ── Redis Backend Tests ──────────────────────────────────────────────────


try:
    from fakeredis.aioredis import FakeRedis  # noqa: F401
    _HAS_FAKEREDIS = True
except ImportError:
    _HAS_FAKEREDIS = False


@pytest.mark.skipif(
    not _HAS_FAKEREDIS,
    reason="RedisSessionBackend tests require fakeredis",
)
class TestRedisSessionBackend:
    """Tests for RedisSessionBackend using _SharedRedisPool.

    Requires fakeredis; skipped if not available.
    """

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import RedisSessionBackend

        yield RedisSessionBackend(pool=_SharedRedisPool())

    async def test_redis_create_and_get(
        self, backend: SessionBackend
    ) -> None:
        session_id = await backend.create_session("user_1", "jti_abc")
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.user_id == "user_1"


# ── Metadata serialization tests (v0.6) ────────────────────────────────────


class _SharedRedisPool:
    """Test pool that reuses a single FakeRedis instance."""

    def __init__(self) -> None:
        from fakeredis.aioredis import FakeRedis

        self._redis = FakeRedis(decode_responses=True)
        self._max_size = 10
        self._active = 0

    async def acquire(self) -> Redis:
        if self._active >= self._max_size:
            raise ConnectionError("Pool exhausted")
        self._active += 1
        return self._redis

    async def release(self, conn: Redis) -> None:
        if self._active > 0:
            self._active -= 1

    async def health(self) -> bool:
        return True

    def get_redis_client(self) -> Redis:
        return self._redis

    async def close(self) -> None:
        self._active = 0


class TestInMemorySessionBackendCleanup:
    """Tests for InMemorySessionBackend cleanup of expired sessions."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend(session_ttl_seconds=3600)

    async def test_cleanup_removes_expired_session(
        self, backend: SessionBackend
    ) -> None:
        """cleanup_expired should remove sessions past their TTL."""
        from araxys.sessions.storage import InMemorySessionBackend

        assert isinstance(backend, InMemorySessionBackend)
        # Create a session and manually set expires_at in the past
        session_id = await backend.create_session("user_1", "jti_abc")
        backend._sessions[session_id].expires_at = 0.0  # long expired

        removed = await backend.cleanup_expired()
        assert removed == 1
        record = await backend.get_session(session_id)
        assert record is None

    async def test_cleanup_no_expired_is_noop(
        self, backend: SessionBackend
    ) -> None:
        """cleanup_expired with no expired sessions should return 0."""
        await backend.create_session("user_1", "jti_1")
        await backend.create_session("user_1", "jti_2")

        removed = await backend.cleanup_expired()
        assert removed == 0
        sessions = await backend.list_sessions("user_1")
        assert len(sessions) == 2

    async def test_cleanup_handles_mixed_expired(
        self, backend: SessionBackend
    ) -> None:
        """cleanup_expired should remove only expired sessions."""
        from araxys.sessions.storage import InMemorySessionBackend

        fresh_id = await backend.create_session("user_1", "jti_fresh")
        stale_id = await backend.create_session("user_1", "jti_stale")
        assert isinstance(backend, InMemorySessionBackend)
        backend._sessions[stale_id].expires_at = 0.0  # expired

        removed = await backend.cleanup_expired()
        assert removed == 1

        # Fresh session should still exist
        assert await backend.get_session(fresh_id) is not None
        # Stale session should be gone
        assert await backend.get_session(stale_id) is None


class TestSessionManagerCleanupLoop:
    """Tests for SessionManager._cleanup_loop()."""

    @pytest.fixture
    def config(self) -> object:
        from araxys.core.config import SessionConfig

        return SessionConfig(max_concurrent_per_user=5, cleanup_interval_seconds=60)

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend(session_ttl_seconds=3600)

    @pytest.fixture
    def event_bus(self) -> MagicMock:
        bus = MagicMock()
        bus.emit = AsyncMock()
        return bus

    async def test_cleanup_loop_calls_backend_cleanup_expired(
        self, config: object, backend: SessionBackend, event_bus: MagicMock
    ) -> None:
        """_cleanup_loop should call backend.cleanup_expired()."""
        from araxys.sessions.manager import SessionManager
        from araxys.sessions.storage import InMemorySessionBackend

        manager = SessionManager(config, backend, event_bus)  # type: ignore[arg-type]

        # Create an expired session
        session_id = await backend.create_session("user_1", "jti_abc")
        if isinstance(backend, InMemorySessionBackend):
            backend._sessions[session_id].expires_at = 0.0

        # Reset the loop interval so it fires quickly
        manager._cleanup_interval = 0.01  # type: ignore[assignment]
        await manager.start_cleanup()

        # Wait for at least one loop iteration
        import asyncio

        await asyncio.sleep(0.05)
        await manager.stop_cleanup()

        # The expired session should be cleaned
        record = await backend.get_session(session_id)
        assert record is None


class TestInMemorySessionBackendRefresh:
    """Tests for InMemorySessionBackend.refresh_session()."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import InMemorySessionBackend

        yield InMemorySessionBackend(session_ttl_seconds=3600)

    async def test_refresh_updates_expires_at(
        self, backend: SessionBackend
    ) -> None:
        """refresh_session should update expires_at to a later time."""
        session_id = await backend.create_session("user_1", "jti_abc")
        record_before = await backend.get_session(session_id)
        assert record_before is not None
        original_expires = record_before.expires_at

        # Small delay to ensure time difference
        import asyncio

        await asyncio.sleep(0.01)
        result = await backend.refresh_session(session_id)
        assert result is True

        record_after = await backend.get_session(session_id)
        assert record_after is not None
        assert record_after.expires_at is not None
        assert record_after.expires_at > original_expires  # type: ignore[operator]

    async def test_refresh_unknown_returns_false(
        self, backend: SessionBackend
    ) -> None:
        """refresh_session on unknown session_id should return False."""
        result = await backend.refresh_session("nonexistent")
        assert result is False


class TestRedisSessionBackendRefresh:
    """Tests for RedisSessionBackend.refresh_session()."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import RedisSessionBackend

        yield RedisSessionBackend(pool=_SharedRedisPool(), session_ttl_seconds=3600)

    async def test_refresh_resets_ttl_on_both_keys(
        self, backend: SessionBackend
    ) -> None:
        """refresh_session should reset EXPIRE on both session and user keys."""
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            session_id = await backend.create_session("user_1", "jti_abc")
            skey = f"araxys:sessions:{session_id}"
            ukey = "araxys:sessions:user:user_1"

            ttl_before = await conn.ttl(skey)

            result = await backend.refresh_session(session_id)
            assert result is True

            ttl_after = await conn.ttl(skey)
            assert ttl_after >= ttl_before, (
                f"TTL should reset, got {ttl_after} < {ttl_before}"
            )

            ukey_ttl = await conn.ttl(ukey)
            assert ukey_ttl > 0, f"User key TTL should be > 0, got {ukey_ttl}"
        finally:
            await pool.release(conn)

    async def test_refresh_unknown_returns_false(
        self, backend: SessionBackend
    ) -> None:
        """refresh_session on unknown session_id should return False."""
        result = await backend.refresh_session("nonexistent")
        assert result is False


class TestRedisSessionBackendTTL:
    """Tests for RedisSessionBackend EXPIRE behavior (v0.7)."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import RedisSessionBackend

        yield RedisSessionBackend(pool=_SharedRedisPool(), session_ttl_seconds=3600)

    async def test_create_session_sets_ttl_on_session_key(
        self, backend: SessionBackend
    ) -> None:
        """create_session should set EXPIRE on the session HASH key."""
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            session_id = await backend.create_session("user_1", "jti_abc")
            skey = f"araxys:sessions:{session_id}"
            ttl = await conn.ttl(skey)
            assert ttl > 0, f"Expected TTL > 0 for {skey}, got {ttl}"
        finally:
            await pool.release(conn)

    async def test_create_session_sets_ttl_on_user_key(
        self, backend: SessionBackend
    ) -> None:
        """create_session should set EXPIRE on the user SET key."""
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            await backend.create_session("user_1", "jti_abc")
            ukey = "araxys:sessions:user:user_1"
            ttl = await conn.ttl(ukey)
            assert ttl > 0, f"Expected TTL > 0 for {ukey}, got {ttl}"
        finally:
            await pool.release(conn)

    async def test_revoke_session_has_no_expire(
        self, backend: SessionBackend
    ) -> None:
        """revoke_session pipeline must NOT contain EXPIRE."""
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            session_id = await backend.create_session("user_1", "jti_abc")
            await backend.revoke_session(session_id)
            # After revoke, the session key should not exist (DEL, not EXPIRE)
            skey = f"araxys:sessions:{session_id}"
            exists = await conn.exists(skey)
            assert exists == 0, "Session key should be DELeted, not expired"
        finally:
            await pool.release(conn)

    async def test_cleanup_removes_orphaned_user_set_member(
        self, backend: SessionBackend
    ) -> None:
        """cleanup_expired should remove orphaned session IDs from user SET."""
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            session_id = await backend.create_session("user_1", "jti_abc")
            skey = f"araxys:sessions:{session_id}"
            ukey = "araxys:sessions:user:user_1"

            # Simulate the session HASH being gone (as if Redis EXPIRE removed it)
            await conn.delete(skey)

            # Run cleanup — should detect orphaned member and remove it
            removed = await backend.cleanup_expired()
            assert removed >= 1, "Cleanup should remove the orphaned member"

            # The user SET should no longer contain the orphaned session_id
            members = await conn.smembers(ukey)  # type: ignore[misc]
            norm: set[str] = cast("set[str]", members)
            assert session_id not in norm
        finally:
            await pool.release(conn)


class TestRedisSessionBackendMetadata:
    """Tests for JSON metadata serialization fix (Task 1.1, v0.6).

    Uses _SharedRedisPool (fakeredis) to test without a real Redis.
    """

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[SessionBackend]:
        from araxys.sessions.storage import RedisSessionBackend

        yield RedisSessionBackend(pool=_SharedRedisPool())

    async def test_metadata_round_trip_dict(
        self, backend: SessionBackend
    ) -> None:
        """Round-trip with dict metadata preserves all values."""
        session_id = await backend.create_session(
            "user_1", "jti_1", metadata={"key": 42, "nested": [1, 2], "flag": True}
        )
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.metadata == {"key": 42, "nested": [1, 2], "flag": True}

    async def test_metadata_round_trip_list(
        self, backend: SessionBackend
    ) -> None:
        """Round-trip with list inside dict metadata."""
        session_id = await backend.create_session(
            "user_1", "jti_2", metadata={"items": [1, "two", 3.0]}
        )
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.metadata == {"items": [1, "two", 3.0]}

    async def test_metadata_round_trip_int(
        self, backend: SessionBackend
    ) -> None:
        """Round-trip with int inside dict metadata."""
        session_id = await backend.create_session(
            "user_1", "jti_3", metadata={"value": 42}
        )
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.metadata == {"value": 42}

    async def test_empty_metadata_becomes_empty_dict(
        self, backend: SessionBackend
    ) -> None:
        """None metadata is stored as {}."""
        session_id = await backend.create_session("user_1", "jti_4")
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.metadata == {}

    async def test_datetime_in_metadata_does_not_raise(
        self, backend: SessionBackend
    ) -> None:
        """datetime object in metadata serializes via default=str."""
        session_id = await backend.create_session(
            "user_1", "jti_5", metadata={"now": datetime.now(UTC)}
        )
        record = await backend.get_session(session_id)
        assert record is not None
        assert "now" in record.metadata

    async def test_old_single_quote_format_recovery(
        self, backend: SessionBackend
    ) -> None:
        """Old str() format (single-quoted) loads via ast.literal_eval fallback."""
        session_id = await backend.create_session(
            "user_1", "jti_6", metadata={"clean": "data"}
        )
        # Directly write old-format metadata to simulate pre-fix data
        from araxys.sessions.storage import RedisSessionBackend

        assert isinstance(backend, RedisSessionBackend)
        pool = backend._pool
        assert isinstance(pool, _SharedRedisPool)
        conn = await pool.acquire()
        try:
            key = f"araxys:sessions:{session_id}"
            # Write single-quoted repr like old str() would produce
            await conn.hset(key, "metadata", "{'clean': 'data'}")  # type: ignore[misc]
        finally:
            await pool.release(conn)

        record = await backend.get_session(session_id)
        assert record is not None
        assert record.metadata == {"clean": "data"}
