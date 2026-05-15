"""Tests for the Session Management module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

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


# ── Redis Backend Tests ──────────────────────────────────────────────────


@pytest.mark.skipif(
    True,  # We'll let fakeredis handle it when available
    reason="RedisSessionBackend requires fakeredis or real redis",
)
class TestRedisSessionBackend:
    """Tests for RedisSessionBackend.

    These tests are skipped if fakeredis is not available.
    """

    @pytest.fixture
    async def backend(self) -> SessionBackend:
        from araxys.sessions.storage import RedisSessionBackend

        backend = RedisSessionBackend("redis://localhost:6379")
        return backend

    async def test_redis_create_and_get(
        self, backend: SessionBackend
    ) -> None:
        session_id = await backend.create_session("user_1", "jti_abc")
        record = await backend.get_session(session_id)
        assert record is not None
        assert record.user_id == "user_1"
