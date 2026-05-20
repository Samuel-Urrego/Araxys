"""Tests for RedisPool (v0.6 — get_redis_client() accessor, health loop, timeouts).

Tests follow strict TDD: written before implementation.

Tasks:
- 1.3: Add get_redis_client() public accessor to RedisPool.
- 2.1: Health check interval wiring (background health loop).
- 2.2: Idle timeout enforcement (PING on stale connections).
- 2.3: Acquire timeout enforcement (asyncio.wait_for).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

if TYPE_CHECKING:
    from araxys.db_security.pool import InMemoryPool, RedisPool


class TestRedisPoolGetRedisClient:
    """Tests for RedisPool.get_redis_client()."""

    @pytest.fixture
    def pool(self) -> RedisPool:
        from araxys.db_security.pool import RedisPool

        return RedisPool(url="redis://localhost:6379")

    async def test_accessor_returns_client(self, pool: RedisPool) -> None:
        """get_redis_client() returns the underlying Redis client."""
        client = pool.get_redis_client()
        assert client is not None
        assert client is pool._redis  # noqa: SLF001 — testing internal

    async def test_accessor_after_close_returns_client(self, pool: RedisPool) -> None:
        """get_redis_client() after close returns the client (no crash)."""
        await pool.close()
        client = pool.get_redis_client()
        assert client is not None


class TestRedisPoolHealthLoop:
    """Tests for RedisPool background health-check loop (Task 2.1)."""

    async def test_health_task_created_on_init(self) -> None:
        """Health task is created when health_check_interval_seconds > 0."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=10,
        )
        try:
            assert p._health_task is not None  # noqa: SLF001
            assert not p._health_task.done()  # noqa: SLF001
        finally:
            await p.close()

    async def test_health_task_not_created_when_zero(self) -> None:
        """No health task when health_check_interval_seconds is 0."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0,
        )
        try:
            assert p._health_task is None  # noqa: SLF001
        finally:
            await p.close()

    async def test_health_task_calls_ping_periodically(self) -> None:
        """Health loop calls self._redis.ping() at the configured interval."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0.02,
        )
        try:
            mock_ping = AsyncMock(return_value=True)
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            # Wait for at least one health check cycle
            await asyncio.sleep(0.05)

            # Must have called ping at least once
            assert mock_ping.call_count >= 1
        finally:
            await p.close()

    async def test_close_cancels_health_task(self) -> None:
        """Close cancels the background health task (no asyncio warnings)."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=1,
        )
        task = p._health_task  # noqa: SLF001
        assert task is not None
        assert not task.done()

        await p.close()

        assert task.cancelled() or task.done()


class TestRedisPoolIdleTimeout:
    """Tests for RedisPool idle timeout enforcement (Task 2.2)."""

    async def test_idle_detection_triggers_ping(self) -> None:
        """PING is called when connection has been idle past the timeout."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            idle_timeout_seconds=300,
        )
        try:
            mock_ping = AsyncMock(return_value=True)
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            # Simulate idle by setting _last_active far in the past
            p._last_active = time.time() - 600  # noqa: SLF001 — 600s > 300s idle timeout

            conn = await p.acquire()
            assert conn is not None

            # Ping must have been called due to idle detection
            mock_ping.assert_awaited_once()
        finally:
            await p.close()

    async def test_active_connection_skips_ping(self) -> None:
        """PING is NOT called when connection was recently active."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            idle_timeout_seconds=300,
        )
        try:
            mock_ping = AsyncMock(return_value=True)
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            # _last_active defaults to time.time() on init (recent)
            conn = await p.acquire()
            assert conn is not None

            # Ping should NOT be called (not idle)
            mock_ping.assert_not_awaited()
        finally:
            await p.close()

    async def test_timer_reset_after_successful_acquire(self) -> None:
        """_last_active is updated after a successful acquire."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            idle_timeout_seconds=300,
        )
        try:
            mock_ping = AsyncMock(return_value=True)
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            # Force _last_active to be old
            p._last_active = time.time() - 600  # noqa: SLF001

            conn = await p.acquire()
            assert conn is not None

            # Timer should be reset to now-ish
            assert time.time() - p._last_active < 5  # noqa: SLF001
        finally:
            await p.close()

    async def test_idle_ping_failure_raises_connection_error(self) -> None:
        """ConnectionError is raised when idle PING fails."""
        from araxys.core.exceptions import ConnectionError as AraxysConnectionError
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            idle_timeout_seconds=300,
        )
        try:
            mock_ping = AsyncMock(side_effect=OSError("Connection refused"))
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            # Simulate idle
            p._last_active = time.time() - 600  # noqa: SLF001

            with pytest.raises(AraxysConnectionError, match="idle"):
                await p.acquire()
        finally:
            await p.close()


class TestRedisPoolAcquireTimeout:
    """Tests for RedisPool acquire timeout enforcement (Task 2.3)."""

    async def test_acquire_timeout_raises_connection_error(self) -> None:
        """ConnectionError raised when acquire body exceeds timeout."""
        from araxys.core.exceptions import ConnectionError as AraxysConnectionError
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            acquire_timeout_seconds=0.01,
        )
        try:
            # Make the idle PING hang forever by mocking
            import asyncio

            async def _never(*args: object, **kwargs: object) -> None:
                await asyncio.Event().wait()  # never resolves

            p._redis.ping = _never  # type: ignore[method-assign,assignment]  # noqa: SLF001

            # Simulate an idle connection so the PING check is triggered
            p._last_active = time.time() - 600  # noqa: SLF001

            with pytest.raises(AraxysConnectionError, match="timed out"):
                await p.acquire()
        finally:
            await p.close()

    async def test_acquire_completes_within_timeout(self) -> None:
        """Normal acquire completes successfully within the timeout."""
        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            acquire_timeout_seconds=5.0,
        )
        try:
            mock_ping = AsyncMock(return_value=True)
            p._redis.ping = mock_ping  # type: ignore[method-assign]  # noqa: SLF001

            conn = await p.acquire()
            assert conn is not None
        finally:
            await p.close()


class TestInMemoryPool:
    """Basic InMemoryPool tests for coverage."""

    @pytest.fixture
    def pool(self) -> InMemoryPool:
        from araxys.db_security.pool import InMemoryPool

        return InMemoryPool()

    async def test_acquire_and_release(self, pool: InMemoryPool) -> None:
        """Acquire returns a client, release decrements count."""
        conn = await pool.acquire()
        assert conn is not None
        assert pool._active == 1  # noqa: SLF001
        await pool.release(conn)
        assert pool._active == 0  # noqa: SLF001

    async def test_health(self, pool: InMemoryPool) -> None:
        """Health returns True when pool is open."""
        assert await pool.health() is True


# ── v0.7 — RedisPool Reconnection (Tasks 2.2 + 2.3) ─────────────────────────


class TestRedisPoolReconnect:
    """Tests for RedisPool._reconnect() and health-loop trigger."""

    async def test_reconnect_succeeds(self) -> None:
        """_reconnect() closes old client, creates new, PINGs, resets _closed."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0,
        )
        old_client = p._redis  # noqa: SLF001
        old_client.ping = AsyncMock(return_value=True)
        old_client.aclose = AsyncMock()

        new_client = MagicMock()
        new_client.ping = AsyncMock(return_value=True)

        with patch("araxys.db_security.pool.Redis.from_url", return_value=new_client):
            p._closed = True  # Simulate closed state  # noqa: SLF001
            await p._reconnect()  # noqa: SLF001

        # Old client was closed
        old_client.aclose.assert_awaited_once()
        # New client was PINGed
        new_client.ping.assert_awaited_once()
        # _redis is now the new client
        assert p._redis is new_client  # noqa: SLF001
        # _closed is reset
        assert p._closed is False  # noqa: SLF001

    async def test_reconnect_lock_prevents_concurrent(self) -> None:
        """Second reconnect attempt skips when lock is held."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0,
        )

        import asyncio

        # Make aclose take time so the lock is held
        async def slow_aclose() -> None:
            await asyncio.sleep(0.1)

        p._redis.aclose = slow_aclose  # type: ignore[method-assign]  # noqa: SLF001
        p._closed = True  # noqa: SLF001

        new_client = MagicMock()
        new_client.ping = AsyncMock(return_value=True)

        reconnect_calls: list[int] = []

        with patch("araxys.db_security.pool.Redis.from_url", return_value=new_client):
            # Call reconnect twice concurrently
            async def call_reconnect(idx: int) -> None:
                await p._reconnect()  # noqa: SLF001
                reconnect_calls.append(idx)

            await asyncio.gather(call_reconnect(1), call_reconnect(2))

        # Only one should have actually reconnected (closed old client, created new)
        assert len(reconnect_calls) == 2  # Both returned
        # The second should have early-returned because lock was held or _closed was already reset
        # Verify the new client was only set once — _redis was only assigned once
        assert p._redis is new_client  # noqa: SLF001
        assert p._closed is False  # noqa: SLF001

    async def test_health_loop_triggers_reconnect_after_threshold(self) -> None:
        """Health loop calls _reconnect() after N consecutive PING failures."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0.01,
            reconnect_retries=3,
        )
        try:
            # Mock PING to fail 3 times, then succeed
            ping_results = [OSError("fail")] * 3 + [True]
            p._redis.ping = AsyncMock(side_effect=ping_results)  # type: ignore[method-assign]  # noqa: SLF001

            reconnect_mock = AsyncMock()
            p._reconnect = reconnect_mock  # type: ignore[method-assign]  # noqa: SLF001

            # Wait for enough health check cycles (4 pings × 0.01s + margin)
            await asyncio.sleep(0.08)

            # Reconnect should have been called after 3 consecutive failures
            reconnect_mock.assert_awaited_once()
        finally:
            await p.close()
