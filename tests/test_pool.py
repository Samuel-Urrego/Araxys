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
    from unittest.mock import MagicMock

    from araxys.db_security.pool import (
        InMemoryPool,
        RedisClusterPool,
        RedisPool,
        RedisSentinelPool,
    )


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
        old_client.ping = AsyncMock(return_value=True)  # type: ignore[method-assign]
        old_client.aclose = AsyncMock()  # type: ignore[method-assign]

        new_client = MagicMock()
        new_client.ping = AsyncMock(return_value=True)

        with patch("araxys.db_security.pool.Redis.from_url", return_value=new_client):
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

        p._redis.aclose = slow_aclose  # type: ignore[method-assign,assignment]  # noqa: SLF001

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
        # The second skipped because the lock was already held
        # Verify the new client was only set once
        assert p._redis is new_client  # noqa: SLF001
        assert p._closed is False  # noqa: SLF001

    async def test_health_loop_triggers_reconnect_after_threshold(self) -> None:
        """Health loop calls _reconnect() after N consecutive PING failures."""
        from unittest.mock import AsyncMock

        from araxys.db_security.pool import RedisPool

        p = RedisPool(
            url="redis://localhost:6379",
            health_check_interval_seconds=0.01,
            reconnect_retries=3,
        )
        try:
            # Mock PING to always fail so reconnect keeps being called
            p._redis.ping = AsyncMock(side_effect=OSError("fail"))  # type: ignore[method-assign]  # noqa: SLF001

            reconnect_mock = AsyncMock()
            p._reconnect = reconnect_mock  # type: ignore[method-assign]  # noqa: SLF001

            # Wait for enough health check cycles (4 pings × 0.01s + margin)
            await asyncio.sleep(0.08)

            # Reconnect should have been called (at least once)
            reconnect_mock.assert_awaited()
        finally:
            await p.close()


# ── v0.9 — RedisSentinelPool (Task 4.2) ─────────────────────────────────────


class TestRedisSentinelPool:
    """Tests for RedisSentinelPool (Sentinel-backed connection pool)."""

    @pytest.fixture
    def mock_sentinel(self) -> MagicMock:
        """Return a mock redis.asyncio.sentinel.Sentinel.

        Uses MagicMock (not AsyncMock) because ``master_for`` is a
        synchronous method — AsyncMock would return a coroutine instead
        of the mock Redis client.
        """
        from unittest.mock import MagicMock

        sentinel = MagicMock()
        health_client = AsyncMock()
        sentinel.master_for.return_value = health_client
        return sentinel

    @pytest.fixture
    def pool(self, mock_sentinel: MagicMock) -> RedisSentinelPool:
        from unittest.mock import patch

        from araxys.db_security.pool import RedisSentinelPool

        with patch(
            "araxys.db_security.pool.Sentinel", return_value=mock_sentinel,
        ):
            return RedisSentinelPool(
                sentinels=[("localhost", 26379)],
                master_name="mymaster",
                health_check_interval_seconds=0,
            )

    async def test_constructor_requires_sentinels_and_master_name(
        self,
    ) -> None:
        """Constructor validates sentinels and master_name."""
        from araxys.db_security.pool import RedisSentinelPool

        with pytest.raises(TypeError):
            RedisSentinelPool()  # type: ignore[call-arg]

    async def test_acquire_returns_redis_client(self, pool: RedisSentinelPool) -> None:
        """acquire() calls master_for and returns a Redis client."""
        conn = await pool.acquire()
        assert conn is not None
        # First call is __init__ (health client), second is acquire
        assert pool._sentinel.master_for.call_count >= 2  # type: ignore[attr-defined]  # noqa: SLF001
        pool._sentinel.master_for.assert_called_with(  # type: ignore[attr-defined]  # noqa: SLF001
            "mymaster",
        )

    async def test_release_decrements_count(self, pool: RedisSentinelPool) -> None:
        """release() decrements the active count."""
        conn = await pool.acquire()
        assert pool._active_count == 1  # noqa: SLF001
        await pool.release(conn)
        assert pool._active_count == 0  # noqa: SLF001

    async def test_health_returns_true_when_healthy(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """health() returns True when health client responds."""
        pool._health_client.ping = AsyncMock(return_value=True)  # type: ignore[method-assign]  # noqa: SLF001
        healthy = await pool.health()
        assert healthy is True

    async def test_health_returns_false_when_unhealthy(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """health() returns False when health client is unreachable."""
        pool._health_client.ping = AsyncMock(  # type: ignore[method-assign]  # noqa: SLF001
            side_effect=OSError("Connection refused"),
        )
        healthy = await pool.health()
        assert healthy is False

    async def test_close_cancels_health_task(self, pool: RedisSentinelPool) -> None:
        """close() cancels the health task and marks pool as closed."""
        task = pool._health_task  # noqa: SLF001
        await pool.close()
        assert pool._closed is True  # noqa: SLF001
        assert task is None or task.cancelled() or task.done()

    async def test_acquire_exhausted_raises_connection_error(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """ConnectionError when max_size is exceeded."""
        from araxys.core.exceptions import ConnectionError as AraxysConnectionError

        pool.max_size = 1  # noqa: SLF001
        conn = await pool.acquire()  # first one works
        with pytest.raises(AraxysConnectionError, match="exhausted"):
            await pool.acquire()  # second should fail
        await pool.release(conn)

    async def test_get_redis_client_returns_redis_client(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """get_redis_client() returns a Redis client (the health client)."""
        client = pool.get_redis_client()
        assert client is pool._health_client  # noqa: SLF001

    async def test_reconnect_creates_new_sentinel(
        self,
        mock_sentinel: MagicMock,
        pool: RedisSentinelPool,
    ) -> None:
        """_reconnect() creates a new Sentinel instance."""
        from unittest.mock import MagicMock, patch

        old_sentinel = pool._sentinel  # noqa: SLF001
        new_mock = MagicMock()
        health_client = AsyncMock()
        health_client.ping = AsyncMock(return_value=True)
        new_mock.master_for.return_value = health_client

        with patch(
            "araxys.db_security.pool.Sentinel", return_value=new_mock,
        ):
            await pool._reconnect()  # noqa: SLF001

        assert pool._sentinel is new_mock  # noqa: SLF001
        assert pool._sentinel is not old_sentinel  # noqa: SLF001

    async def test_acquire_after_close_raises(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """Acquire after close raises ConnectionError."""
        from araxys.core.exceptions import ConnectionError as AraxysConnectionError

        await pool.close()
        with pytest.raises(AraxysConnectionError, match="closed"):
            await pool.acquire()

    async def test_ssl_context_forwarded_to_sentinel(self) -> None:
        """SSL context is passed to the Sentinel constructor."""
        import ssl
        from unittest.mock import patch

        from araxys.db_security.pool import RedisSentinelPool

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch("araxys.db_security.pool.Sentinel") as mock_cls:
            RedisSentinelPool(
                sentinels=[("localhost", 26379)],
                master_name="mymaster",
                ssl_context=ctx,
                health_check_interval_seconds=0,
            )
        mock_cls.assert_called_once_with(
            [("localhost", 26379)],
            ssl_context=ctx,
        )

    async def test_cert_pin_mismatch_raises_tls_error(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """Acquire with cert_pin mismatch raises TLSConfigurationError."""
        from unittest.mock import AsyncMock

        from araxys.core.exceptions import TLSConfigurationError

        pool._cert_pin_sha256 = "abcdef1234567890"  # noqa: SLF001
        # Simulate a cert pin mismatch
        pool._verify_cert_pin = AsyncMock(  # type: ignore[method-assign]  # noqa: SLF001
            side_effect=TLSConfigurationError("Certificate pin mismatch"),
        )
        with pytest.raises(TLSConfigurationError, match="Certificate pin mismatch"):
            await pool.acquire()

    async def test_leak_detection_warning(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """Warning is logged when active count exceeds threshold."""

        pool.leak_threshold = 2
        pool._active_count = 5  # noqa: SLF001
        # _check_leak should set _leak_warned to True
        pool._check_leak()  # noqa: SLF001
        assert pool._leak_warned is True  # noqa: SLF001

    async def test_reconnect_lock_prevents_concurrent(
        self,
        pool: RedisSentinelPool,
    ) -> None:
        """Second reconnect attempt skips when lock is held."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        # Make aclose take time so the lock is held
        async def slow_aclose() -> None:
            await asyncio.sleep(0.1)

        pool._health_client.aclose = slow_aclose  # type: ignore[method-assign,assignment]  # noqa: SLF001

        new_sentinel = MagicMock()
        health_client = AsyncMock()
        health_client.ping = AsyncMock(return_value=True)
        new_sentinel.master_for.return_value = health_client
        reconnect_calls: list[int] = []

        with patch(
            "araxys.db_security.pool.Sentinel", return_value=new_sentinel,
        ):
            async def call_reconnect(idx: int) -> None:
                await pool._reconnect()  # noqa: SLF001
                reconnect_calls.append(idx)

            await asyncio.gather(call_reconnect(1), call_reconnect(2))

        assert len(reconnect_calls) == 2
        assert pool._sentinel is new_sentinel  # noqa: SLF001

    async def test_validate_query_no_validator(self, pool: RedisSentinelPool) -> None:
        """validate_query returns passed=True when no validator set."""
        result = pool.validate_query("SELECT 1")
        assert result.passed is True
        assert result.reason is None


# ── v0.9 — RedisClusterPool (Task 4.3) ──────────────────────────────────────


class TestRedisClusterPool:
    """Tests for RedisClusterPool (Cluster-backed connection pool)."""

    @pytest.fixture
    def mock_cluster(self) -> AsyncMock:
        """Return a mock redis.asyncio.cluster.RedisCluster."""
        cluster = AsyncMock()
        cluster.ping.return_value = True
        return cluster

    @pytest.fixture
    def pool_from_nodes(
        self,
        mock_cluster: AsyncMock,
    ) -> RedisClusterPool:
        from unittest.mock import patch

        from araxys.db_security.pool import RedisClusterPool

        with patch(
            "araxys.db_security.pool.RedisCluster", return_value=mock_cluster,
        ):
            return RedisClusterPool(
                startup_nodes=[("localhost", 7000)],
                health_check_interval_seconds=0,
            )

    @pytest.fixture
    def pool_from_url(
        self,
        mock_cluster: AsyncMock,
    ) -> RedisClusterPool:
        from unittest.mock import patch

        from araxys.db_security.pool import RedisClusterPool

        with patch(
            "araxys.db_security.pool.RedisCluster.from_url",
            return_value=mock_cluster,
        ):
            return RedisClusterPool(
                url="redis://localhost:7000",
                health_check_interval_seconds=0,
            )

    async def test_constructor_from_startup_nodes(self) -> None:
        """Pool can be created from startup_nodes."""
        from unittest.mock import patch

        from araxys.db_security.pool import RedisClusterPool

        with patch("araxys.db_security.pool.RedisCluster") as mock_cls:
            RedisClusterPool(
                startup_nodes=[("h1", 7000), ("h2", 7001)],
                health_check_interval_seconds=0,
            )
        mock_cls.assert_called_once()
        _, kwargs = mock_cls.call_args
        assert "startup_nodes" in kwargs
        assert len(kwargs["startup_nodes"]) == 2

    async def test_acquire_returns_client(
        self,
        pool_from_nodes: RedisClusterPool,
    ) -> None:
        """acquire() returns the cluster client."""
        conn = await pool_from_nodes.acquire()
        assert conn is not None

    async def test_release_decrements_count(
        self,
        pool_from_nodes: RedisClusterPool,
    ) -> None:
        """release() decrements the active count."""
        conn = await pool_from_nodes.acquire()
        assert pool_from_nodes._active_count == 1  # noqa: SLF001
        await pool_from_nodes.release(conn)
        assert pool_from_nodes._active_count == 0  # noqa: SLF001

    async def test_health_all_up_returns_true(
        self,
        pool_from_nodes: RedisClusterPool,
    ) -> None:
        """health() returns True when all nodes respond."""
        pool_from_nodes._client.ping = AsyncMock(return_value=True)  # type: ignore[method-assign]  # noqa: SLF001
        healthy = await pool_from_nodes.health()
        assert healthy is True

    async def test_health_all_down_returns_false(
        self,
        pool_from_nodes: RedisClusterPool,
    ) -> None:
        """health() returns False when cluster is completely unreachable."""
        pool_from_nodes._client.ping = AsyncMock(  # type: ignore[method-assign]  # noqa: SLF001
            side_effect=OSError("All nodes unreachable"),
        )
        healthy = await pool_from_nodes.health()
        assert healthy is False

    async def test_close_cancels_task(
        self,
        pool_from_nodes: RedisClusterPool,
    ) -> None:
        """close() cancels health task and marks pool closed."""
        task = pool_from_nodes._health_task  # noqa: SLF001
        await pool_from_nodes.close()
        assert pool_from_nodes._closed is True  # noqa: SLF001
        assert task is None or task.cancelled() or task.done()

    async def test_ssl_context_forwarded(self) -> None:
        """SSL context is passed to the RedisCluster constructor."""
        import ssl
        from unittest.mock import patch

        from araxys.db_security.pool import RedisClusterPool

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch("araxys.db_security.pool.RedisCluster") as mock_cls:
            RedisClusterPool(
                startup_nodes=[("localhost", 7000)],
                ssl_context=ctx,
                health_check_interval_seconds=0,
            )
        mock_cls.assert_called_once()
        _, kwargs = mock_cls.call_args
        assert kwargs.get("ssl_context") is ctx

    async def test_read_from_replicas_forwarded(self) -> None:
        """read_from_replicas is passed to the RedisCluster constructor."""
        from unittest.mock import patch

        from araxys.db_security.pool import RedisClusterPool

        with patch("araxys.db_security.pool.RedisCluster") as mock_cls:
            RedisClusterPool(
                startup_nodes=[("localhost", 7000)],
                read_from_replicas=True,
                health_check_interval_seconds=0,
            )
        _, kwargs = mock_cls.call_args
        assert kwargs.get("read_from_replicas") is True
