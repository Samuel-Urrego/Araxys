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
from unittest.mock import AsyncMock, patch

import pytest


class TestRedisPoolGetRedisClient:
    """Tests for RedisPool.get_redis_client()."""

    @pytest.fixture
    def pool(self):
        from araxys.db_security.pool import RedisPool

        return RedisPool(url="redis://localhost:6379")

    async def test_accessor_returns_client(self, pool) -> None:
        """get_redis_client() returns the underlying Redis client."""
        client = pool.get_redis_client()
        assert client is not None
        assert client is pool._redis  # noqa: SLF001 — testing internal

    async def test_accessor_after_close_returns_client(self, pool) -> None:
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
            p._redis.ping = mock_ping  # noqa: SLF001

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


class TestInMemoryPool:
    """Basic InMemoryPool tests for coverage."""

    @pytest.fixture
    def pool(self):
        from araxys.db_security.pool import InMemoryPool

        return InMemoryPool()

    async def test_acquire_and_release(self, pool) -> None:
        """Acquire returns a client, release decrements count."""
        conn = await pool.acquire()
        assert conn is not None
        assert pool._active == 1  # noqa: SLF001
        await pool.release(conn)
        assert pool._active == 0  # noqa: SLF001

    async def test_health(self, pool) -> None:
        """Health returns True when pool is open."""
        assert await pool.health() is True
