"""Tests for RedisPool (v0.6 — get_redis_client() accessor).

Tests follow strict TDD: written before implementation.

Task 1.3: Add get_redis_client() public accessor to RedisPool.
"""

from __future__ import annotations

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
