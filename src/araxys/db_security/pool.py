"""Connection pool abstractions for database security.

Provides a ``ConnectionPool`` Protocol with ``InMemoryPool`` (for testing)
and ``RedisPool`` (wraps ``redis.asyncio.Redis`` with health checks,
leak detection, and idle timeout).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import ssl

import structlog
from redis.asyncio import Redis

from araxys.core.exceptions import ConnectionError

logger = structlog.get_logger("araxys.db_security.pool")


@runtime_checkable
class ConnectionPool(Protocol):
    """A pool of database connections.

    Implementations must provide acquire/release semantics, a health
    check, and a clean shutdown.
    """

    async def acquire(self) -> Redis:
        """Obtain a connection from the pool.

        Raises:
            ConnectionError: If the pool is exhausted or unhealthy.
        """
        ...

    async def release(self, conn: Redis) -> None:
        """Return a connection to the pool."""

    async def health(self) -> bool:
        """Check whether the pool is healthy (e.g. can reach Redis)."""

    async def close(self) -> None:
        """Close all connections and release resources."""


class InMemoryPool:
    """No-op pool for testing.

    Tracks acquire/release counts and enforces max_size.
    Acquire returns a :class:`fakeredis.FakeRedis` instance so callers
    can interact with it as a real Redis client.
    """

    def __init__(self, max_size: int = 10) -> None:
        self.max_size = max_size
        self._active: int = 0
        self._closed: bool = False

    async def acquire(self) -> Redis:
        """Return a FakeRedis instance, or raise if exhausted/closed."""
        if self._closed:
            raise ConnectionError("Pool is closed")
        if self._active >= self.max_size:
            raise ConnectionError("Pool exhausted")
        self._active += 1
        from fakeredis.aioredis import FakeRedis

        return FakeRedis(decode_responses=True)

    async def release(self, conn: Redis) -> None:
        """Return a connection (decrement active count)."""
        if self._active > 0:
            self._active -= 1

    async def health(self) -> bool:
        """Return True unless the pool has been closed."""
        return not self._closed

    async def close(self) -> None:
        """Mark the pool as closed and reset active count."""
        self._closed = True
        self._active = 0


class RedisPool:
    """Production pool that wraps a single ``redis.asyncio.Redis`` client.

    redis-py handles the actual connection multiplexing. This class adds:
    * Health checks (``PING`` via :meth:`health`)
    * Leak detection (acquire/release counters with a warning threshold)
    * Max-size enforcement (configurable limit on outstanding
      acquires)
    * Clean shutdown

    Parameters
    ----------
    url:
        Redis connection URL (e.g. ``redis://localhost:6379/0``).
    max_size:
        Maximum outstanding acquires before :meth:`acquire` raises.
    idle_timeout_seconds:
        Unused; reserved for future TTL enforcement at the pool level.
    acquire_timeout_seconds:
        Unused; reserved for future acquire-timeout support.
    leak_threshold:
        Number of outstanding acquires that triggers a warning.
    ssl_context:
        Optional SSL context for TLS-wrapped Redis connections.
    """

    def __init__(
        self,
        url: str,
        *,
        max_size: int = 10,
        idle_timeout_seconds: int = 300,
        acquire_timeout_seconds: float = 5.0,
        leak_threshold: int = 10,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.url = url
        self.max_size = max_size
        self.idle_timeout_seconds = idle_timeout_seconds
        self.acquire_timeout_seconds = acquire_timeout_seconds
        self.leak_threshold = leak_threshold
        self._active_count: int = 0
        self._leak_warned: bool = False
        self._closed: bool = False
        self._redis: Redis = Redis.from_url(url, ssl_context=ssl_context)

    async def acquire(self) -> Redis:
        """Return the underlying Redis client (or raise if exhausted)."""
        if self._closed:
            raise ConnectionError("Pool is closed")
        if self._active_count >= self.max_size:
            raise ConnectionError("Pool exhausted")
        self._active_count += 1
        self._check_leak()
        return self._redis

    async def release(self, conn: Redis) -> None:
        """Decrement the active-connection counter."""
        if self._active_count > 0:
            self._active_count -= 1
        self._leak_warned = False  # reset so warning can fire again

    async def health(self) -> bool:
        """Run a PING check against Redis.

        Returns ``True`` if the server responds, ``False`` otherwise.
        """
        try:
            await self._redis.ping()  # type: ignore[misc]
            return True
        except Exception:  # noqa: BLE001 — intentionally broad, health is a boolean
            return False

    async def close(self) -> None:
        """Close the underlying Redis client and reset state."""
        self._closed = True
        self._active_count = 0
        await self._redis.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_leak(self) -> None:
        """Emit a structlog warning if active count exceeds threshold."""
        if self._active_count >= self.leak_threshold and not self._leak_warned:
            logger.warning(
                "db_pool.leak_detected",
                active=self._active_count,
                threshold=self.leak_threshold,
                msg=f"Pool has {self._active_count} outstanding connections "
                f"(threshold={self.leak_threshold})",
            )
            self._leak_warned = True
