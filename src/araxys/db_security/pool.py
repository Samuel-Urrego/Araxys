"""Connection pool abstractions for database security.

Provides a ``ConnectionPool`` Protocol with ``InMemoryPool`` (for testing)
and ``RedisPool`` (wraps ``redis.asyncio.Redis`` with health checks,
leak detection, and idle timeout).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import ssl

import structlog
from redis.asyncio import Redis

from araxys.core.exceptions import ConnectionError, TLSConfigurationError

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

    def get_redis_client(self) -> Redis:
        """Public accessor for the underlying Redis client.

        Returns the :class:`redis.asyncio.Redis` instance used by this
        pool. Callers should not mutate the client directly.
        """
        ...

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

    def get_redis_client(self) -> Redis:
        """Return a new FakeRedis instance."""
        from fakeredis.aioredis import FakeRedis

        return FakeRedis(decode_responses=True)

    async def acquire(self) -> Redis:
        """Return a FakeRedis instance, or raise if exhausted/closed."""
        if self._closed:
            raise ConnectionError("Pool is closed")
        if self._active >= self.max_size:
            raise ConnectionError("Pool exhausted")
        self._active += 1
        return self.get_redis_client()

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
    cert_pin_sha256:
        Optional SHA-256 fingerprint of the expected server certificate.
        When set, :meth:`acquire` verifies the server cert matches the
        pin before returning the connection. Raises
        :exc:`TLSConfigurationError` on mismatch.
    """

    def __init__(
        self,
        url: str,
        *,
        max_size: int = 10,
        idle_timeout_seconds: int = 300,
        acquire_timeout_seconds: float = 5.0,
        health_check_interval_seconds: int = 30,
        leak_threshold: int = 10,
        ssl_context: ssl.SSLContext | None = None,
        cert_pin_sha256: str | None = None,
    ) -> None:
        self.url = url
        self.max_size = max_size
        self.idle_timeout_seconds = idle_timeout_seconds
        self.acquire_timeout_seconds = acquire_timeout_seconds
        self.health_check_interval_seconds = health_check_interval_seconds
        self.leak_threshold = leak_threshold
        self._active_count: int = 0
        self._leak_warned: bool = False
        self._closed: bool = False
        self._cert_pin_sha256: str | None = cert_pin_sha256
        self._redis: Redis = Redis.from_url(url, ssl_context=ssl_context)
        self._last_active: float = time.time()
        self._health_task: asyncio.Task | None = None
        if health_check_interval_seconds > 0:
            try:
                loop = asyncio.get_running_loop()
                self._health_task = loop.create_task(self._health_loop())
            except RuntimeError:
                # No running event loop (e.g. at import time) — health
                # loop is a best-effort optimization, not required.
                pass

    def get_redis_client(self) -> Redis:
        """Public accessor for the underlying Redis client.

        Returns the :class:`redis.asyncio.Redis` instance used by this
        pool. Callers should not mutate the client directly.
        """
        return self._redis

    async def acquire(self) -> Redis:
        """Return the underlying Redis client (or raise if exhausted).

        Enforces ``acquire_timeout_seconds`` via :func:`asyncio.wait_for`.
        Raises :exc:`araxys.core.exceptions.ConnectionError` on timeout.
        """

        async def _acquire_body() -> Redis:
            if self._closed:
                raise ConnectionError("Pool is closed")
            if self._active_count >= self.max_size:
                raise ConnectionError("Pool exhausted")
            self._active_count += 1
            self._check_leak()
            if self._cert_pin_sha256:
                await self._verify_cert_pin(self._redis)
            # Idle timeout: PING if the connection has been idle too long.
            if time.time() - self._last_active > self.idle_timeout_seconds:
                try:
                    await self._redis.ping()
                except Exception as exc:
                    raise ConnectionError(
                        f"Connection idle timeout — PING failed: {exc}",
                    ) from exc
            self._last_active = time.time()
            return self._redis

        try:
            return await asyncio.wait_for(
                _acquire_body(), timeout=self.acquire_timeout_seconds,
            )
        except TimeoutError as err:
            raise ConnectionError("Acquire timed out") from err

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
        """Cancel the health-check task and close the underlying Redis client."""
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        self._closed = True
        self._active_count = 0
        await self._redis.aclose()

    # ------------------------------------------------------------------
    # Background health check
    # ------------------------------------------------------------------

    async def _health_loop(self) -> None:
        """Periodically PING Redis to verify connectivity.

        Runs in a background asyncio task. Failures are logged via
        structlog and never propagate.
        """
        while True:
            await asyncio.sleep(self.health_check_interval_seconds)
            try:
                await self._redis.ping()
            except asyncio.CancelledError:
                raise  # re-raise to let the task be cancelled cleanly
            except Exception:  # noqa: BLE001 — intentionally broad, health loop never raises
                logger.warning("db_pool.health_check_failed")

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

    async def _verify_cert_pin(self, conn: Redis) -> None:
        """Verify the server certificate's SHA-256 fingerprint.

        Retrieves the peer certificate from the underlying asyncio
        connection, computes its SHA-256 digest, and compares against
        the pinned value stored in ``self._cert_pin_sha256``.

        Parameters
        ----------
        conn:
            The Redis client whose connection should be checked.

        Raises
        ------
        TLSConfigurationError:
            - If the connection does not use TLS.
            - If no peer certificate is available.
            - If the certificate fingerprint does not match the pin.
        """
        try:
            connection = conn.connection_pool.get_connection(  # type: ignore[no-untyped-call]
                "_pin_check",
            )
            try:
                if not connection.is_connected:
                    await connection.connect()

                writer = getattr(connection, "_writer", None)
                if writer is None:
                    raise TLSConfigurationError(
                        "TLS is not enabled on this connection",
                    )

                ssl_object = writer.get_extra_info("ssl_object")
                if ssl_object is None:
                    raise TLSConfigurationError(
                        "TLS is not enabled on this connection",
                    )

                cert_der = ssl_object.getpeercert(binary_form=True)
                if not cert_der:
                    raise TLSConfigurationError(
                        "No peer certificate available",
                    )

                cert_sha256 = hashlib.sha256(cert_der).hexdigest()
                assert self._cert_pin_sha256 is not None  # Guard ensures this
                if cert_sha256 != self._cert_pin_sha256:
                    raise TLSConfigurationError(
                        f"Certificate pin mismatch: expected "
                        f"sha256={self._cert_pin_sha256[:16]}..., "
                        f"got sha256={cert_sha256[:16]}...",
                    )
            finally:
                await conn.connection_pool.release(connection)
        except TLSConfigurationError:
            raise
        except Exception as exc:
            raise TLSConfigurationError(
                f"Cannot verify certificate pin: {exc}",
            ) from exc
