"""Connection pool abstractions for database security.

Provides a ``ConnectionPool`` Protocol with ``InMemoryPool`` (for testing),
``RedisPool`` (standalone), ``RedisSentinelPool`` (Sentinel-backed), and
``RedisClusterPool`` (Cluster-backed).  All three production pools support
health checks, leak detection, idle timeout, and reconnection.

Pool selection is driven by ``RedisPoolConfig.mode``:

* ``\"standalone\"`` — :class:`RedisPool` (single ``redis.asyncio.Redis``)
* ``\"sentinel\"``   — :class:`RedisSentinelPool`
  (``redis.asyncio.sentinel.Sentinel``)
* ``\"cluster\"``    — :class:`RedisClusterPool`
  (``redis.asyncio.cluster.RedisCluster``)
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import ssl

    from araxys.db_security.query_validator import (
        QueryValidationResult,
        QueryValidator,
    )

import structlog
from redis.asyncio import Redis
from redis.asyncio.cluster import RedisCluster
from redis.asyncio.sentinel import Sentinel

from araxys.core.exceptions import (
    ConfigurationError,
    ConnectionError,
    TLSConfigurationError,
)

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

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """Validate a SQL query template for parameterization safety.

        Parameters
        ----------
        template:
            The SQL query string (may contain placeholders).
        params:
            Bound parameters, if any.

        Returns
        -------
        QueryValidationResult
            ``passed=True`` for safe queries; in ``warn`` mode,
            interpolated queries still return ``passed=True`` but with
            a descriptive ``reason``.
        """


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

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """No-op — always returns ``passed=True``."""
        from araxys.db_security.query_validator import QueryValidationResult

        return QueryValidationResult(passed=True, reason=None)

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
    * Reconnection on consecutive health-check failures
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
    health_check_interval_seconds:
        Interval between background PING checks in seconds.
    leak_threshold:
        Number of outstanding acquires that triggers a warning.
    reconnect_retries:
        Consecutive PING failures before triggering reconnection.
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
        health_check_interval_seconds: float = 30,
        leak_threshold: int = 10,
        reconnect_retries: int = 3,
        ssl_context: ssl.SSLContext | None = None,
        cert_pin_sha256: str | None = None,
        query_validator: QueryValidator | None = None,
    ) -> None:
        self.url = url
        self.max_size = max_size
        self.idle_timeout_seconds = idle_timeout_seconds
        self.acquire_timeout_seconds = acquire_timeout_seconds
        self.health_check_interval_seconds = health_check_interval_seconds
        self.leak_threshold = leak_threshold
        self._active_count: int = 0
        self._query_validator = query_validator
        self._leak_warned: bool = False
        self._closed: bool = False
        self._cert_pin_sha256: str | None = cert_pin_sha256
        self._ssl_context: ssl.SSLContext | None = ssl_context
        self._redis: Redis = Redis.from_url(url, ssl_context=ssl_context)
        self._last_active: float = time.time()
        self._health_task: asyncio.Task[None] | None = None
        self._reconnect_lock: asyncio.Lock = asyncio.Lock()
        self._reconnect_retries: int = reconnect_retries
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
                    await self._redis.ping()  # type: ignore[misc]
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
    # Query validation
    # ------------------------------------------------------------------

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """Delegate to :attr:`_query_validator` or return ``passed=True``.

        When no ``QueryValidator`` was provided at init, the validation
        is a no-op (returns ``passed=True`` with no reason).
        """
        if self._query_validator is None:
            from araxys.db_security.query_validator import (
                QueryValidationResult,
            )

            return QueryValidationResult(passed=True, reason=None)
        return self._query_validator.validate(template, params)

    # ------------------------------------------------------------------
    # Background health check
    # ------------------------------------------------------------------

    async def _health_loop(self) -> None:
        """Periodically PING Redis to verify connectivity.

        Runs in a background asyncio task. After *reconnect_retries*
        consecutive failures, a reconnection is attempted. Failures are
        logged via structlog and never propagate.
        """
        consecutive_failures = 0
        while True:
            await asyncio.sleep(self.health_check_interval_seconds)
            try:
                await self._redis.ping()  # type: ignore[misc]
                consecutive_failures = 0
            except asyncio.CancelledError:
                raise  # re-raise to let the task be cancelled cleanly
            except Exception:  # noqa: BLE001 — intentionally broad, health loop never raises
                consecutive_failures += 1
                logger.warning(
                    "db_pool.health_check_failed",
                    consecutive=consecutive_failures,
                    threshold=self._reconnect_retries,
                )
                if consecutive_failures >= self._reconnect_retries:
                    await self._reconnect()
                    consecutive_failures = 0  # reset regardless of outcome

    # ------------------------------------------------------------------
    # Reconnection
    # ------------------------------------------------------------------

    async def _reconnect(self) -> None:
        """Close the existing connection and create a new one.

        Guarded by :attr:`_reconnect_lock` to prevent thundering herd.
        On success the new client replaces ``self._redis`` and
        ``self._closed`` is reset to ``False``. On failure the old state
        is preserved and a warning is logged.
        """
        if self._reconnect_lock.locked():
            logger.info("db_pool.reconnect_skipped")
            return
        async with self._reconnect_lock:
            try:
                await self._redis.aclose()
                self._redis = Redis.from_url(
                    self.url, ssl_context=self._ssl_context,
                )
                await self._redis.ping()  # type: ignore[misc]
                self._closed = False
                logger.info("db_pool.reconnected")
            except Exception:  # noqa: BLE001 — preserve old state on failure
                logger.warning("db_pool.reconnect_failed")

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


class RedisClusterPool:
    """Pool that wraps a single ``redis.asyncio.cluster.RedisCluster``.

    Unlike :class:`RedisSentinelPool`, :meth:`acquire` returns the same
    shared ``RedisCluster`` instance every time — the cluster client
    is itself a connection manager with topology awareness.  ``release``
    only decrements the acquire counter.

    Parameters
    ----------
    startup_nodes:
        List of ``(host, port)`` pairs for cluster startup nodes.
    url:
        Redis URL for cluster (alternative to ``startup_nodes``).
    read_from_replicas:
        Allow routing read commands to replica nodes.
    max_size:
        Maximum outstanding acquires before :meth:`acquire` raises.
    health_check_interval_seconds:
        Interval between background PING checks in seconds.
    reconnect_retries:
        Consecutive health failures before triggering reconnection.
    ssl_context:
        Optional SSL context for TLS-wrapped cluster connections.
    cert_pin_sha256:
        Raises :exc:`ConfigurationError` if provided — cert pinning is not
        supported for cluster mode (RedisCluster has per-node connection
        pools which makes single-connection pin checking impractical).
    query_validator:
        Optional query validator for SQL parameterization checks.
    """

    def __init__(
        self,
        startup_nodes: list[tuple[str, int]] | None = None,
        url: str | None = None,
        *,
        read_from_replicas: bool = False,
        max_size: int = 10,
        idle_timeout_seconds: int = 300,
        acquire_timeout_seconds: float = 5.0,
        health_check_interval_seconds: float = 30,
        leak_threshold: int = 10,
        reconnect_retries: int = 3,
        ssl_context: ssl.SSLContext | None = None,
        cert_pin_sha256: str | None = None,
        query_validator: QueryValidator | None = None,
    ) -> None:
        self.startup_nodes = startup_nodes
        self.url = url
        self.read_from_replicas = read_from_replicas
        self.max_size = max_size
        self.idle_timeout_seconds = idle_timeout_seconds
        self.acquire_timeout_seconds = acquire_timeout_seconds
        self.health_check_interval_seconds = health_check_interval_seconds
        self.leak_threshold = leak_threshold
        self._active_count: int = 0
        self._query_validator = query_validator
        self._leak_warned: bool = False
        self._closed: bool = False
        if cert_pin_sha256 is not None:
            raise ConfigurationError(
                "cert_pin_sha256 is not supported for cluster mode — "
                "RedisCluster has per-node connection pools which makes "
                "single-connection pin checking impractical",
            )
        self._ssl_context: ssl.SSLContext | None = ssl_context
        self._client: RedisCluster = self._create_client()
        self._last_active: float = time.time()
        self._health_task: asyncio.Task[None] | None = None
        self._reconnect_lock: asyncio.Lock = asyncio.Lock()
        self._reconnect_retries: int = reconnect_retries
        if health_check_interval_seconds > 0:
            try:
                loop = asyncio.get_running_loop()
                self._health_task = loop.create_task(self._health_loop())
            except RuntimeError:
                pass

    def _create_client(self) -> RedisCluster:
        """Create the underlying RedisCluster client.

        Prefers ``startup_nodes`` if provided; falls back to ``url``.
        """
        if self.startup_nodes:
            return RedisCluster(
                startup_nodes=list(self.startup_nodes),  # type: ignore[arg-type]
                read_from_replicas=self.read_from_replicas,
                ssl_context=self._ssl_context,  # type: ignore[call-arg]
            )
        assert self.url is not None  # Guarded by config validation
        return RedisCluster.from_url(
            self.url,
            read_from_replicas=self.read_from_replicas,
            ssl_context=self._ssl_context,
        )

    def get_redis_client(self) -> Redis:
        """Return the underlying RedisCluster instance as a Redis client."""
        return self._client  # type: ignore[return-value]

    async def acquire(self) -> Redis:
        """Return the shared cluster client.

        The cluster client manages topology internally — no new
        connection is created per acquire.
        """
        if self._closed:
            raise ConnectionError("Pool is closed")
        if self._active_count >= self.max_size:
            raise ConnectionError("Pool exhausted")
        self._active_count += 1
        self._check_leak()
        self._last_active = time.time()
        return self._client  # type: ignore[return-value]

    async def release(self, conn: Redis) -> None:
        """Decrement the active-connection counter."""
        if self._active_count > 0:
            self._active_count -= 1
        self._leak_warned = False

    async def health(self) -> bool:
        """Check whether the cluster is reachable.

        Tries ``PING`` one startup node.  Partial failure is tolerated
        — as long as *one* node responds the cluster is considered
        healthy.  Only returns ``False`` when *no* node is reachable.
        """
        try:
            await self._client.ping()  # type: ignore[misc]
            return True
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        """Cancel the health-check task and close the cluster client."""
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        self._closed = True
        self._active_count = 0
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Query validation
    # ------------------------------------------------------------------

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """Delegate to :attr:`_query_validator` or return ``passed=True``."""
        if self._query_validator is None:
            from araxys.db_security.query_validator import (
                QueryValidationResult,
            )

            return QueryValidationResult(passed=True, reason=None)
        return self._query_validator.validate(template, params)

    # ------------------------------------------------------------------
    # Background health check
    # ------------------------------------------------------------------

    async def _health_loop(self) -> None:
        """Periodically PING the cluster."""
        consecutive_failures = 0
        while True:
            await asyncio.sleep(self.health_check_interval_seconds)
            try:
                await self._client.ping()  # type: ignore[misc]
                consecutive_failures = 0
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                consecutive_failures += 1
                logger.warning(
                    "db_pool.health_check_failed",
                    pool_type="cluster",
                    consecutive=consecutive_failures,
                    threshold=self._reconnect_retries,
                )
                if consecutive_failures >= self._reconnect_retries:
                    await self._reconnect()
                    consecutive_failures = 0

    # ------------------------------------------------------------------
    # Reconnection
    # ------------------------------------------------------------------

    async def _reconnect(self) -> None:
        """Close the existing cluster client and create a new one.

        Guarded by :attr:`_reconnect_lock`.
        """
        if self._reconnect_lock.locked():
            logger.info("db_pool.reconnect_skipped", pool_type="cluster")
            return
        async with self._reconnect_lock:
            try:
                await self._client.aclose()
                self._client = self._create_client()
                await self._client.ping()  # type: ignore[misc]
                self._closed = False
                logger.info("db_pool.reconnected", pool_type="cluster")
            except Exception:  # noqa: BLE001
                logger.warning("db_pool.reconnect_failed", pool_type="cluster")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_leak(self) -> None:
        """Emit a structlog warning if active count exceeds threshold."""
        if self._active_count >= self.leak_threshold and not self._leak_warned:
            logger.warning(
                "db_pool.leak_detected",
                pool_type="cluster",
                active=self._active_count,
                threshold=self.leak_threshold,
                msg=f"Cluster pool has {self._active_count} outstanding connections "
                f"(threshold={self.leak_threshold})",
            )
            self._leak_warned = True

class RedisSentinelPool:
    """Pool that wraps ``redis.asyncio.sentinel.Sentinel``.

    Each call to :meth:`acquire` obtains a fresh Redis client via
    ``sentinel.master_for(master_name)``.  The Sentinel instance itself
    manages connections to the Sentinel nodes and tracks the current
    master.

    Parameters
    ----------
    sentinels:
        List of ``(host, port)`` pairs for Sentinel monitor nodes.
    master_name:
        Name of the master service in Sentinel configuration.
    max_size:
        Maximum outstanding acquires before :meth:`acquire` raises.
    idle_timeout_seconds:
        Unused; reserved for future TTL enforcement.
    acquire_timeout_seconds:
        Unused; reserved for future acquire-timeout support.
    health_check_interval_seconds:
        Interval between background PING checks in seconds.
    leak_threshold:
        Number of outstanding acquires that triggers a warning.
    reconnect_retries:
        Consecutive health failures before triggering reconnection.
    ssl_context:
        Optional SSL context for TLS-wrapped connections.
    cert_pin_sha256:
        Optional SHA-256 fingerprint for server certificate pinning.
    query_validator:
        Optional query validator for SQL parameterization checks.
    """

    def __init__(
        self,
        sentinels: list[tuple[str, int]],
        master_name: str,
        *,
        max_size: int = 10,
        idle_timeout_seconds: int = 300,
        acquire_timeout_seconds: float = 5.0,
        health_check_interval_seconds: float = 30,
        leak_threshold: int = 10,
        reconnect_retries: int = 3,
        ssl_context: ssl.SSLContext | None = None,
        cert_pin_sha256: str | None = None,
        query_validator: QueryValidator | None = None,
    ) -> None:
        self.sentinels = sentinels
        self.master_name = master_name
        self.max_size = max_size
        self.idle_timeout_seconds = idle_timeout_seconds
        self.acquire_timeout_seconds = acquire_timeout_seconds
        self.health_check_interval_seconds = health_check_interval_seconds
        self.leak_threshold = leak_threshold
        self._active_count: int = 0
        self._query_validator = query_validator
        self._leak_warned: bool = False
        self._closed: bool = False
        self._cert_pin_sha256: str | None = cert_pin_sha256
        self._ssl_context: ssl.SSLContext | None = ssl_context
        self._sentinel: Sentinel = Sentinel(  # type: ignore[no-untyped-call]
            sentinels,
            ssl_context=ssl_context,
        )
        self._health_client: Redis = self._sentinel.master_for(master_name)
        self._last_active: float = time.time()
        self._health_task: asyncio.Task[None] | None = None
        self._reconnect_lock: asyncio.Lock = asyncio.Lock()
        self._reconnect_retries: int = reconnect_retries
        if health_check_interval_seconds > 0:
            try:
                loop = asyncio.get_running_loop()
                self._health_task = loop.create_task(self._health_loop())
            except RuntimeError:
                pass

    def get_redis_client(self) -> Redis:
        """Return a Redis client via ``master_for``.

        Uses the dedicated health client so callers can execute Redis
        commands without needing to ``acquire`` first.
        """
        return self._health_client

    async def acquire(self) -> Redis:
        """Obtain a Redis client via ``sentinel.master_for(master_name)``.

        Each call creates a new client handle from the Sentinel, ensuring
        it points to the current master even after a failover.

        Raises
        ------
        ConnectionError:
            If the pool is closed, exhausted, or the health check fails.
        """
        if self._closed:
            raise ConnectionError("Pool is closed")
        if self._active_count >= self.max_size:
            raise ConnectionError("Pool exhausted")
        self._active_count += 1
        self._check_leak()
        client = self._sentinel.master_for(self.master_name)
        if self._cert_pin_sha256:
            await self._verify_cert_pin(client)
        if time.time() - self._last_active > self.idle_timeout_seconds:
            try:
                await client.ping()
            except Exception as exc:
                raise ConnectionError(
                    f"Connection idle timeout — PING failed: {exc}",
                ) from exc
        self._last_active = time.time()
        return client  # type: ignore[no-any-return]

    async def release(self, conn: Redis) -> None:
        """Decrement the active-connection counter.

        The Redis client handle from ``master_for`` is lightweight — we
        simply discard it after releasing.  redis-py's SentinelConnectionPool
        manages the actual connection lifecycle.
        """
        if self._active_count > 0:
            self._active_count -= 1
        self._leak_warned = False

    async def health(self) -> bool:
        """PING the dedicated health client.

        Returns ``True`` if the health client responds, ``False``
        otherwise.
        """
        try:
            await self._health_client.ping()  # type: ignore[misc]
            return True
        except Exception:  # noqa: BLE001 — intentionally broad
            return False

    async def close(self) -> None:
        """Cancel the health-check task and close all resources."""
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        self._closed = True
        self._active_count = 0
        await self._health_client.aclose()

    # ------------------------------------------------------------------
    # Query validation
    # ------------------------------------------------------------------

    def validate_query(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """Delegate to :attr:`_query_validator` or return ``passed=True``."""
        if self._query_validator is None:
            from araxys.db_security.query_validator import (
                QueryValidationResult,
            )

            return QueryValidationResult(passed=True, reason=None)
        return self._query_validator.validate(template, params)

    # ------------------------------------------------------------------
    # Background health check
    # ------------------------------------------------------------------

    async def _health_loop(self) -> None:
        """Periodically PING the health client.

        Runs in a background asyncio task.  After *reconnect_retries*
        consecutive failures a reconnection is attempted.
        """
        consecutive_failures = 0
        while True:
            await asyncio.sleep(self.health_check_interval_seconds)
            try:
                await self._health_client.ping()  # type: ignore[misc]
                consecutive_failures = 0
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                consecutive_failures += 1
                logger.warning(
                    "db_pool.health_check_failed",
                    pool_type="sentinel",
                    consecutive=consecutive_failures,
                    threshold=self._reconnect_retries,
                )
                if consecutive_failures >= self._reconnect_retries:
                    await self._reconnect()
                    consecutive_failures = 0

    # ------------------------------------------------------------------
    # Reconnection
    # ------------------------------------------------------------------

    async def _reconnect(self) -> None:
        """Close the existing sentinel client and create a new one.

        Guarded by :attr:`_reconnect_lock` to prevent thundering herd.
        """
        if self._reconnect_lock.locked():
            logger.info("db_pool.reconnect_skipped", pool_type="sentinel")
            return
        async with self._reconnect_lock:
            try:
                await self._health_client.aclose()
                self._sentinel = Sentinel(  # type: ignore[no-untyped-call]
                    self.sentinels,
                    ssl_context=self._ssl_context,
                )
                self._health_client = self._sentinel.master_for(self.master_name)
                await self._health_client.ping()  # type: ignore[misc]
                self._closed = False
                logger.info("db_pool.reconnected", pool_type="sentinel")
            except Exception:  # noqa: BLE001
                logger.warning("db_pool.reconnect_failed", pool_type="sentinel")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_leak(self) -> None:
        """Emit a structlog warning if active count exceeds threshold."""
        if self._active_count >= self.leak_threshold and not self._leak_warned:
            logger.warning(
                "db_pool.leak_detected",
                pool_type="sentinel",
                active=self._active_count,
                threshold=self.leak_threshold,
                msg=f"Sentinel pool has {self._active_count} outstanding connections "
                f"(threshold={self.leak_threshold})",
            )
            self._leak_warned = True

    async def _verify_cert_pin(self, conn: Redis) -> None:
        """Verify the server certificate's SHA-256 fingerprint.

        Parameters
        ----------
        conn:
            The Redis client whose connection should be checked.

        Raises
        ------
        TLSConfigurationError:
            If the connection does not use TLS, no peer certificate is
            available, or the fingerprint does not match the pin.
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
                assert self._cert_pin_sha256 is not None
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
