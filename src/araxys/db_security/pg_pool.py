"""PostgreSQL connection pool with TLS and health checks.

Requires ``asyncpg`` (optional dependency).  Install with::

    pip install araxys[postgres]

The pool wraps ``asyncpg.create_pool()`` and adds:
- TLS/SSL configuration
- Periodic health checks (connection liveness)
- Acquire timeouts
- Graceful shutdown
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import structlog

from araxys.core.exceptions import ConnectionError, SecretRotationError

if TYPE_CHECKING:
    import ssl

logger = structlog.get_logger("araxys.db_security.pg_pool")


class PGPool:
    """PostgreSQL async connection pool.

    Parameters
    ----------
    dsn:
        PostgreSQL connection string or keyword arguments to
        ``asyncpg.create_pool()``.
    min_size:
        Minimum number of connections (default 2).
    max_size:
        Maximum number of connections (default 10).
    acquire_timeout:
        Seconds to wait for a connection before raising (default 5).
    idle_timeout:
        Seconds before idle connections are closed (default 300).
    health_check_interval:
        Seconds between liveness checks (default 30).
    ssl_context:
        Optional ``ssl.SSLContext`` for TLS connections.
    **kwargs:
        Additional keyword arguments passed to ``asyncpg.create_pool()``.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        min_size: int = 2,
        max_size: int = 10,
        acquire_timeout: float = 5.0,
        idle_timeout: float = 300.0,
        health_check_interval: float = 30.0,
        ssl_context: ssl.SSLContext | None = None,
        **kwargs: Any,
    ) -> None:
        self._dsn = dsn
        self._pool_kwargs = {
            "min_size": min_size,
            "max_size": max_size,
            "timeout": acquire_timeout,
            "max_inactive_connection_lifetime": idle_timeout,
            "ssl": ssl_context,
            **kwargs,
        }
        if dsn:
            self._pool_kwargs["dsn"] = dsn

        self._pool: Any = None
        self._health_interval = health_check_interval
        self._health_task: asyncio.Task[None] | None = None
        self._running = False

    # ── Lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Create the pool and start health checks."""
        try:
            import asyncpg
        except ImportError as exc:
            raise ImportError(
                "PGPool requires the 'asyncpg' package. "
                "Install it with: pip install asyncpg"
            ) from exc

        self._pool = await asyncpg.create_pool(**self._pool_kwargs)
        self._running = True
        self._health_task = asyncio.create_task(self._health_loop())
        logger.info(
            "pg_pool.started",
            min_size=self._pool_kwargs.get("min_size"),
            max_size=self._pool_kwargs.get("max_size"),
        )

    async def shutdown(self) -> None:
        """Close all connections and stop health checks."""
        self._running = False
        if self._health_task is not None:
            self._health_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_task
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        logger.info("pg_pool.shutdown")

    # ── Connection Management ──────────────────────────────────────

    async def acquire(self) -> Any:
        """Acquire a connection from the pool.

        Returns an ``asyncpg.Connection``.
        """
        if self._pool is None:
            raise ConnectionError("PGPool is not started")
        try:
            conn = await asyncio.wait_for(
                self._pool.acquire(), timeout=self._pool_kwargs.get("timeout", 5)
            )
            return conn
        except TimeoutError:
            raise ConnectionError(
                "Timed out waiting for PostgreSQL connection"
            ) from None

    async def release(self, conn: Any) -> None:
        """Release a connection back to the pool."""
        if self._pool is not None:
            await self._pool.release(conn)

    async def health(self) -> bool:
        """Check pool health by executing ``SELECT 1``."""
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                result: Any = await conn.fetchval("SELECT 1")
                return result == 1  # type: ignore[no-any-return]
        except Exception:
            logger.warning("pg_pool.health_check_failed")
            return False

    async def fetch(self, query: str, *args: Any) -> list[Any]:
        """Execute a query and return all rows.

        Convenience method that acquires, executes, and releases.
        """
        if self._pool is None:
            raise ConnectionError("PGPool is not started")
        async with self._pool.acquire() as conn:
            rows: list[Any] = await conn.fetch(query, *args)
            return rows

    async def execute(self, query: str, *args: Any) -> str:
        """Execute a query and return the status string."""
        if self._pool is None:
            raise ConnectionError("PGPool is not started")
        async with self._pool.acquire() as conn:
            status: str = await conn.execute(query, *args)
            return status

    # ── Internal ───────────────────────────────────────────────────

    async def _health_loop(self) -> None:
        """Periodic health check loop."""
        consecutive_failures = 0
        while self._running:
            await asyncio.sleep(self._health_interval)
            try:
                ok = await self.health()
                if not ok:
                    consecutive_failures += 1
                    logger.warning(
                        "pg_pool.health_check_failed",
                        consecutive=consecutive_failures,
                    )
                else:
                    consecutive_failures = 0
            except Exception:
                logger.exception("pg_pool.health_loop_error")

    # ── Dynamic secrets rotation — reload_dsn ─────────────────────────

    async def reload_dsn(self, dsn: str) -> None:
        """Reload the pool with a new PostgreSQL DSN.

        Validates the new DSN by creating a temporary pool and executing
        ``SELECT 1``. On success, closes the old pool, creates a new
        one with the configured ``min_size`` (pre-warming), and swaps.

        Raises :exc:`SecretRotationError` if the new DSN is unreachable.
        """
        if dsn == self._dsn:
            return

        # Validate the new DSN with a temporary pool + SELECT 1.
        try:
            import asyncpg
        except ImportError as exc:
            raise ImportError(
                "PGPool requires the 'asyncpg' package. "
                "Install it with: pip install asyncpg"
            ) from exc

        new_kwargs = dict(self._pool_kwargs)
        new_kwargs["dsn"] = dsn

        temp_pool = None
        try:
            temp_pool = await asyncpg.create_pool(**new_kwargs)
            async with temp_pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                if result != 1:
                    raise SecretRotationError(
                        "postgres",
                        reason=f"New DSN health check failed: SELECT 1 returned {result}",
                    )
        except SecretRotationError:
            raise
        except Exception as exc:
            raise SecretRotationError(
                "postgres", reason=f"New DSN unreachable: {exc}",
            ) from exc
        finally:
            if temp_pool is not None:
                await temp_pool.close()

        # Swap: close old pool, replace with new.
        old_pool = self._pool
        self._dsn = dsn
        self._pool_kwargs = new_kwargs
        self._pool = await asyncpg.create_pool(**self._pool_kwargs)
        self._running = True
        if old_pool is not None:
            await old_pool.close()
        logger.info("pg_pool.reload_dsn", dsn=dsn)

    # ── Properties ────────────────────────────────────────────────────

    @property
    def pool(self) -> Any | None:
        """Access the underlying ``asyncpg.Pool`` instance."""
        return self._pool
