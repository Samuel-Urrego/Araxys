"""Tests for the PostgreSQL connection pool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestPGPool:
    """Tests for PGPool (asyncpg is mocked to avoid requiring the package)."""

    @patch("asyncpg.create_pool", new_callable=AsyncMock)
    async def test_start_and_shutdown(self, mock_create_pool: AsyncMock) -> None:
        """Pool should start and shut down cleanly."""
        from araxys.db_security.pg_pool import PGPool

        mock_pool = MagicMock()
        mock_pool.close = AsyncMock()
        mock_create_pool.return_value = mock_pool

        pool = PGPool(dsn="postgresql://localhost/test", min_size=1, max_size=2)
        await pool.start()
        assert pool.pool is not None
        await pool.shutdown()
        mock_create_pool.assert_called_once()

    @patch("asyncpg.create_pool", new_callable=AsyncMock)
    async def test_health_check(self, mock_create_pool: AsyncMock) -> None:
        """Health check should execute SELECT 1."""
        from araxys.db_security.pg_pool import PGPool

        # Setup mock pool with a connection that returns 1
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = mock_conn
        mock_pool.close = AsyncMock()
        mock_create_pool.return_value = mock_pool

        pool = PGPool(dsn="postgresql://localhost/test")
        await pool.start()
        assert await pool.health()
        mock_conn.fetchval.assert_called_with("SELECT 1")
        await pool.shutdown()

    async def test_not_started_raises(self) -> None:
        """Acquiring before start should raise ConnectionError."""
        import pytest

        from araxys.core.exceptions import ConnectionError
        from araxys.db_security.pg_pool import PGPool

        pool = PGPool(dsn="postgresql://localhost/test")
        with pytest.raises(ConnectionError, match="not started"):
            await pool.acquire()

    @patch("asyncpg.create_pool", new_callable=AsyncMock)
    async def test_shutdown_idempotent(self, mock_create_pool: AsyncMock) -> None:
        """Calling shutdown twice should not crash."""
        from araxys.db_security.pg_pool import PGPool

        mock_pool = MagicMock()
        mock_pool.close = AsyncMock()
        mock_create_pool.return_value = mock_pool

        pool = PGPool(dsn="postgresql://localhost/test")
        await pool.start()
        await pool.shutdown()
        await pool.shutdown()  # should not raise

    def test_config_defaults(self) -> None:
        """Default config values should be reasonable."""
        from araxys.core.config import PgPoolConfig

        cfg = PgPoolConfig()
        assert cfg.min_size == 2
        assert cfg.max_size == 10
        assert cfg.acquire_timeout_seconds == 5.0
        assert cfg.idle_timeout_seconds == 300.0
        assert cfg.health_check_seconds == 30.0


# ── v0.14 — Dynamic Secrets Rotation: PGPool reload_dsn ─────────────────────


class TestPGPoolReloadDsn:
    """Tests for PGPool.reload_dsn() (PR 2 Pool Reload — Tasks 2.7-2.8)."""

    async def test_reload_dsn_same_dsn_noop(self) -> None:
        """Same DSN string skips reload — no pool swap."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.db_security.pg_pool import PGPool

        mock_pool = MagicMock()
        mock_pool.close = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire.return_value = mock_conn

        create_pool_calls = [0]

        async def mock_create_pool(**kwargs: object) -> MagicMock:
            create_pool_calls[0] += 1
            return mock_pool

        with patch("asyncpg.create_pool", new=AsyncMock(side_effect=mock_create_pool)):
            pool = PGPool(dsn="postgresql://localhost/test", min_size=1, max_size=2)
            await pool.start()
            try:
                original = pool._pool  # noqa: SLF001
                calls_before = create_pool_calls[0]

                await pool.reload_dsn("postgresql://localhost/test")

                # Pool unchanged
                assert pool._pool is original  # noqa: SLF001
                # No new pool created
                assert create_pool_calls[0] == calls_before
            finally:
                await pool.shutdown()

    async def test_reload_dsn_ping_failure_preserves_pool(self) -> None:
        """When new DSN PING fails, old pool is preserved and SecretRotationError raised."""  # noqa: E501
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.core.exceptions import SecretRotationError
        from araxys.db_security.pg_pool import PGPool

        mock_pool = MagicMock()
        mock_pool.close = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_pool.acquire.return_value = mock_conn

        # Mock create_pool: first call (start) succeeds, second call fails
        create_pool_calls = [0]

        async def mock_create_pool(**kwargs: object) -> MagicMock:
            create_pool_calls[0] += 1
            if create_pool_calls[0] >= 2:
                raise OSError("Connection refused")
            return mock_pool

        with patch("asyncpg.create_pool", new=AsyncMock(side_effect=mock_create_pool)):
            pool = PGPool(dsn="postgresql://localhost/test", min_size=1, max_size=2)
            await pool.start()
            try:
                original = pool._pool  # noqa: SLF001

                with pytest.raises(SecretRotationError, match="postgres"):
                    await pool.reload_dsn("postgresql://unreachable/test")

                # Old pool preserved
                assert pool._pool is original  # noqa: SLF001
            finally:
                await pool.shutdown()

    async def test_reload_dsn_prewarms_min_size(self) -> None:
        """Successful reload creates new pool with min_size connections and closes old."""  # noqa: E501
        from unittest.mock import AsyncMock, MagicMock, patch

        from araxys.db_security.pg_pool import PGPool

        # Old pool and its mocks
        old_pool = MagicMock()
        old_pool.close = AsyncMock()
        old_conn = AsyncMock()
        old_conn.fetchval = AsyncMock(return_value=1)
        old_conn.__aenter__ = AsyncMock(return_value=old_conn)
        old_conn.__aexit__ = AsyncMock(return_value=False)
        old_pool.acquire.return_value = old_conn

        # New pool (after reload)
        new_pool = MagicMock()
        new_pool.close = AsyncMock()
        new_conn = AsyncMock()
        new_conn.fetchval = AsyncMock(return_value=1)
        new_conn.__aenter__ = AsyncMock(return_value=new_conn)
        new_conn.__aexit__ = AsyncMock(return_value=False)
        new_pool.acquire.return_value = new_conn

        create_pool_calls = [0]
        created_pools: list[dict[str, object]] = []

        async def mock_create_pool(**kwargs: object) -> MagicMock:
            created_pools.append(kwargs)
            create_pool_calls[0] += 1
            if create_pool_calls[0] == 1:
                return old_pool
            return new_pool

        with patch("asyncpg.create_pool", new=AsyncMock(side_effect=mock_create_pool)):
            pool = PGPool(dsn="postgresql://localhost/test", min_size=3, max_size=10)
            await pool.start()
            try:
                await pool.reload_dsn("postgresql://newhost/test")

                # Old pool was closed
                old_pool.close.assert_awaited_once()
                # New pool is in place
                assert pool._pool is new_pool  # noqa: SLF001
                # New DSN stored
                assert pool._dsn == "postgresql://newhost/test"
                # Second create_pool call was made (temp + permanent = 2 more)
                assert create_pool_calls[0] == 3
                # Third call (permanent pool) used min_size from original config
                new_pool_kwargs = created_pools[2]
                assert new_pool_kwargs.get("min_size") == 3
            finally:
                await pool.shutdown()
