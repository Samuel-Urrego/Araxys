"""Tests for the PostgreSQL connection pool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch


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
