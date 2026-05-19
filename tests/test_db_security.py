"""Tests for db_security/pool.py and db_security/secrets.py (v0.5)."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fakeredis.aioredis import FakeRedis

from araxys.core.exceptions import ConnectionError
from araxys.db_security.pool import ConnectionPool, InMemoryPool, RedisPool
from araxys.db_security.secrets import (
    AWSSecretsResolver,
    ChainedResolver,
    ConnectionStringResolver,
    EnvVarResolver,
    VaultResolver,
)

# ---------------------------------------------------------------------------
# Helpers: mock optional third-party packages before constructing resolvers
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_hvac() -> Iterator[MagicMock]:
    """Inject a mock ``hvac`` module into sys.modules."""
    mock = MagicMock()
    mock.Client.return_value = MagicMock()
    with patch.dict(sys.modules, {"hvac": mock}):
        yield mock


@pytest.fixture
def mock_boto3() -> Iterator[MagicMock]:
    """Inject a mock ``boto3`` module into sys.modules."""
    mock = MagicMock()
    mock.client.return_value = MagicMock()
    with patch.dict(sys.modules, {"boto3": mock}):
        yield mock


# =============================================================================
# ConnectionPool Protocol
# =============================================================================

class TestConnectionPoolProtocol:
    """ConnectionPool must be a runtime-checkable Protocol."""

    def test_protocol_methods_exist(self) -> None:
        """All required methods must be defined on the Protocol."""
        method_names = {"acquire", "release", "health", "close"}
        protocol_methods = {
            name
            for name in dir(ConnectionPool)
            if not name.startswith("_")
            and callable(getattr(ConnectionPool, name, None))
        }
        assert method_names.issubset(protocol_methods)

    def test_runtime_checkable(self) -> None:
        """ConnectionPool should be runtime-checkable so isinstance works."""
        # A runtime-checkable Protocol has _is_protocol=True in its metaclass
        # or has __instancecheck__ defined.
        assert hasattr(ConnectionPool, "__instancecheck__")


# =============================================================================
# InMemoryPool
# =============================================================================

class TestInMemoryPool:
    """InMemoryPool — no-op pool for tests tracking acquire/release counts."""

    async def test_acquire_returns_fakeredis(self) -> None:
        pool = InMemoryPool(max_size=10)
        conn = await pool.acquire()
        assert isinstance(conn, FakeRedis)

    async def test_acquire_release_cycle(self) -> None:
        pool = InMemoryPool(max_size=10)
        conn = await pool.acquire()
        assert pool._active == 1
        await pool.release(conn)
        assert pool._active == 0

    async def test_health_returns_true(self) -> None:
        pool = InMemoryPool(max_size=10)
        healthy = await pool.health()
        assert healthy is True

    async def test_exhaustion_raises_connection_error(self) -> None:
        pool = InMemoryPool(max_size=2)
        c1 = await pool.acquire()
        c2 = await pool.acquire()
        with pytest.raises(ConnectionError) as excinfo:
            await pool.acquire()
        assert "exhausted" in str(excinfo.value).lower()
        await pool.release(c1)
        await pool.release(c2)

    async def test_acquire_after_exhaustion_reuses_freed_slot(self) -> None:
        pool = InMemoryPool(max_size=2)
        c1 = await pool.acquire()
        c2 = await pool.acquire()
        with pytest.raises(ConnectionError):
            await pool.acquire()
        await pool.release(c1)
        c3 = await pool.acquire()
        assert c3 is not None
        await pool.release(c2)
        await pool.release(c3)

    async def test_close_marks_closed_and_raises_on_acquire(self) -> None:
        pool = InMemoryPool(max_size=10)
        await pool.close()
        with pytest.raises(ConnectionError) as excinfo:
            await pool.acquire()
        assert "closed" in str(excinfo.value).lower()

    async def test_close_sets_closed_flag(self) -> None:
        pool = InMemoryPool(max_size=10)
        assert pool._closed is False
        await pool.close()
        assert pool._closed is True

    async def test_close_releases_connections(self) -> None:
        pool = InMemoryPool(max_size=10)
        await pool.acquire()
        assert pool._active == 1
        await pool.close()
        assert pool._active == 0

    async def test_is_runtime_checkable_connection_pool(self) -> None:
        pool = InMemoryPool(max_size=10)
        assert isinstance(pool, ConnectionPool)

    async def test_health_after_close(self) -> None:
        pool = InMemoryPool(max_size=10)
        await pool.close()
        healthy = await pool.health()
        assert healthy is False

    async def test_release_unacquired_connection_does_not_error(self) -> None:
        pool = InMemoryPool(max_size=10)
        fake = FakeRedis(decode_responses=True)
        await pool.release(fake)
        assert pool._active == 0

    async def test_release_twice_does_not_error(self) -> None:
        pool = InMemoryPool(max_size=10)
        conn = await pool.acquire()
        await pool.release(conn)
        await pool.release(conn)
        assert pool._active == 0


# =============================================================================
# RedisPool
# =============================================================================

class TestRedisPool:
    """RedisPool — wraps single redis.asyncio.Redis with health, leak, idle."""

    @pytest.fixture
    def pool(self) -> RedisPool:
        p = RedisPool("redis://localhost:6379", max_size=5, leak_threshold=3)
        p._redis = FakeRedis(decode_responses=True)
        return p

    async def test_acquire_returns_same_client(self, pool: RedisPool) -> None:
        c1 = await pool.acquire()
        c2 = await pool.acquire()
        assert c1 is c2
        assert isinstance(c1, FakeRedis)

    async def test_acquire_increments_active_count(self, pool: RedisPool) -> None:
        assert pool._active_count == 0
        c1 = await pool.acquire()
        assert pool._active_count == 1
        c2 = await pool.acquire()
        assert pool._active_count == 2
        await pool.release(c1)
        assert pool._active_count == 1
        await pool.release(c2)
        assert pool._active_count == 0

    async def test_release_decrements_active(self, pool: RedisPool) -> None:
        conn = await pool.acquire()
        assert pool._active_count == 1
        await pool.release(conn)
        assert pool._active_count == 0

    async def test_health_ping_success(self, pool: RedisPool) -> None:
        healthy = await pool.health()
        assert healthy is True

    async def test_health_ping_failure(self, pool: RedisPool) -> None:
        with patch.object(pool._redis, "ping", new=AsyncMock(
            side_effect=ConnectionError("Redis down"),
        )):
            healthy = await pool.health()
        assert healthy is False

    async def test_health_ping_general_error(self, pool: RedisPool) -> None:
        """Any exception during ping causes health() to return False."""
        with patch.object(pool._redis, "ping", new=AsyncMock(
            side_effect=RuntimeError("Unexpected error"),
        )):
            healthy = await pool.health()
        assert healthy is False

    async def test_max_size_enforcement(self, pool: RedisPool) -> None:
        pool.max_size = 2
        c1 = await pool.acquire()
        c2 = await pool.acquire()
        with pytest.raises(ConnectionError) as excinfo:
            await pool.acquire()
        assert "exhausted" in str(excinfo.value).lower()
        await pool.release(c1)
        await pool.release(c2)

    async def test_leak_detection_sets_warned_flag(self) -> None:
        """When active_count meets or exceeds leak_threshold, _leak_warned is set."""
        pool = RedisPool("redis://localhost:6379", max_size=5, leak_threshold=2)
        pool._redis = FakeRedis(decode_responses=True)
        assert pool._leak_warned is False
        c1 = await pool.acquire()
        assert pool._leak_warned is False  # 1 < 2
        c2 = await pool.acquire()
        # 2 >= 2 → warning fires at threshold
        assert pool._leak_warned is True
        await pool.release(c1)
        await pool.release(c2)

    async def test_leak_warning_resets_on_release(self) -> None:
        """_leak_warned resets after a release so warning can fire again."""
        pool = RedisPool("redis://localhost:6379", max_size=5, leak_threshold=1)
        pool._redis = FakeRedis(decode_responses=True)
        c1 = await pool.acquire()
        assert pool._leak_warned is True
        await pool.release(c1)
        assert pool._leak_warned is False  # reset

    async def test_close_closes_underlying_client(self, pool: RedisPool) -> None:
        pool._redis = MagicMock(spec=FakeRedis)
        pool._redis.aclose = AsyncMock()
        await pool.close()
        pool._redis.aclose.assert_awaited_once()

    async def test_close_resets_active(self, pool: RedisPool) -> None:
        await pool.acquire()
        await pool.acquire()
        assert pool._active_count == 2
        await pool.close()
        assert pool._active_count == 0

    async def test_is_runtime_checkable_connection_pool(  # noqa: PLR0913
        self, pool: RedisPool,
    ) -> None:
        assert isinstance(pool, ConnectionPool)


# =============================================================================
# ConnectionStringResolver Protocol
# =============================================================================

class TestConnectionStringResolverProtocol:
    """ConnectionStringResolver must be a runtime-checkable Protocol."""

    def test_runtime_checkable(self) -> None:
        assert hasattr(ConnectionStringResolver, "__instancecheck__")

    def test_protocol_methods_exist(self) -> None:
        assert hasattr(ConnectionStringResolver, "resolve")
        assert callable(ConnectionStringResolver.resolve)


# =============================================================================
# EnvVarResolver
# =============================================================================

class TestEnvVarResolver:
    """EnvVarResolver — reads ARAXYS_DB__{NAME} from environment."""

    async def test_resolves_existing_var(self) -> None:
        resolver = EnvVarResolver(prefix="ARAXYS_DB__")
        env = {"ARAXYS_DB__REDIS_URL": "redis://test:6379"}
        with patch.dict(os.environ, env, clear=False):
            result = await resolver.resolve("REDIS_URL")
        assert result == "redis://test:6379"

    async def test_returns_none_for_missing_var(self) -> None:
        resolver = EnvVarResolver(prefix="ARAXYS_DB__")
        with patch.dict(os.environ, {}, clear=True):
            result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_default_prefix(self) -> None:
        """Default prefix should be ARAXYS_DB__."""
        resolver = EnvVarResolver()
        assert resolver._prefix == "ARAXYS_DB__"

    async def test_custom_prefix(self) -> None:
        resolver = EnvVarResolver(prefix="MY_PREFIX__")
        env = {"MY_PREFIX__DB_URL": "redis://custom:6379"}
        with patch.dict(os.environ, env, clear=False):
            result = await resolver.resolve("DB_URL")
        assert result == "redis://custom:6379"

    async def test_trailing_underscore_name(self) -> None:
        """Names with underscores should work correctly."""
        resolver = EnvVarResolver(prefix="ARAXYS_DB__")
        env = {"ARAXYS_DB__MY_SECRET_KEY": "my-value"}
        with patch.dict(os.environ, env, clear=False):
            result = await resolver.resolve("MY_SECRET_KEY")
        assert result == "my-value"


# =============================================================================
# VaultResolver
# =============================================================================

class TestVaultResolver:
    """VaultResolver — reads secrets from HashiCorp Vault using hvac."""

    async def test_resolves_secret(self, mock_hvac: MagicMock) -> None:
        """Happy path: Vault returns a secret value."""
        resolver = VaultResolver(
            url="https://vault:8200", token="s.test123",
        )
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"REDIS_URL": "redis://vault:6379"}},
        }
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result == "redis://vault:6379"
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="REDIS_URL", mount_point="araxys",
        )

    async def test_custom_mount_path(self, mock_hvac: MagicMock) -> None:
        resolver = VaultResolver(
            url="https://vault:8200", token="s.test123", mount_path="custom",
        )
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY": "val"}},
        }
        resolver._client = mock_client

        result = await resolver.resolve("KEY")
        assert result == "val"
        mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="KEY", mount_point="custom",
        )

    async def test_fail_soft_on_connection_error(self, mock_hvac: MagicMock) -> None:
        """When Vault is unreachable, returns None without raising."""
        resolver = VaultResolver(url="https://vault:8200", token="s.test123")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = (
            ConnectionError("Vault unreachable")
        )
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_fail_soft_on_auth_error(self, mock_hvac: MagicMock) -> None:
        """When Vault auth fails, returns None without raising."""
        resolver = VaultResolver(url="https://vault:8200", token="s.bad")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = (
            PermissionError("Permission denied")
        )
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_fail_soft_on_generic_exception(self, mock_hvac: MagicMock) -> None:
        """Any exception should result in None, not propagate."""
        resolver = VaultResolver(url="https://vault:8200", token="s.test123")
        mock_client = MagicMock()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = RuntimeError(
            "Unexpected error",
        )
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_init_creates_hvac_client(self, mock_hvac: MagicMock) -> None:
        """Constructor should create an hvac.Client instance."""
        VaultResolver(url="https://vault:8200", token="s.test123")
        mock_hvac.Client.assert_called_once_with(
            url="https://vault:8200", token="s.test123",
        )


# =============================================================================
# AWSSecretsResolver
# =============================================================================

class TestAWSSecretsResolver:
    """AWSSecretsResolver — reads secrets from AWS Secrets Manager via boto3."""

    async def test_resolves_secret(self, mock_boto3: MagicMock) -> None:
        """Happy path: AWS Secrets Manager returns a secret string."""
        resolver = AWSSecretsResolver(
            secret_prefix="araxys/", region_name="us-east-1",
        )
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": "redis://aws:6379",
        }
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result == "redis://aws:6379"
        mock_client.get_secret_value.assert_called_once_with(
            SecretId="araxys/REDIS_URL",
        )

    async def test_default_secret_prefix(self, mock_boto3: MagicMock) -> None:
        resolver = AWSSecretsResolver(region_name="us-east-1")
        assert resolver._secret_prefix == "araxys/"

    async def test_custom_secret_prefix(self, mock_boto3: MagicMock) -> None:
        resolver = AWSSecretsResolver(
            secret_prefix="myapp/", region_name="us-east-1",
        )
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            "SecretString": "redis://custom:6379",
        }
        resolver._client = mock_client

        result = await resolver.resolve("DB_URL")
        assert result == "redis://custom:6379"
        mock_client.get_secret_value.assert_called_once_with(SecretId="myapp/DB_URL")

    async def test_fail_soft_on_boto3_error(self, mock_boto3: MagicMock) -> None:
        """When boto3 raises an exception, returns None (fail-soft)."""
        resolver = AWSSecretsResolver(
            secret_prefix="araxys/", region_name="us-east-1",
        )
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = ValueError(
            "Secret not found",
        )
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_fail_soft_on_generic_exception(self, mock_boto3: MagicMock) -> None:
        """Any exception should result in None, not propagate."""
        resolver = AWSSecretsResolver(
            secret_prefix="araxys/", region_name="us-east-1",
        )
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = RuntimeError("Network error")
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_fail_soft_on_endpoint_error(self, mock_boto3: MagicMock) -> None:
        """Connection errors to AWS should also return None."""
        resolver = AWSSecretsResolver(
            secret_prefix="araxys/", region_name="us-east-1",
        )
        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = ConnectionError(
            "AWS unreachable",
        )
        resolver._client = mock_client

        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_init_creates_boto3_client(self, mock_boto3: MagicMock) -> None:
        """Constructor should create a boto3 secretsmanager client."""
        AWSSecretsResolver(
            secret_prefix="araxys/", region_name="eu-west-1",
        )
        mock_boto3.client.assert_called_once_with(
            "secretsmanager", region_name="eu-west-1",
        )


# =============================================================================
# ChainedResolver
# =============================================================================

class TestChainedResolver:
    """ChainedResolver — composes resolvers, first non-None wins."""

    async def test_first_wins(self) -> None:
        r1 = MagicMock(spec=ConnectionStringResolver)
        r1.resolve = AsyncMock(return_value="redis://first:6379")
        r2 = MagicMock(spec=ConnectionStringResolver)
        r2.resolve = AsyncMock(return_value="redis://second:6379")
        resolver = ChainedResolver(resolvers=[r1, r2])

        result = await resolver.resolve("REDIS_URL")
        assert result == "redis://first:6379"
        r1.resolve.assert_awaited_once_with("REDIS_URL")
        r2.resolve.assert_not_awaited()

    async def test_second_wins_when_first_returns_none(self) -> None:
        r1 = MagicMock(spec=ConnectionStringResolver)
        r1.resolve = AsyncMock(return_value=None)
        r2 = MagicMock(spec=ConnectionStringResolver)
        r2.resolve = AsyncMock(return_value="redis://second:6379")
        resolver = ChainedResolver(resolvers=[r1, r2])

        result = await resolver.resolve("REDIS_URL")
        assert result == "redis://second:6379"
        r1.resolve.assert_awaited_once_with("REDIS_URL")
        r2.resolve.assert_awaited_once_with("REDIS_URL")

    async def test_all_fail_returns_none(self) -> None:
        r1 = MagicMock(spec=ConnectionStringResolver)
        r1.resolve = AsyncMock(return_value=None)
        r2 = MagicMock(spec=ConnectionStringResolver)
        r2.resolve = AsyncMock(return_value=None)
        resolver = ChainedResolver(resolvers=[r1, r2])

        result = await resolver.resolve("REDIS_URL")
        assert result is None
        r1.resolve.assert_awaited_once_with("REDIS_URL")
        r2.resolve.assert_awaited_once_with("REDIS_URL")

    async def test_empty_resolvers_returns_none(self) -> None:
        resolver = ChainedResolver(resolvers=[])
        result = await resolver.resolve("REDIS_URL")
        assert result is None

    async def test_env_overrides_vault(self, mock_hvac: MagicMock) -> None:
        """EnvVarResolver before VaultResolver means env wins."""
        vault = VaultResolver(url="https://vault:8200", token="s.test123")
        resolver = ChainedResolver(resolvers=[
            EnvVarResolver(prefix="ARAXYS_DB__"),
            vault,
        ])
        env = {"ARAXYS_DB__REDIS_URL": "redis://env:6379"}
        with patch.dict(os.environ, env, clear=False):
            result = await resolver.resolve("REDIS_URL")
        assert result == "redis://env:6379"

    async def test_vault_fallback_when_env_missing(self, mock_hvac: MagicMock) -> None:
        """When env is not set, falls through to Vault."""
        env_resolver = EnvVarResolver(prefix="ARAXYS_DB__")
        vault_resolver = VaultResolver(
            url="https://vault:8200", token="s.test123",
        )
        vault_resolver._client = MagicMock()
        vault_resolver._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"REDIS_URL": "redis://vault:6379"}},
        }
        resolver = ChainedResolver(resolvers=[env_resolver, vault_resolver])
        with patch.dict(os.environ, {}, clear=True):
            result = await resolver.resolve("REDIS_URL")
        assert result == "redis://vault:6379"

    async def test_propagates_exceptions_from_inner_resolvers(self) -> None:
        """If a resolver raises (not fail-soft), the exception propagates."""
        r1 = MagicMock(spec=ConnectionStringResolver)
        r1.resolve = AsyncMock(side_effect=ValueError(
            "Unexpected error in resolver",
        ))
        resolver = ChainedResolver(resolvers=[r1])

        with pytest.raises(ValueError, match="Unexpected error in resolver"):
            await resolver.resolve("REDIS_URL")
