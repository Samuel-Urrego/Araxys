"""Tests for db_security module (v0.5).

Covers pool, secrets, TLS, audit, and manager.
"""

from __future__ import annotations

import os
import ssl
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

import pytest
from fakeredis.aioredis import FakeRedis
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from araxys.core.config import (
    DatabaseSecurityConfig,
    QueryAuditConfig,
    RedisPoolConfig,
    TLSConfig,
)
from araxys.core.exceptions import ConnectionError, TLSConfigurationError
from araxys.core.types import AuditEntry, AuditEventType
from araxys.db_security.audit import QueryAuditor, QueryEvent
from araxys.db_security.dependencies import get_db_pool, get_query_auditor
from araxys.db_security.manager import DatabaseSecurityManager
from araxys.db_security.pool import ConnectionPool, InMemoryPool, RedisPool
from araxys.db_security.secrets import (
    AWSSecretsResolver,
    ChainedResolver,
    ConnectionStringResolver,
    EnvVarResolver,
    VaultResolver,
)
from araxys.db_security.tls import build_ssl_context

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


# =============================================================================
# TLS — build_ssl_context
# =============================================================================


class TestBuildSSLContext:
    """build_ssl_context() factory tests."""

    def test_returns_none_when_disabled(self) -> None:
        """TLS disabled → returns None."""
        config = TLSConfig(enabled=False)
        result = build_ssl_context(config)
        assert result is None

    def test_returns_ssl_context_with_tls_12(self) -> None:
        """With min_tls_version=TLSv1.2, returns an SSLContext >= 1.2."""
        config = TLSConfig(enabled=True, min_tls_version="TLSv1.2")
        ctx = build_ssl_context(config)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    def test_raises_on_nonexistent_ca_cert_path(self) -> None:
        """Nonexistent ca_cert_path raises TLSConfigurationError."""
        fake_path = "/nonexistent/ca-cert.pem"
        config = TLSConfig(enabled=True, ca_cert_path=fake_path)
        with pytest.raises(TLSConfigurationError, match="CA cert file not found"):
            build_ssl_context(config)

    def test_raises_on_unsupported_tls_version(self) -> None:
        """When the system doesn't support the minimum TLS version, raises."""
        config = TLSConfig(enabled=True, min_tls_version="TLSv1.3")
        # Simulate a system where minimum_version silently stays at TLSv1.2
        # even when TLSv1.3 is requested (old OpenSSL behaviour).
        with patch.object(
            ssl.SSLContext,
            "minimum_version",
            new_callable=PropertyMock,
        ) as mock_min_version:
            mock_min_version.return_value = ssl.TLSVersion.TLSv1_2
            with pytest.raises(
                TLSConfigurationError,
                match="does not support TLSv1.3",
            ):
                build_ssl_context(config)

    def test_ca_cert_path_loaded_when_exists(self, tmp_path: Path) -> None:
        """When ca_cert_path exists, load_verify_locations is called."""
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text("fake-cert-content\n")

        config = TLSConfig(
            enabled=True,
            ca_cert_path=str(ca_file),
            min_tls_version="TLSv1.2",
        )
        with patch.object(ssl.SSLContext, "load_verify_locations") as mock_load:
            ctx = build_ssl_context(config)
        assert isinstance(ctx, ssl.SSLContext)
        mock_load.assert_called_once_with(cafile=str(ca_file))


# =============================================================================
# QueryEvent dataclass
# =============================================================================


class TestQueryEvent:
    """QueryEvent frozen dataclass tests."""

    def test_frozen(self) -> None:
        """QueryEvent instances should be immutable."""
        event = QueryEvent(query_text="SELECT 1")
        with pytest.raises(AttributeError, match="cannot assign to field"):
            event.query_text = "UPDATED"  # type: ignore[misc]

    def test_slots(self) -> None:
        """QueryEvent should use __slots__ (no __dict__)."""
        event = QueryEvent(query_text="SELECT 1")
        with pytest.raises(AttributeError, match="__dict__"):
            _ = event.__dict__

    def test_default_timestamp(self) -> None:
        """Default timestamp is set on construction."""
        event = QueryEvent(query_text="SELECT 1")
        assert event.timestamp is not None

    def test_all_fields(self) -> None:
        """All fields can be set via constructor."""
        event = QueryEvent(
            query_text="SELECT * FROM users WHERE id = :uid",
            query_params={"uid": 42},
            connection_id="conn-1",
            duration_ms=15.5,
        )
        assert event.query_text == "SELECT * FROM users WHERE id = :uid"
        assert event.query_params == {"uid": 42}
        assert event.connection_id == "conn-1"
        assert event.duration_ms == 15.5

    def test_query_params_default_none(self) -> None:
        """query_params defaults to None."""
        event = QueryEvent(query_text="SELECT 1")
        assert event.query_params is None

    def test_connection_id_default_none(self) -> None:
        """connection_id defaults to None."""
        event = QueryEvent(query_text="SELECT 1")
        assert event.connection_id is None

    def test_duration_ms_default_none(self) -> None:
        """duration_ms defaults to None."""
        event = QueryEvent(query_text="SELECT 1")
        assert event.duration_ms is None


# =============================================================================
# QueryAuditor
# =============================================================================


class TestQueryAuditor:
    """QueryAuditor emit() behaviour tests."""

    @pytest.fixture
    def on_audit(self) -> AsyncMock:
        return AsyncMock()

    async def test_emit_calls_on_audit_with_audit_entry(
        self, on_audit: AsyncMock,
    ) -> None:
        """emit() creates an AuditEntry with QUERY_EXECUTED and calls on_audit."""
        auditor = QueryAuditor(on_audit=on_audit)
        event = QueryEvent(query_text="SELECT 1", duration_ms=5.0)

        await auditor.emit(event)

        on_audit.assert_awaited_once()
        args = on_audit.await_args
        assert args is not None
        entry: AuditEntry = args[0][0]
        assert entry.event_type == AuditEventType.QUERY_EXECUTED
        assert entry.detail is None

    async def test_emit_skips_when_disabled(self, on_audit: AsyncMock) -> None:
        """When enabled=False, emit() does not call on_audit."""
        auditor = QueryAuditor(enabled=False, on_audit=on_audit)
        event = QueryEvent(query_text="SELECT 1")

        await auditor.emit(event)

        on_audit.assert_not_awaited()

    async def test_emit_skips_when_on_audit_is_none(self) -> None:
        """When on_audit is None, emit() returns silently."""
        auditor = QueryAuditor(on_audit=None)
        event = QueryEvent(query_text="SELECT 1")

        # Should not raise
        await auditor.emit(event)

    async def test_slow_query_flagged(self, on_audit: AsyncMock) -> None:
        """When duration_ms > slow_query_threshold_ms, detail='slow_query'."""
        auditor = QueryAuditor(
            on_audit=on_audit,
            slow_query_threshold_ms=100,
        )
        event = QueryEvent(query_text="SELECT 1", duration_ms=200.0)

        await auditor.emit(event)

        on_audit.assert_awaited_once()
        args = on_audit.await_args
        assert args is not None
        entry: AuditEntry = args[0][0]
        assert entry.event_type == AuditEventType.QUERY_EXECUTED
        assert entry.detail == "slow_query"

    async def test_normal_query_not_flagged(self, on_audit: AsyncMock) -> None:
        """When duration_ms <= slow_query_threshold_ms, detail is None."""
        auditor = QueryAuditor(
            on_audit=on_audit,
            slow_query_threshold_ms=100,
        )
        event = QueryEvent(query_text="SELECT 1", duration_ms=50.0)

        await auditor.emit(event)

        on_audit.assert_awaited_once()
        args = on_audit.await_args
        assert args is not None
        entry: AuditEntry = args[0][0]
        assert entry.event_type == AuditEventType.QUERY_EXECUTED
        assert entry.detail is None

    async def test_slow_query_logs_warning(
        self, on_audit: AsyncMock,
    ) -> None:
        """Slow queries should emit a structlog warning."""
        import araxys.db_security.audit as audit_module

        auditor = QueryAuditor(
            on_audit=on_audit,
            slow_query_threshold_ms=100,
        )
        event = QueryEvent(
            query_text="SELECT * FROM big_table",
            duration_ms=500.0,
        )

        with patch.object(audit_module, "logger") as mock_logger:
            await auditor.emit(event)

            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args
            assert "slow_query" in str(call_args)

    async def test_emit_without_duration(
        self, on_audit: AsyncMock,
    ) -> None:
        """emit() works when duration_ms is None (no slow-query check)."""
        auditor = QueryAuditor(on_audit=on_audit)
        event = QueryEvent(query_text="SELECT 1")

        await auditor.emit(event)

        on_audit.assert_awaited_once()
        args = on_audit.await_args
        assert args is not None
        entry: AuditEntry = args[0][0]
        assert entry.detail is None


# =============================================================================
# DatabaseSecurityManager
# =============================================================================


class TestDatabaseSecurityManager:
    """DatabaseSecurityManager lifecycle tests."""

    @pytest.fixture
    def mock_pool(self) -> MagicMock:
        pool = MagicMock(spec=ConnectionPool)
        pool.acquire = AsyncMock()
        pool.release = AsyncMock()
        pool.health = AsyncMock(return_value=True)
        pool.close = AsyncMock()
        return pool

    @pytest.fixture
    def on_audit(self) -> AsyncMock:
        return AsyncMock()

    @pytest.fixture
    def full_config(self) -> DatabaseSecurityConfig:
        """Config with TLS + query audit enabled + no secrets."""
        return DatabaseSecurityConfig(
            enabled=True,
            redis_pool=RedisPoolConfig(url="redis://test:6379"),
            tls=TLSConfig(enabled=False),
            query_audit=QueryAuditConfig(enabled=True, slow_query_threshold_ms=100),
        )

    def test_creates_redis_pool_from_config(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """Manager creates a RedisPool from the config."""
        manager = DatabaseSecurityManager(config=full_config, on_audit=None)
        assert manager.pool is not None
        assert isinstance(manager.pool, RedisPool)
        assert manager.pool.url == "redis://test:6379"

    def test_falls_back_to_config_url_when_resolver_none(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """Pool URL comes from config.redis_pool.url (resolver is lazy)."""
        config = DatabaseSecurityConfig(
            enabled=True,
            redis_pool=RedisPoolConfig(url="redis://fallback:6379"),
            tls=TLSConfig(enabled=False),
            query_audit=QueryAuditConfig(enabled=False),
        )
        manager = DatabaseSecurityManager(config=config, on_audit=None)
        assert manager.pool is not None
        assert manager.pool.url == "redis://fallback:6379"  # type: ignore[attr-defined]

    def test_creates_auditor_when_enabled(
        self, full_config: DatabaseSecurityConfig, on_audit: AsyncMock,
    ) -> None:
        """When query_audit.enabled=True, auditor is created."""
        manager = DatabaseSecurityManager(config=full_config, on_audit=on_audit)
        assert manager.auditor is not None
        assert isinstance(manager.auditor, QueryAuditor)

    def test_skips_auditor_when_disabled(self, on_audit: AsyncMock) -> None:
        """When query_audit.enabled=False, auditor is None."""
        config = DatabaseSecurityConfig(
            enabled=True,
            redis_pool=RedisPoolConfig(url="redis://test:6379"),
            tls=TLSConfig(enabled=False),
            query_audit=QueryAuditConfig(enabled=False),
        )
        manager = DatabaseSecurityManager(config=config, on_audit=on_audit)
        assert manager.auditor is None

    async def test_shutdown_calls_pool_close(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """shutdown() calls close() on the pool."""
        manager = DatabaseSecurityManager(config=full_config, on_audit=None)
        with patch.object(manager.pool, "close", new=AsyncMock()) as mock_close:
            await manager.shutdown()
            mock_close.assert_awaited_once()

    async def test_shutdown_logs_error_on_pool_close_failure(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """When pool.close() raises, shutdown() logs and does not re-raise."""
        import araxys.db_security.manager as manager_module

        manager = DatabaseSecurityManager(config=full_config, on_audit=None)

        async def failing_close() -> None:
            raise RuntimeError("Pool shutdown failed")

        manager.pool.close = failing_close  # type: ignore[method-assign]
        with patch.object(manager_module, "logger") as mock_logger:
            await manager.shutdown()
            mock_logger.error.assert_called_once()
            # Verify error was logged (exc_info=True means the exception
            # traceback is captured — the message prefix confirms the context).
            args, kwargs = mock_logger.error.call_args
            assert args[0] == "db_security.shutdown_error"
            assert kwargs.get("exc_info") is True

    async def test_shutdown_never_raises(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """shutdown() should never raise, even if pool operations fail."""
        manager = DatabaseSecurityManager(config=full_config, on_audit=None)
        manager.pool.close = AsyncMock(side_effect=RuntimeError("Boom"))  # type: ignore[method-assign]
        # Should not raise
        await manager.shutdown()

    def test_pool_property_returns_pool(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """pool property returns the underlying ConnectionPool."""
        manager = DatabaseSecurityManager(config=full_config, on_audit=None)
        assert isinstance(manager.pool, ConnectionPool)

    def test_auditor_property_none_when_disabled(
        self, full_config: DatabaseSecurityConfig,
    ) -> None:
        """When no on_audit and audit disabled, auditor property is None."""
        config = DatabaseSecurityConfig(
            enabled=True,
            redis_pool=RedisPoolConfig(url="redis://test:6379"),
            tls=TLSConfig(enabled=False),
            query_audit=QueryAuditConfig(enabled=False),
        )
        manager = DatabaseSecurityManager(config=config, on_audit=None)
        assert manager.auditor is None


# =============================================================================
# Dependencies — get_db_pool, get_query_auditor
# =============================================================================


class TestGetDBPool:
    """get_db_pool FastAPI dependency tests."""

    def test_returns_pool_when_initialized(self) -> None:
        """get_db_pool returns the ConnectionPool from app.state.db_security.pool."""
        app = FastAPI()
        pool = MagicMock(spec=ConnectionPool)
        manager = MagicMock(spec=DatabaseSecurityManager)
        manager.pool = pool
        app.state.db_security = manager

        @app.get("/test")
        async def handler(
            p: ConnectionPool = Depends(get_db_pool),
        ) -> dict[str, object]:
            return {"pool_id": id(p)}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json()["pool_id"] == id(pool)

    def test_raises_when_not_initialized(self) -> None:
        """get_db_pool raises RuntimeError when db_security not in app.state."""
        app = FastAPI()

        @app.get("/test")
        async def handler(
            p: ConnectionPool = Depends(get_db_pool),
        ) -> dict[str, object]:
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test")
        assert response.status_code == 500

    def test_raises_when_db_security_is_none(self) -> None:
        """get_db_pool raises RuntimeError when db_security is None."""
        app = FastAPI()
        app.state.db_security = None

        @app.get("/test")
        async def handler(
            p: ConnectionPool = Depends(get_db_pool),
        ) -> dict[str, object]:
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test")
        assert response.status_code == 500


class TestGetQueryAuditor:
    """get_query_auditor FastAPI dependency tests."""

    def test_returns_auditor_when_initialized(self) -> None:
        """get_query_auditor returns QueryAuditor when auditor is set."""
        app = FastAPI()
        auditor = MagicMock(spec=QueryAuditor)
        manager = MagicMock(spec=DatabaseSecurityManager)
        manager.auditor = auditor
        app.state.db_security = manager

        @app.get("/test")
        async def handler(
            a: QueryAuditor | None = Depends(get_query_auditor),
        ) -> dict[str, object]:
            return {"auditor_id": id(a) if a else None}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json()["auditor_id"] == id(auditor)

    def test_returns_none_when_auditor_is_none(self) -> None:
        """get_query_auditor returns None when auditor is None."""
        app = FastAPI()
        manager = MagicMock(spec=DatabaseSecurityManager)
        manager.auditor = None
        app.state.db_security = manager

        @app.get("/test")
        async def handler(
            a: QueryAuditor | None = Depends(get_query_auditor),
        ) -> dict[str, object]:
            return {"auditor_id": id(a) if a else None}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json()["auditor_id"] is None

    def test_returns_none_when_db_security_missing(self) -> None:
        """get_query_auditor returns None when db_security not in app.state."""
        app = FastAPI()

        @app.get("/test")
        async def handler(
            a: QueryAuditor | None = Depends(get_query_auditor),
        ) -> dict[str, object]:
            return {"auditor_id": id(a) if a else None}

        client = TestClient(app)
        response = client.get("/test")
        assert response.status_code == 200
        assert response.json()["auditor_id"] is None
