"""Database security manager.

Orchestrates the connection pool, secret resolution, TLS configuration,
and query auditing lifecycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from araxys.db_security.audit import QueryAuditor
from araxys.db_security.pool import ConnectionPool, RedisPool
from araxys.db_security.secrets import (
    ChainedResolver,
    ConnectionStringResolver,
    EnvVarResolver,
)
from araxys.db_security.tls import build_ssl_context

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from araxys.core.config import DatabaseSecurityConfig
    from araxys.core.types import AuditEntry
    from araxys.db_security.pg_pool import PGPool

logger = structlog.get_logger("araxys.db_security.manager")


class DatabaseSecurityManager:
    """Orchestrates pool, resolver, and auditor lifecycle.

    Parameters
    ----------
    config:
        Database security configuration.
    on_audit:
        Optional async callback for audit entries (forwarded to
        :class:`QueryAuditor`).
    """

    def __init__(
        self,
        config: DatabaseSecurityConfig,
        on_audit: Callable[[AuditEntry], Awaitable[None]] | None = None,
    ) -> None:
        self._config = config
        self._on_audit = on_audit

        # Build resolver chain: EnvVarResolver always, then Vault/AWS if configured.
        # The chain is built synchronously but resolved lazily (async).
        resolvers: list[ConnectionStringResolver] = [EnvVarResolver()]
        if config.secrets.vault_url:
            from araxys.db_security.secrets import VaultResolver

            resolvers.append(
                VaultResolver(
                    url=config.secrets.vault_url,
                    token=config.secrets.vault_token or "",
                    mount_path=config.secrets.vault_mount_path,
                ),
            )
        if config.secrets.aws_region:
            from araxys.db_security.secrets import AWSSecretsResolver

            resolvers.append(
                AWSSecretsResolver(
                    secret_prefix=config.secrets.aws_secret_prefix,
                    region_name=config.secrets.aws_region,
                ),
            )

        self._resolver: ConnectionStringResolver | None = (
            ChainedResolver(resolvers=resolvers) if resolvers else None
        )

        # Build SSL context (enabled check is inside build_ssl_context).
        ssl_context = build_ssl_context(config.tls)

        # Create QueryValidator if query_validation config is present.
        query_validator: QueryValidator | None = None
        if config.query_validation is not None:
            from araxys.db_security.query_validator import QueryValidator

            query_validator = QueryValidator(config.query_validation)

        # Select pool class based on mode discriminator.
        pool_params: dict[str, object] = dict(
            max_size=config.redis_pool.max_size,
            idle_timeout_seconds=config.redis_pool.idle_timeout_seconds,
            acquire_timeout_seconds=config.redis_pool.acquire_timeout_seconds,
            health_check_interval_seconds=config.redis_pool.health_check_interval_seconds,
            leak_threshold=config.redis_pool.leak_threshold,
            reconnect_retries=config.redis_pool.reconnect_retries,
            ssl_context=ssl_context,
            cert_pin_sha256=config.tls.cert_pin_sha256,
            query_validator=query_validator,
        )

        if config.redis_pool.mode == "sentinel":
            from araxys.db_security.pool import RedisSentinelPool

            self._pool: ConnectionPool = RedisSentinelPool(
                sentinels=config.redis_pool.sentinels,
                master_name=config.redis_pool.master_name,
                **pool_params,  # type: ignore[arg-type]
            )
        elif config.redis_pool.mode == "cluster":
            from araxys.db_security.pool import RedisClusterPool

            self._pool = RedisClusterPool(
                startup_nodes=config.redis_pool.startup_nodes,
                url=config.redis_pool.url,
                read_from_replicas=config.redis_pool.read_from_replicas,
                **pool_params,  # type: ignore[arg-type]
            )
        else:
            self._pool = RedisPool(
                url=config.redis_pool.url,
                **pool_params,  # type: ignore[arg-type]
            )

        # Create auditor if enabled and callback provided.
        self._auditor: QueryAuditor | None = None
        if config.query_audit.enabled and on_audit is not None:
            self._auditor = QueryAuditor(
                enabled=True,
                slow_query_threshold_ms=config.query_audit.slow_query_threshold_ms,
                on_audit=on_audit,
            )

        # PostgreSQL pool (optional)
        self._pg_pool: PGPool | None = None
        if config.pg_pool is not None and config.pg_pool.enabled:
            from araxys.db_security.pg_pool import PGPool

            self._pg_pool = PGPool(
                dsn=config.pg_pool.dsn,
                min_size=config.pg_pool.min_size,
                max_size=config.pg_pool.max_size,
                acquire_timeout=config.pg_pool.acquire_timeout_seconds,
                idle_timeout=config.pg_pool.idle_timeout_seconds,
                health_check_interval=config.pg_pool.health_check_seconds,
                ssl_context=ssl_context,
            )

    @property
    def pool(self) -> ConnectionPool:
        """The shared connection pool."""
        return self._pool

    @property
    def auditor(self) -> QueryAuditor | None:
        """The query auditor, if enabled."""
        return self._auditor

    @property
    def pg_pool(self) -> PGPool | None:
        """The PostgreSQL connection pool, if enabled."""
        return self._pg_pool

    async def shutdown(self) -> None:
        """Shut down all connection pools."""
        try:
            await self._pool.close()
        except Exception:
            logger.error(
                "db_security.shutdown_error",
                msg="Error shutting down Redis pool",
                exc_info=True,
            )
        if self._pg_pool is not None:
            try:
                await self._pg_pool.shutdown()
            except Exception:
                logger.error(
                    "db_security.shutdown_error",
                    msg="Error shutting down PostgreSQL pool",
                    exc_info=True,
                )
