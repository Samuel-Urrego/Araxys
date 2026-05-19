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

        # Use config URL directly (init is synchronous; async resolver resolution
        # happens lazily in the shield layer).
        self._pool: RedisPool = RedisPool(
            url=config.redis_pool.url,
            max_size=config.redis_pool.max_size,
            idle_timeout_seconds=config.redis_pool.idle_timeout_seconds,
            acquire_timeout_seconds=config.redis_pool.acquire_timeout_seconds,
            health_check_interval_seconds=config.redis_pool.health_check_interval_seconds,
            leak_threshold=config.redis_pool.leak_threshold,
            ssl_context=ssl_context,
            cert_pin_sha256=config.tls.cert_pin_sha256,
        )

        # Create auditor if enabled and callback provided.
        self._auditor: QueryAuditor | None = None
        if config.query_audit.enabled and on_audit is not None:
            self._auditor = QueryAuditor(
                enabled=True,
                slow_query_threshold_ms=config.query_audit.slow_query_threshold_ms,
                on_audit=on_audit,
            )

    @property
    def pool(self) -> ConnectionPool:
        """The shared connection pool."""
        return self._pool

    @property
    def auditor(self) -> QueryAuditor | None:
        """The query auditor, if enabled."""
        return self._auditor

    async def shutdown(self) -> None:
        """Shut down the connection pool.

        Logs errors via structlog and never raises.
        """
        try:
            await self._pool.close()
        except Exception:  # noqa: BLE001 — intentional, never raise from shutdown
            logger.error(
                "db_security.shutdown_error",
                msg="Error shutting down database security pool",
                exc_info=True,
            )
