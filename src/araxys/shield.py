"""AraxysShield — the main entry point for Araxys security.

Wires all security modules together and registers them on a
FastAPI application in the correct middleware order.

Usage::

    from fastapi import FastAPI
    from araxys import AraxysShield, AraxysConfig

    shield = AraxysShield(
        app, AraxysConfig(secret_key="your-32-char-secret-key-here!!!!")
    )
"""


from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import InMemoryAPIKeyStorage
from araxys.audit.logger import AuditLogger
from araxys.headers.middleware import SecureHeadersMiddleware
from araxys.honeypot.middleware import HoneypotMiddleware
from araxys.honeypot.trap import HoneypotTrap
from araxys.jwt_auth.storage import InMemoryTokenStorage
from araxys.jwt_auth.tokens import JWTManager
from araxys.rate_limit.backends import InMemoryBackend, RateLimitBackend
from araxys.rate_limit.middleware import RateLimitMiddleware
from araxys.sanitize.middleware import SanitizeMiddleware

if TYPE_CHECKING:
    from fastapi import FastAPI

    from araxys.core.config import AraxysConfig
    from araxys.core.types import AuditEntry

logger = structlog.get_logger("araxys.shield")


class AraxysShield:
    """Central orchestrator that wires all Araxys modules.

    Parameters
    ----------
    app:
        The FastAPI application to protect.
    config:
        Master configuration for all modules.
    rate_limit_backend:
        Custom rate limit backend (default: auto-detect from config).
    api_key_storage:
        Custom API key storage (default: InMemoryAPIKeyStorage).
    token_storage:
        Custom JWT token storage (default: InMemoryTokenStorage).
    """

    def __init__(
        self,
        app: FastAPI,
        config: AraxysConfig,
        *,
        rate_limit_backend: RateLimitBackend | None = None,
        api_key_storage: InMemoryAPIKeyStorage | None = None,
        token_storage: InMemoryTokenStorage | None = None,
    ) -> None:
        self.config = config
        self._app = app

        # --- Initialize shared components ---

        # Audit logger
        self.audit_logger: AuditLogger | None = None
        if config.audit.enabled:
            self.audit_logger = AuditLogger(
                config=config.audit,
                secret_key=config.secret_key,
            )

        # Rate limit backend
        self._rate_backend = rate_limit_backend or self._create_rate_backend(config)

        # API key manager
        self._api_key_storage = api_key_storage or self._create_api_key_storage(config)
        self.api_key_manager = APIKeyManager(
            storage=self._api_key_storage,
            on_audit=self._emit_audit,
        )

        # JWT manager
        self._token_storage = token_storage or self._create_token_storage(config)
        self.jwt_manager = JWTManager(
            config=config.jwt,
            secret_key=config.secret_key,
            storage=self._token_storage,
            on_audit=self._emit_audit,
        )

        # --- Register modules ---
        # ORDER MATTERS: middlewares are applied in REVERSE registration order
        # Last registered = first to execute (outermost)
        # So we register inner → outer:
        #   1. Sanitize (innermost — closest to handler)
        #   2. Rate Limit
        #   3. Honeypot IP check
        #   4. Secure Headers (outermost — always adds headers)

        self._register_sanitize(app, config)
        self._register_rate_limit(app, config)
        self._register_honeypot(app, config)
        self._register_secure_headers(app, config)

        logger.info(
            "araxys.shield_initialized",
            modules=[
                m
                for m, enabled in [
                    ("secure_headers", config.secure_headers.enabled),
                    ("honeypot", config.honeypot.enabled),
                    ("rate_limit", config.rate_limit.enabled),
                    ("sanitize", config.sanitize.enabled),
                    ("audit", config.audit.enabled),
                    ("jwt", True),
                    ("api_keys", True),
                ]
                if enabled
            ],
        )

    def _create_rate_backend(self, config: AraxysConfig) -> RateLimitBackend:
        """Create the rate limit backend based on config."""
        if config.redis_url:
            from araxys.rate_limit.backends import RedisBackend

            logger.info("araxys.using_redis_backend", url=config.redis_url)
            return RedisBackend(config.redis_url)
        logger.info("araxys.using_inmemory_backend")
        return InMemoryBackend()

    def _create_token_storage(self, config: AraxysConfig):  # type: ignore
        """Create the token storage based on config."""
        if config.redis_url:
            from araxys.jwt_auth.storage import RedisTokenStorage

            return RedisTokenStorage(config.redis_url)
        return InMemoryTokenStorage()

    def _create_api_key_storage(self, config: AraxysConfig):  # type: ignore
        """Create the API key storage based on config."""
        if config.redis_url:
            from araxys.api_keys.storage import RedisAPIKeyStorage

            return RedisAPIKeyStorage(config.redis_url)
        return InMemoryAPIKeyStorage()

    async def _emit_audit(self, entry: AuditEntry) -> None:
        """Internal audit event callback shared across all modules."""
        if self.audit_logger:
            await self.audit_logger.log(entry)

    def _register_secure_headers(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.secure_headers.enabled:
            return
        app.add_middleware(SecureHeadersMiddleware, config=config.secure_headers)

    def _register_honeypot(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.honeypot.enabled:
            return
        # Register the IP-ban check middleware
        app.add_middleware(HoneypotMiddleware, backend=self._rate_backend)
        # Register the trap routes
        trap = HoneypotTrap(
            backend=self._rate_backend,
            config=config.honeypot,
            on_audit=self._emit_audit,
        )
        trap.register_routes(app)

    def _register_rate_limit(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.rate_limit.enabled:
            return
        app.add_middleware(
            RateLimitMiddleware,
            backend=self._rate_backend,
            config=config.rate_limit,
        )

    def _register_sanitize(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.sanitize.enabled:
            return
        app.add_middleware(SanitizeMiddleware, config=config.sanitize)
