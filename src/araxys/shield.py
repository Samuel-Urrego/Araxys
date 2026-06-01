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

from araxys.account_protection.middleware import AccountProtectionMiddleware
from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import InMemoryAPIKeyStorage
from araxys.audit.logger import AuditLogger
from araxys.brute_force.limiter import (
    BruteForceMiddleware,
    InMemoryBruteForceBackend,
    RedisBruteForceBackend,
)
from araxys.brute_force.password_policy import PasswordPolicy, PasswordPolicyConfig
from araxys.core.exceptions import ConfigurationError

# v0.3 module imports
from araxys.cors.middleware import CORSMiddleware
from araxys.csrf.middleware import CSRFMiddleware as _CSRFMiddleware
from araxys.csrf.tokens import CSRFHandler
from araxys.db_security.manager import DatabaseSecurityManager
from araxys.db_security.pool import (
    ConnectionPool,  # noqa: TC001 — runtime annotation for db_pool property
)
from araxys.headers.middleware import SecureHeadersMiddleware
from araxys.honeypot.middleware import HoneypotMiddleware
from araxys.honeypot.trap import HoneypotTrap
from araxys.ip_access.backends import InMemoryIPAccessBackend, RedisIPAccessBackend
from araxys.ip_access.middleware import IPAccessMiddleware
from araxys.jwt_auth.storage import InMemoryTokenStorage
from araxys.jwt_auth.tokens import JWTManager
from araxys.malware.middleware import MalwareMiddleware
from araxys.xxe.middleware import XXEMiddleware
from araxys.metrics.collector import MetricsRegistry
from araxys.metrics.endpoint import mount_metrics
from araxys.prompt_injection.middleware import PromptInjectionMiddleware
from araxys.rate_limit.backends import InMemoryBackend, RateLimitBackend
from araxys.rate_limit.middleware import RateLimitMiddleware
from araxys.sanitize.middleware import SanitizeMiddleware
from araxys.sessions.manager import SessionManager
from araxys.sessions.storage import InMemorySessionBackend, RedisSessionBackend
from araxys.telemetry.middleware import TelemetryMiddleware
from araxys.telemetry.tracer import AraxysTracer
from araxys.webauthn.challenges import (
    InMemoryChallengeStore,
    RedisChallengeStore,
)
from araxys.webauthn.manager import WebAuthnManager as _WebAuthnManager
from araxys.webauthn.storage import (
    InMemoryCredentialStore,
    RedisCredentialStore,
)
from araxys.webhooks.delivery import WebhookDelivery
from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend
from araxys.webhooks.emitter import SecurityEventBus

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

        # --- Initialize shared components (v0.2.1) ---

        # Audit logger
        self.audit_logger: AuditLogger | None = None
        if config.audit.enabled:
            self.audit_logger = AuditLogger(
                config=config.audit,
                secret_key=config.secret_key,
            )

        # v0.5 — Database Security
        self._db_security: DatabaseSecurityManager | None = None
        if config.db_security is not None and config.db_security.enabled:
            # Deprecation: migrate old redis_url to db_security
            if config.redis_url and config.db_security.redis_pool.url == "redis://localhost:6379":
                import warnings
                warnings.warn(
                    "AraxysConfig.redis_url is deprecated when db_security is enabled. "
                    "Use AraxysConfig.db_security.redis_pool.url instead.",
                    DeprecationWarning,
                    stacklevel=2,
                )
                config.db_security.redis_pool.url = config.redis_url

            self._db_security = DatabaseSecurityManager(
                config=config.db_security,
                on_audit=self._emit_audit,
            )

        # Rate limit backend
        self._rate_backend = rate_limit_backend or self._create_rate_backend(config)

        # API key manager
        self._api_key_storage = api_key_storage or self._create_api_key_storage(config)
        self.api_key_manager = APIKeyManager(
            storage=self._api_key_storage,
            on_audit=self._emit_audit,
            protection_config=config.account_protection,
        )

        # JWT manager
        self._token_storage = token_storage or self._create_token_storage(config)
        self.jwt_manager = JWTManager(
            config=config.jwt,
            secret_key=config.secret_key,
            storage=self._token_storage,
            on_audit=self._emit_audit,
        )

        # --- v0.3 cross-cutting concerns ---

        # Event bus (shared dependency for webhooks + Prometheus)
        self.event_bus: SecurityEventBus | None = None
        if config.webhooks is not None and config.webhooks.enabled:
            self.event_bus = SecurityEventBus(queue_size=config.webhooks.queue_size)
            self.event_bus.start()

        # Webhook delivery (subscribes to event bus)
        self._webhook_delivery: WebhookDelivery | None = None
        if config.webhooks is not None and config.webhooks.enabled:
            assert self.event_bus is not None

            # DLQ backend (optional — must be created before delivery)
            self.dlq_backend: WebhookDLQBackend | None = None
            self._dlq_consumer: DLQConsumer | None = None
            webhooks_cfg = config.webhooks
            if webhooks_cfg.dlq_enabled:
                if not config.redis_url:
                    raise ConfigurationError(
                        "redis_url is required when webhooks.dlq_enabled=True"
                    )
                from redis.asyncio import from_url

                redis = from_url(config.redis_url, decode_responses=True)
                self.dlq_backend = WebhookDLQBackend(redis)
                self._webhook_delivery = WebhookDelivery(
                    webhooks_cfg, self.event_bus, config.secret_key,
                    dlq_backend=self.dlq_backend,
                )

                # Start DLQ consumer
                self._dlq_consumer = DLQConsumer(
                    backend=self.dlq_backend,
                    deliver_fn=self._webhook_delivery._deliver_with_retry,
                    config=webhooks_cfg,
                )
                self._dlq_consumer.start()
            else:
                self._webhook_delivery = WebhookDelivery(
                    webhooks_cfg, self.event_bus, config.secret_key,
                )

        # Metrics registry (subscribes to event bus, mounts /metrics)
        self._metrics_registry: MetricsRegistry | None = None
        if config.metrics is not None and config.metrics.enabled:
            self._metrics_registry = MetricsRegistry(config.metrics)
            if self.event_bus is not None:
                self._metrics_registry.subscribe_to_event_bus(self.event_bus)
            mount_metrics(app, config.metrics, self._metrics_registry)

        # Set module-level event bus references so middlewares can emit events
        if self.event_bus is not None:
            import araxys.ip_access.middleware as _ip_mw

            _ip_mw._event_bus = self.event_bus

            import araxys.brute_force.limiter as _bf_mw

            _bf_mw._event_bus = self.event_bus

            import araxys.xxe.middleware as _xxe_mw

            _xxe_mw._event_bus = self.event_bus
            import araxys.csrf.middleware as _csrf_mw

            _csrf_mw._event_bus = self.event_bus

        # Set module-level config for account_protection
        if config.account_protection is not None and config.account_protection.enabled:
            import araxys.account_protection.middleware as _ap_mw
            import araxys.mfa.dependencies as _mfa_deps

            if self.event_bus is not None:
                _ap_mw._event_bus = self.event_bus
            _mfa_deps._account_protection_config = config.account_protection

        # Session manager
        self._session_manager: SessionManager | None = None
        if config.session is not None and config.session.enabled:
            session_backend = self._create_session_backend(config)
            self._session_manager = SessionManager(
                config=config.session,
                backend=session_backend,
                event_bus=self.event_bus,
                jti_blacklist=self._token_storage.blacklist_jti
                if self._token_storage is not None
                else None,
            )
            import asyncio

            asyncio.create_task(self._session_manager.start_cleanup())

        # CSRF handler (stored on shield for dependency access)
        self.csrf_handler: CSRFHandler | None = None
        if config.csrf is not None and config.csrf.enabled:
            self.csrf_handler = CSRFHandler()

        # Password policy
        self.password_policy: PasswordPolicy | None = None
        if config.brute_force is not None and config.brute_force.enabled:
            self.password_policy = PasswordPolicy(
                PasswordPolicyConfig(
                    min_length=8,
                    max_length=128,
                    require_uppercase=True,
                    require_lowercase=True,
                    require_digit=True,
                    require_special=True,
                    check_hibp=config.brute_force.check_hibp,
                )
            )

        # MFA (TOTP)
        self.mfa_manager: MFAManager | None = None
        if config.mfa is not None and config.mfa.enabled:
            from araxys.mfa.manager import MFAManager

            self.mfa_manager = MFAManager(config.mfa, config.secret_key)

        # WebAuthn / Passkeys (v0.6)
        self.webauthn_manager: _WebAuthnManager | None = None
        if config.webauthn is not None and config.webauthn.enabled:
            from araxys.webauthn.models import RelyingPartyConfig

            rp_config = RelyingPartyConfig(
                rp_id=config.webauthn.rp_id,
                rp_name=config.webauthn.rp_name,
                expected_origin=config.webauthn.origin,
            )
            cred_store = self._create_credential_store(config)
            challenge_store = self._create_challenge_store(config)
            self.webauthn_manager = _WebAuthnManager(
                rp_config, cred_store, challenge_store=challenge_store
            )
            # Expose on app.state for FastAPI Depends injection
            app.state.webauthn_manager = self.webauthn_manager

        # Telemetry tracer
        self._tracer: AraxysTracer | None = None
        if config.telemetry is not None and config.telemetry.enabled:
            self._tracer = AraxysTracer(config.telemetry)

        # --- Register modules ---
        # ORDER MATTERS: middlewares are applied in REVERSE registration order
        # Last registered = first to execute (outermost)
        # So we register inner → outer:
        #   Innermost: Sanitize → Honeypot → IP Access → BruteForce →
        #   RateLimit → Telemetry → SecureHeaders → CORS (outermost)

        self._register_sanitize(app, config)
        self._register_xxe(app, config)  # between sanitize (inner) and prompt_injection
        self._register_prompt_injection(app, config)
        self._register_malware(app, config)
        self._register_honeypot(app, config)
        self._register_account_protection(app, config)
        self._register_ip_access(app, config)
        self._register_brute_force(app, config)
        self._register_rate_limit(app, config)
        self._register_telemetry(app, config)
        self._register_csrf(app, config)
        self._register_secure_headers(app, config)
        self._register_cors(app, config)

        _modules = [
            ("cors", True),
            ("secure_headers", config.secure_headers.enabled),
            ("telemetry", config.telemetry is not None and config.telemetry.enabled),
            ("rate_limit", config.rate_limit.enabled),
            ("brute_force", config.brute_force is not None and config.brute_force.enabled),  # noqa: E501
            ("ip_access", config.ip_control is not None and config.ip_control.enabled),  # noqa: E501
            ("honeypot", config.honeypot.enabled),
            (
                "account_protection",
                config.account_protection is not None
                and config.account_protection.enabled,
            ),
            ("sanitize", config.sanitize.enabled),
            (
                "prompt_injection",
                config.prompt_injection is not None,
            ),
            (
                "malware",
                config.malware is not None,
            ),
            (
                "xxe",
                config.xxe is not None,
            ),
            ("audit", config.audit.enabled),
            ("sessions", config.session is not None and config.session.enabled),
            ("webhooks", config.webhooks is not None and config.webhooks.enabled),
            ("metrics", config.metrics is not None and config.metrics.enabled),
            ("mfa", config.mfa is not None and config.mfa.enabled),
            ("jwt", True),
            ("api_keys", True),
            (
                "webauthn",
                config.webauthn is not None and config.webauthn.enabled,
            ),
        ]
        logger.info(
            "araxys.shield_initialized",
            modules=[m for m, enabled in _modules if enabled],
        )

    def _create_rate_backend(self, config: AraxysConfig) -> RateLimitBackend:
        """Create the rate limit backend based on config."""
        if self._db_security is not None:
            from araxys.rate_limit.backends import RedisBackend

            logger.info("araxys.using_pooled_redis_backend")
            return RedisBackend(pool=self._db_security.pool)
        if config.redis_url:
            from araxys.rate_limit.backends import RedisBackend

            logger.info("araxys.using_redis_backend", url=config.redis_url)
            return RedisBackend(config.redis_url)
        logger.warning(
            "araxys.using_inmemory_backend — NOT suitable for multi-worker "
            "deployments. Each worker has its own independent counters. "
            "Use Redis for production."
        )
        return InMemoryBackend()

    def _create_token_storage(self, config: AraxysConfig):  # type: ignore
        """Create the token storage based on config."""
        if self._db_security is not None:
            from araxys.jwt_auth.storage import RedisTokenStorage

            return RedisTokenStorage(pool=self._db_security.pool)
        if config.redis_url:
            from araxys.jwt_auth.storage import RedisTokenStorage

            return RedisTokenStorage(config.redis_url)
        return InMemoryTokenStorage()

    def _create_api_key_storage(self, config: AraxysConfig):  # type: ignore
        """Create the API key storage based on config."""
        if self._db_security is not None:
            from araxys.api_keys.storage import RedisAPIKeyStorage

            return RedisAPIKeyStorage(pool=self._db_security.pool)
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
        app.add_middleware(
            HoneypotMiddleware,
            backend=self._rate_backend,
            trusted_proxies=config.trusted_proxies,
        )
        # Register the trap routes
        trap = HoneypotTrap(
            backend=self._rate_backend,
            config=config.honeypot,
            on_audit=self._emit_audit,
            trusted_proxies=config.trusted_proxies,
        )
        trap.register_routes(app)

    def _register_rate_limit(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.rate_limit.enabled:
            return
        app.add_middleware(
            RateLimitMiddleware,
            backend=self._rate_backend,
            config=config.rate_limit,
            trusted_proxies=config.trusted_proxies,
        )

    def _register_sanitize(self, app: FastAPI, config: AraxysConfig) -> None:
        if not config.sanitize.enabled:
            return
        app.add_middleware(SanitizeMiddleware, config=config.sanitize)

    def _register_prompt_injection(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register Prompt Injection middleware (between Sanitize and IP Access).

        The middleware is read-only — it scans query params, JSON body,
        form fields, and multipart uploads without mutating the request.
        Only registered when ``config.prompt_injection`` is not ``None``.
        """
        if config.prompt_injection is None:
            return
        app.add_middleware(
            PromptInjectionMiddleware,
            config=config.prompt_injection,
        )

    def _register_xxe(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register XXE middleware (between Sanitize and PromptInjection).

        The middleware is read-only — it scans XML request bodies for
        XXE attack patterns and returns 400 on detection.
        Only registered when ``config.xxe`` is not ``None``.
        """
        if config.xxe is None:
            return
        app.add_middleware(XXEMiddleware, config=config.xxe)

    def _register_malware(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register Malware middleware (between PromptInjection and Honeypot).

        The middleware is read-only — it scans multipart file uploads
        using heuristic detectors and returns 400 on detection.
        Only registered when ``config.malware`` is not ``None``.
        """
        if config.malware is None:
            return
        app.add_middleware(
            MalwareMiddleware,
            config=config.malware,
        )

    # ── New v0.3 registration methods ────────────────────────────────────

    def _register_cors(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register CORS middleware (outermost — applies to all requests).

        CORS is always registered with the configured policy. By default
        ``allow_origins`` is empty, which means fail-closed (deny all origins).
        """
        app.add_middleware(CORSMiddleware, cors_config=config.cors)

    def _register_telemetry(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register Telemetry middleware (wraps everything below)."""
        if config.telemetry is None or not config.telemetry.enabled:
            return
        app.add_middleware(
            TelemetryMiddleware,
            config=config.telemetry,
            tracer=self._tracer,
            trusted_proxies=config.trusted_proxies,
        )

    def _register_csrf(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register CSRF middleware (between Telemetry and SecureHeaders).

        Only registered when ``config.csrf`` is not ``None`` and
        ``config.csrf.enabled`` is ``True``.
        """
        if config.csrf is None or not config.csrf.enabled:
            return
        app.add_middleware(
            _CSRFMiddleware,
            config=config.csrf,
            handler=self.csrf_handler,
        )

    def _register_account_protection(
        self, app: FastAPI, config: AraxysConfig
    ) -> None:
        """Register Account Protection middleware (between Honeypot and IP Access).

        Normalizes auth endpoint responses — masks 401/403 error detail
        fields and adds timing jitter — to prevent attackers from
        inferring valid usernames or API keys via timing or message
        differences.
        """
        if config.account_protection is None or not config.account_protection.enabled:
            return
        app.add_middleware(
            AccountProtectionMiddleware,
            config=config.account_protection,
            on_audit=self._emit_audit,
        )

    def _register_ip_access(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register IP Access Control middleware (before Honeypot)."""
        if config.ip_control is None or not config.ip_control.enabled:
            return
        backend = self._create_ip_backend(config)
        app.add_middleware(
            IPAccessMiddleware,
            config=config.ip_control,
            backend=backend,
            trusted_proxies=config.trusted_proxies,
        )

    def _register_brute_force(self, app: FastAPI, config: AraxysConfig) -> None:
        """Register Brute Force middleware (after RateLimit)."""
        if config.brute_force is None or not config.brute_force.enabled:
            return
        backend = self._create_bf_backend(config)
        app.add_middleware(
            BruteForceMiddleware, config=config.brute_force, backend=backend
        )

    # ── New v0.3 backend factory methods ──────────────────────────────────

    def _create_ip_backend(
        self, config: AraxysConfig
    ) -> InMemoryIPAccessBackend | RedisIPAccessBackend:
        """Create the IP access backend based on config."""
        if self._db_security is not None:
            # get_redis_client() is the public accessor
            redis = self._db_security.pool.get_redis_client()
            return RedisIPAccessBackend(redis)
        if config.ip_control is None:
            return InMemoryIPAccessBackend()
        if config.ip_control.redis_url:
            logger.info(
                "araxys.using_redis_ip_backend", url=config.ip_control.redis_url
            )
            from redis.asyncio import from_url

            redis = from_url(config.ip_control.redis_url, decode_responses=True)
            return RedisIPAccessBackend(redis)
        logger.info("araxys.using_inmemory_ip_backend")
        return InMemoryIPAccessBackend(
            allowlist=set(config.ip_control.allowlist),
            blocklist=set(config.ip_control.blocklist),
        )

    def _create_bf_backend(
        self, config: AraxysConfig
    ) -> InMemoryBruteForceBackend | RedisBruteForceBackend:
        """Create the brute force backend based on config."""
        bf_config = config.brute_force
        attempt_ttl = bf_config.attempt_ttl_seconds if bf_config else 3600
        if self._db_security is not None:
            redis = self._db_security.pool.get_redis_client()
            return RedisBruteForceBackend(redis, attempt_ttl_seconds=attempt_ttl)
        if bf_config is None:
            return InMemoryBruteForceBackend(attempt_ttl_seconds=attempt_ttl)
        if config.redis_url:
            logger.info("araxys.using_redis_bf_backend", url=config.redis_url)
            from redis.asyncio import from_url

            redis = from_url(config.redis_url, decode_responses=True)
            return RedisBruteForceBackend(redis, attempt_ttl_seconds=attempt_ttl)
        logger.info("araxys.using_inmemory_bf_backend")
        return InMemoryBruteForceBackend(attempt_ttl_seconds=attempt_ttl)

    def _create_session_backend(
        self, config: AraxysConfig
    ) -> InMemorySessionBackend | RedisSessionBackend:
        """Create the session backend based on config."""
        assert config.session is not None  # only called when session enabled
        if self._db_security is not None:
            logger.info("araxys.using_pooled_redis_session_backend")
            return RedisSessionBackend(
                pool=self._db_security.pool,
                session_ttl_seconds=config.session.session_ttl_seconds,
                idle_timeout_seconds=config.session.idle_timeout_seconds,
            )
        if config.session is None:
            return InMemorySessionBackend()
        if config.session.redis_url:
            logger.info(
                "araxys.using_redis_session_backend", url=config.session.redis_url
            )
            return RedisSessionBackend(
                config.session.redis_url,
                session_ttl_seconds=config.session.session_ttl_seconds,
                idle_timeout_seconds=config.session.idle_timeout_seconds,
            )
        logger.info("araxys.using_inmemory_session_backend")
        return InMemorySessionBackend(
            session_ttl_seconds=config.session.session_ttl_seconds,
            idle_timeout_seconds=config.session.idle_timeout_seconds,
        )

    # ── Shutdown ──────────────────────────────────────────────────────────

    async def shutdown(self) -> None:
        """Graceful shutdown of all background tasks and services."""
        # v0.5 — close db pool first
        if self._db_security is not None:
            await self._db_security.shutdown()

        # Stop event bus (drains queued events)
        if self.event_bus is not None:
            await self.event_bus.stop()

        # Stop session cleanup loop
        if self._session_manager is not None:
            await self._session_manager.stop_cleanup()

        # Stop DLQ consumer
        if hasattr(self, "_dlq_consumer") and self._dlq_consumer is not None:
            await self._dlq_consumer.stop()

        logger.info("araxys.shield_shutdown_complete")

    # ── v0.5 — Database Security Properties ───────────────────────────────

    @property
    def db_pool(self) -> ConnectionPool | None:
        """The shared database connection pool, if db_security is enabled."""
        return self._db_security.pool if self._db_security else None

    @property
    def db_auditor(self) -> object | None:
        """The query auditor, if db_security and query_audit are enabled."""
        return self._db_security.auditor if self._db_security else None

    @property
    def rate_backend(self) -> object | None:
        """The rate limit backend, for admin inspection."""
        return self._rate_backend

    @property
    def session_manager(self) -> object | None:
        """The session manager, for admin endpoints."""
        return self._session_manager

    # ── WebAuthn Backend Factories ──────────────────────────────────────────

    def _create_credential_store(
        self, config: AraxysConfig
    ) -> InMemoryCredentialStore | RedisCredentialStore:
        """Create credential store based on config."""
        if self._db_security is not None:
            return RedisCredentialStore(self._db_security.pool.get_redis_client())
        if config.redis_url:
            from redis.asyncio import from_url

            redis = from_url(config.redis_url, decode_responses=True)
            return RedisCredentialStore(redis)
        logger.info(
            "araxys.using_inmemory_credential_store — "
            "NOT suitable for multi-worker deployments."
        )
        return InMemoryCredentialStore()

    def _create_challenge_store(
        self, config: AraxysConfig
    ) -> InMemoryChallengeStore | RedisChallengeStore:
        """Create challenge store based on config."""
        if self._db_security is not None:
            return RedisChallengeStore(self._db_security.pool.get_redis_client())
        if config.redis_url:
            from redis.asyncio import from_url

            redis = from_url(config.redis_url, decode_responses=True)
            return RedisChallengeStore(redis)
        logger.info(
            "araxys.using_inmemory_challenge_store — "
            "NOT suitable for multi-worker deployments."
        )
        return InMemoryChallengeStore()
