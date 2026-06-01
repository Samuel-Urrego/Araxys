"""Araxys — Plug & play security library for FastAPI.

Usage::

    from fastapi import FastAPI
    from araxys import AraxysShield, AraxysConfig

    app = FastAPI()
    shield = AraxysShield(
        app,
        AraxysConfig(secret_key="your-32-char-secret-key-here!!!!"),
    )
"""

# v0.3 middleware imports
from araxys.account_protection import (
    AccountProtectionMiddleware,
    EnumerationDetector,
    apply_rate_limit_presets,
    constant_time_compare,
    normalize_error_message,
    simulate_hash_lookup,
    simulate_verification_work,
)
from araxys.brute_force.limiter import BruteForceBackend, BruteForceMiddleware

# v0.3 module imports
from araxys.brute_force.password_policy import password_policy_dependency
from araxys.core.config import (
    # v0.12 configs
    AccountProtectionConfig,
    AraxysConfig,
    AuditConfig,
    # v0.3 configs
    BruteForceConfig,
    CORSConfig,
    CSRFConfig,
    HoneypotConfig,
    IPControlConfig,
    JWTConfig,
    # v0.8 configs
    MalwareConfig,
    MetricsConfig,
    # OIDC Discovery
    OIDCDiscoveryConfig,
    # v0.7 configs
    PromptInjectionConfig,
    RateLimitConfig,
    SanitizeConfig,
    SecureHeadersConfig,
    SessionConfig,
    TelemetryConfig,
    # v0.6 configs
    WebAuthnConfig,
    WebhookConfig,
)
from araxys.core.exceptions import (  # type: ignore[attr-defined]
    AraxysError,
    # v0.3 exceptions
    BruteForceLockedError,
    CSRFValidationError,
    EncryptionError,
    HoneypotTriggered,
    InvalidAPIKey,
    IPBlockedError,
    # v0.8 exceptions
    MalwareDetectionError,
    # OIDC Discovery
    OIDCDiscoveryError,
    PasswordValidationError,
    # v0.7 exceptions
    PromptInjectionError,
    RateLimitExceeded,
    SanitizationError,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
    WebAuthnError,
)
from araxys.core.types import (
    AuditEntry,
    AuditEventType,
    # v0.7 types
    ScanResult,
    Scope,
    SecurityContext,
    SecurityEvent,
    SecurityEventType,
)
from araxys.cors.middleware import CORSMiddleware
from araxys.csrf.dependencies import csrf_protected, set_csrf_cookie
from araxys.csrf.middleware import CSRFMiddleware
from araxys.csrf.tokens import CSRFHandler
from araxys.db_security import (
    ConnectionPool,
    ConnectionStringResolver,
    DatabaseSecurityManager,
    InMemoryPool,
    RedisClusterPool,
    RedisPool,
    RedisSentinelPool,
    get_db_pool,
    get_query_auditor,
)
from araxys.ip_access.backends import IPAccessBackend
from araxys.ip_access.middleware import IPAccessMiddleware
from araxys.jwt_auth.dependencies import create_jwks_router
from araxys.jwt_auth.storage import InMemoryJWKSStore, JWKSStore
from araxys.jwt_auth.tokens import JWTManager, TokenPair, TokenPayload
from araxys.malware.dependencies import (
    MalwareGuard,
    get_malware_guard,
    get_malware_scanner,
)
from araxys.malware.scanner import MalwareScanner
from araxys.metrics.collector import MetricsRegistry
from araxys.oidc import OIDCDiscoveryClient, OIDCProviderMetadata
from araxys.prompt_injection.dependencies import PromptInjectionGuard
from araxys.sessions.manager import SessionManager
from araxys.sessions.storage import (
    InMemorySessionBackend,
    RedisSessionBackend,
    SessionBackend,
    SessionRecord,
)
from araxys.shield import AraxysShield
from araxys.telemetry.tracer import AraxysTracer
from araxys.webauthn import CredentialRecord, RelyingPartyConfig, WebAuthnManager
from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend
from araxys.webhooks.emitter import SecurityEventBus
from araxys.xxe.config import XXEConfig
from araxys.xxe.dependencies import get_xxe_scanner, xxe_guard
from araxys.xxe.exceptions import XXEError
from araxys.xxe.middleware import XXEMiddleware
from araxys.xxe.scanner import XXEScanner

__all__ = [
    # Main entry point
    "AraxysShield",
    # Configuration
    "AraxysConfig",
    "AuditConfig",
    "HoneypotConfig",
    "JWTConfig",
    "RateLimitConfig",
    "SanitizeConfig",
    "SecureHeadersConfig",
    # v0.3 configs
    "CORSConfig",
    "IPControlConfig",
    "BruteForceConfig",
    "CSRFConfig",
    "SessionConfig",
    "WebhookConfig",
    "MetricsConfig",
    "TelemetryConfig",
    # v0.6 configs
    "WebAuthnConfig",
    # v0.7 configs
    "PromptInjectionConfig",
    # v0.8 configs
    "MalwareConfig",
    # OIDC Discovery
    "OIDCDiscoveryConfig",
    # v0.12 configs
    # Types
    "AuditEntry",
    "AuditEventType",
    "Scope",
    "SecurityContext",
    # v0.3 types
    "SecurityEventType",
    "SecurityEvent",
    # v0.7 types
    "ScanResult",
    # Exceptions
    "AraxysError",
    "EncryptionError",
    "HoneypotTriggered",
    "InvalidAPIKey",
    "RateLimitExceeded",
    "SanitizationError",
    "TokenExpired",
    "TokenInvalid",
    "TokenRevoked",
    # v0.3 exceptions
    "CSRFValidationError",
    "BruteForceLockedError",
    "WebAuthnError",
    "PasswordValidationError",
    "IPBlockedError",
    # v0.7 exceptions
    "PromptInjectionError",
    # v0.8 exceptions
    "MalwareDetectionError",
    # OIDC Discovery
    "OIDCDiscoveryError",
    # v0.12 Account Enumeration Prevention
    "AccountProtectionConfig",
    "AccountProtectionMiddleware",
    "apply_rate_limit_presets",
    "constant_time_compare",
    "normalize_error_message",
    "simulate_hash_lookup",
    "simulate_verification_work",
    "EnumerationDetector",
    # v0.3 modules — middleware
    "CORSMiddleware",
    "IPAccessMiddleware",
    "BruteForceMiddleware",
    # v0.3 modules — middleware
    "CSRFMiddleware",
    # v0.3 modules — handlers
    "CSRFHandler",
    "SessionManager",
    "SecurityEventBus",
    "DLQConsumer",
    "WebhookDLQBackend",
    "MetricsRegistry",
    "AraxysTracer",
    # v0.3 modules — dependencies
    "csrf_protected",
    "password_policy_dependency",
    "set_csrf_cookie",
    # v0.3 modules — backends
    "IPAccessBackend",
    "BruteForceBackend",
    "SessionBackend",
    "InMemorySessionBackend",
    "RedisSessionBackend",
    "SessionRecord",
    # v0.3 JWT additions
    "JWTManager",
    "TokenPair",
    "TokenPayload",
    "JWKSStore",
    "InMemoryJWKSStore",
    "create_jwks_router",
    # v0.6 WebAuthn / Passkeys
    "WebAuthnConfig",
    "WebAuthnManager",
    "CredentialRecord",
    "RelyingPartyConfig",
    # v0.5 Database Security
    "ConnectionPool",
    "ConnectionStringResolver",
    "DatabaseSecurityManager",
    "InMemoryPool",
    "RedisClusterPool",
    "RedisPool",
    "RedisSentinelPool",
    "get_db_pool",
    "get_query_auditor",
    # v0.7 Prompt Injection
    "PromptInjectionGuard",
    # v0.8 Malware Detection
    "MalwareConfig",
    "MalwareDetectionError",
    "MalwareScanner",
    "MalwareGuard",
    "get_malware_guard",
    "get_malware_scanner",
    # v0.13 XXE Protection
    "XXEConfig",
    "XXEError",
    "XXEScanner",
    "XXEMiddleware",
    "xxe_guard",
    "get_xxe_scanner",
    # v0.13 OIDC Discovery (RFC 8414)
    "OIDCDiscoveryClient",
    "OIDCProviderMetadata",
]
