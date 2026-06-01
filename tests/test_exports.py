"""Tests for public API exports (Task 4.3).

Verifies that all new v0.3 exports are importable from ``araxys`` and
that existing exports remain intact (backward compatibility).
"""

from __future__ import annotations


class TestNewConfigExports:
    """All new v0.3 config classes must be importable from araxys."""

    def test_cors_config(self) -> None:
        from araxys import CORSConfig  # noqa: F811
        assert CORSConfig is not None

    def test_ip_control_config(self) -> None:
        from araxys import IPControlConfig
        assert IPControlConfig is not None

    def test_brute_force_config(self) -> None:
        from araxys import BruteForceConfig
        assert BruteForceConfig is not None

    def test_csrf_config(self) -> None:
        from araxys import CSRFConfig
        assert CSRFConfig is not None

    def test_session_config(self) -> None:
        from araxys import SessionConfig
        assert SessionConfig is not None

    def test_webhook_config(self) -> None:
        from araxys import WebhookConfig
        assert WebhookConfig is not None

    def test_metrics_config(self) -> None:
        from araxys import MetricsConfig
        assert MetricsConfig is not None

    def test_telemetry_config(self) -> None:
        from araxys import TelemetryConfig
        assert TelemetryConfig is not None


class TestNewExceptionExports:
    """All new v0.3 exception classes must be importable from araxys."""

    def test_csrf_validation_error(self) -> None:
        from araxys import CSRFValidationError
        assert CSRFValidationError is not None

    def test_brute_force_locked_error(self) -> None:
        from araxys import BruteForceLockedError
        assert BruteForceLockedError is not None

    def test_password_validation_error(self) -> None:
        from araxys import PasswordValidationError
        assert PasswordValidationError is not None

    def test_ip_blocked_error(self) -> None:
        from araxys import IPBlockedError
        assert IPBlockedError is not None


class TestNewTypeExports:
    """All new v0.3 types must be importable from araxys."""

    def test_security_event_type(self) -> None:
        from araxys import SecurityEventType
        assert SecurityEventType is not None

    def test_security_event(self) -> None:
        from araxys import SecurityEvent
        assert SecurityEvent is not None


class TestNewModuleClassExports:
    """All new v0.3 module classes must be importable from araxys."""

    def test_cors_middleware(self) -> None:
        from araxys import CORSMiddleware
        assert CORSMiddleware is not None

    def test_ip_access_middleware(self) -> None:
        from araxys import IPAccessMiddleware
        assert IPAccessMiddleware is not None

    def test_brute_force_middleware(self) -> None:
        from araxys import BruteForceMiddleware
        assert BruteForceMiddleware is not None

    def test_csrf_handler(self) -> None:
        from araxys import CSRFHandler
        assert CSRFHandler is not None

    def test_session_manager(self) -> None:
        from araxys import SessionManager
        assert SessionManager is not None

    def test_security_event_bus(self) -> None:
        from araxys import SecurityEventBus
        assert SecurityEventBus is not None

    def test_metrics_registry(self) -> None:
        from araxys import MetricsRegistry
        assert MetricsRegistry is not None

    def test_araxys_tracer(self) -> None:
        from araxys import AraxysTracer
        assert AraxysTracer is not None


class TestNewDependencyExports:
    """New dependencies must be importable from araxys."""

    def test_csrf_protected(self) -> None:
        from araxys import csrf_protected
        assert csrf_protected is not None

    def test_password_policy_dependency(self) -> None:
        from araxys import password_policy_dependency
        assert password_policy_dependency is not None

    def test_set_csrf_cookie(self) -> None:
        from araxys import set_csrf_cookie
        assert set_csrf_cookie is not None


class TestNewBackendExports:
    """New Protocol backend classes must be importable from araxys."""

    def test_ip_access_backend(self) -> None:
        from araxys import IPAccessBackend
        assert IPAccessBackend is not None

    def test_brute_force_backend(self) -> None:
        from araxys import BruteForceBackend
        assert BruteForceBackend is not None

    def test_session_backend(self) -> None:
        from araxys import SessionBackend
        assert SessionBackend is not None


class TestExistingExports:
    """Existing v0.2.1 exports must still work (backward compatibility)."""

    def test_araxys_shield(self) -> None:
        from araxys import AraxysShield
        assert AraxysShield is not None

    def test_araxys_config(self) -> None:
        from araxys import AraxysConfig
        assert AraxysConfig is not None

    def test_existing_configs(self) -> None:
        from araxys import (
            AuditConfig,
            HoneypotConfig,
            JWTConfig,
            RateLimitConfig,
            SanitizeConfig,
            SecureHeadersConfig,
        )
        assert AuditConfig is not None
        assert HoneypotConfig is not None
        assert JWTConfig is not None
        assert RateLimitConfig is not None
        assert SanitizeConfig is not None
        assert SecureHeadersConfig is not None

    def test_existing_audit_entry(self) -> None:
        from araxys import AuditEntry
        assert AuditEntry is not None

    def test_audit_event_type(self) -> None:
        from araxys import AuditEventType
        assert AuditEventType is not None

    def test_scope(self) -> None:
        from araxys import Scope
        assert Scope is not None

    def test_security_context(self) -> None:
        from araxys import SecurityContext
        assert SecurityContext is not None

    def test_existing_exceptions(self) -> None:
        from araxys import (
            AraxysError,
            EncryptionError,
            HoneypotTriggered,
            InvalidAPIKey,
            RateLimitExceeded,
            SanitizationError,
            TokenExpired,
            TokenInvalid,
            TokenRevoked,
        )
        assert AraxysError is not None
        assert EncryptionError is not None
        assert HoneypotTriggered is not None
        assert InvalidAPIKey is not None
        assert RateLimitExceeded is not None
        assert SanitizationError is not None
        assert TokenExpired is not None
        assert TokenInvalid is not None
        assert TokenRevoked is not None


class TestOIDCDiscoveryExports:
    """All OIDC Discovery types must be importable from araxys."""

    def test_oidc_discovery_client(self) -> None:
        from araxys import OIDCDiscoveryClient  # noqa: F811
        assert OIDCDiscoveryClient is not None

    def test_oidc_provider_metadata(self) -> None:
        from araxys import OIDCProviderMetadata
        assert OIDCProviderMetadata is not None

    def test_oidc_discovery_error(self) -> None:
        from araxys import OIDCDiscoveryError
        assert OIDCDiscoveryError is not None

    def test_oidc_discovery_config(self) -> None:
        from araxys import OIDCDiscoveryConfig
        assert OIDCDiscoveryConfig is not None
