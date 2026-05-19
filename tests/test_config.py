"""Tests for v0.3 configuration models."""

import re

import pytest

from araxys.core.config import (
    AraxysConfig,
    AuditConfig,
    BruteForceConfig,
    CORSConfig,
    CSPDirectiveConfig,
    CSRFConfig,
    DatabaseSecurityConfig,
    IPControlConfig,
    JWTConfig,
    LogShippingConfig,
    MetricsConfig,
    QueryAuditConfig,
    RateLimitConfig,
    RedisPoolConfig,
    SanitizeConfig,
    SecretsConfig,
    SecureHeadersConfig,
    SessionConfig,
    TelemetryConfig,
    TLSConfig,
    WebhookConfig,
)


class TestCORSConfig:
    def test_defaults(self) -> None:
        c = CORSConfig()
        assert c.allow_origins == []
        assert c.allow_methods == ["GET"]
        assert c.allow_headers == ["*"]
        assert c.allow_credentials is False
        assert c.expose_headers == []
        assert c.max_age == 600

    def test_custom_values(self) -> None:
        c = CORSConfig(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "POST"],
            allow_credentials=True,
            max_age=3600,
        )
        assert c.allow_origins == ["https://app.example.com"]
        assert c.allow_methods == ["GET", "POST"]
        assert c.allow_credentials is True
        assert c.max_age == 3600


class TestIPControlConfig:
    def test_defaults(self) -> None:
        c = IPControlConfig()
        assert c.enabled is False
        assert c.mode == "block"
        assert c.allowlist == []
        assert c.blocklist == []
        assert c.redis_url is None

    def test_custom_values(self) -> None:
        c = IPControlConfig(
            enabled=True,
            mode="allow",
            allowlist=["10.0.0.0/8"],
            blocklist=["1.2.3.4"],
            redis_url="redis://localhost:6379/1",
        )
        assert c.enabled is True
        assert c.mode == "allow"
        assert c.allowlist == ["10.0.0.0/8"]
        assert c.blocklist == ["1.2.3.4"]
        assert c.redis_url == "redis://localhost:6379/1"


class TestBruteForceConfig:
    def test_defaults(self) -> None:
        c = BruteForceConfig()
        assert c.enabled is False
        assert c.max_attempts == 5
        assert c.lockout_duration_seconds == 900
        assert c.identifier_field == "username"
        assert c.check_hibp is False

    def test_custom_values(self) -> None:
        c = BruteForceConfig(
            enabled=True,
            max_attempts=3,
            lockout_duration_seconds=1800,
            identifier_field="email",
            check_hibp=True,
        )
        assert c.enabled is True
        assert c.max_attempts == 3
        assert c.lockout_duration_seconds == 1800
        assert c.identifier_field == "email"
        assert c.check_hibp is True


class TestCSRFConfig:
    def test_defaults(self) -> None:
        c = CSRFConfig()
        assert c.enabled is False
        assert c.token_expiry_seconds == 3600
        assert c.cookie_name == "csrf_token"
        assert c.header_name == "X-CSRF-Token"
        assert c.secure_cookie is True

    def test_custom_values(self) -> None:
        c = CSRFConfig(
            enabled=True,
            token_expiry_seconds=1800,
            cookie_name="xsrf_token",
            header_name="X-XSRF-Token",
            secure_cookie=False,
        )
        assert c.enabled is True
        assert c.token_expiry_seconds == 1800
        assert c.cookie_name == "xsrf_token"
        assert c.header_name == "X-XSRF-Token"
        assert c.secure_cookie is False


class TestSessionConfig:
    def test_defaults(self) -> None:
        c = SessionConfig()
        assert c.enabled is False
        assert c.max_concurrent_per_user == 5
        assert c.cleanup_interval_seconds == 60
        assert c.redis_url is None

    def test_custom_values(self) -> None:
        c = SessionConfig(
            enabled=True,
            max_concurrent_per_user=2,
            cleanup_interval_seconds=120,
            redis_url="redis://localhost:6379/2",
        )
        assert c.enabled is True
        assert c.max_concurrent_per_user == 2
        assert c.cleanup_interval_seconds == 120
        assert c.redis_url == "redis://localhost:6379/2"


class TestWebhookConfig:
    def test_defaults(self) -> None:
        c = WebhookConfig()
        assert c.enabled is False
        assert c.urls == {}
        assert c.retry_max == 3
        assert c.timeout_seconds == 5
        assert c.queue_size == 1000

    def test_custom_values(self) -> None:
        c = WebhookConfig(
            enabled=True,
            urls={"rate_limit_exceeded": ["https://hooks.example.com/alerts"]},
            retry_max=5,
            timeout_seconds=10,
            queue_size=500,
        )
        assert c.enabled is True
        assert c.urls == {
            "rate_limit_exceeded": ["https://hooks.example.com/alerts"]
        }
        assert c.retry_max == 5
        assert c.timeout_seconds == 10
        assert c.queue_size == 500


class TestMetricsConfig:
    def test_defaults(self) -> None:
        c = MetricsConfig()
        assert c.enabled is False
        assert c.path == "/metrics"

    def test_custom_values(self) -> None:
        c = MetricsConfig(enabled=True, path="/custom-metrics")
        assert c.enabled is True
        assert c.path == "/custom-metrics"


class TestTelemetryConfig:
    def test_defaults(self) -> None:
        c = TelemetryConfig()
        assert c.enabled is False
        assert c.service_name == "araxys"
        assert c.exporter_endpoint is None
        assert c.sample_rate == 1.0

    def test_custom_values(self) -> None:
        c = TelemetryConfig(
            enabled=True,
            service_name="my-app",
            exporter_endpoint="http://otel-collector:4318",
            sample_rate=0.5,
        )
        assert c.enabled is True
        assert c.service_name == "my-app"
        assert c.exporter_endpoint == "http://otel-collector:4318"
        assert c.sample_rate == 0.5


class TestNestedInAraxysConfig:
    """All 8 new configs must be optional fields in AraxysConfig."""

    def test_defaults_are_none(self) -> None:
        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        # CORS is always created by default (fail-closed with empty allowlist)
        assert c.cors is not None
        assert c.cors.allow_origins == []
        assert c.cors.allow_methods == ["GET"]
        # All other v0.3 modules are disabled by default
        assert c.ip_control is None
        assert c.brute_force is None
        assert c.csrf is None
        assert c.session is None
        assert c.webhooks is None
        assert c.metrics is None
        assert c.telemetry is None

    def test_cors_provided(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            cors={"allow_origins": ["https://app.example.com"]},  # type: ignore
        )
        assert c.cors is not None
        assert c.cors.allow_origins == ["https://app.example.com"]

    def test_ip_control_provided(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            ip_control={"enabled": True, "mode": "allow"},  # type: ignore
        )
        assert c.ip_control is not None
        assert c.ip_control.enabled is True
        assert c.ip_control.mode == "allow"

    def test_multiple_nested_configs(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            cors={"allow_origins": ["*"]},  # type: ignore
            webhooks={"enabled": True, "queue_size": 2000},  # type: ignore
            metrics={"enabled": True},  # type: ignore
        )
        assert c.cors is not None
        assert c.cors.allow_origins == ["*"]
        assert c.webhooks is not None
        assert c.webhooks.enabled is True
        assert c.webhooks.queue_size == 2000
        assert c.metrics is not None
        assert c.metrics.enabled is True
        assert c.metrics.path == "/metrics"  # default
        assert c.ip_control is None
        assert c.brute_force is None


class TestJWTConfig:
    """Tests for JWT configuration model."""

    def test_defaults(self) -> None:
        c = JWTConfig()
        assert c.algorithm == "HS256"
        assert c.access_token_ttl_minutes == 30
        assert c.refresh_token_ttl_days == 7
        assert c.issuer is None
        assert c.audience is None
        assert c.private_key is None
        assert c.public_key is None
        assert c.jwks_enabled is False

    def test_custom_values(self) -> None:
        c = JWTConfig(
            algorithm="RS256",
            access_token_ttl_minutes=15,
            issuer="https://auth.example.com",
            private_key="-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----",
            public_key="-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----",
            jwks_enabled=True,
        )
        assert c.algorithm == "RS256"
        assert c.access_token_ttl_minutes == 15
        assert c.issuer == "https://auth.example.com"
        assert c.private_key is not None
        assert c.public_key is not None
        assert c.jwks_enabled is True

    def test_es256_algorithm(self) -> None:
        c = JWTConfig(algorithm="ES256")
        assert c.algorithm == "ES256"


class TestRateLimitConfig:
    """Tests for rate limit configuration model."""

    def test_defaults(self) -> None:
        c = RateLimitConfig()
        assert c.enabled is True
        assert c.window_seconds == 60
        assert c.max_requests == 100
        assert c.per_user is False
        assert c.per_api_key is False
        assert c.path_limits == {}

    def test_custom_values(self) -> None:
        c = RateLimitConfig(
            max_requests=50,
            per_user=True,
            per_api_key=True,
            path_limits={
                "/auth/login": RateLimitConfig(max_requests=10, window_seconds=300),
            },
        )
        assert c.per_user is True
        assert c.per_api_key is True
        assert "/auth/login" in c.path_limits
        assert c.path_limits["/auth/login"].max_requests == 10
        assert c.path_limits["/auth/login"].window_seconds == 300


class TestAuditConfig:
    """Tests for audit configuration model."""

    def test_defaults(self) -> None:
        c = AuditConfig()
        assert c.enabled is True
        assert c.encrypt is True
        assert c.log_file is None
        assert c.log_rotation_bytes == 0
        assert c.log_backup_count == 5
        assert c.async_write is False
        assert c.pii_fields == []
        assert c.log_shipping is None

    def test_custom_values(self) -> None:
        c = AuditConfig(
            log_file="/var/log/audit.log",
            log_rotation_bytes=10_485_760,
            log_backup_count=3,
            async_write=True,
            pii_fields=["email", "password"],
            log_shipping=LogShippingConfig(
                type="http",
                endpoint="https://logs.example.com/ingest",
                headers={"Authorization": "Bearer token123"},
                tls_enabled=True,
            ),
        )
        assert c.log_rotation_bytes == 10_485_760
        assert c.log_backup_count == 3
        assert c.async_write is True
        assert c.pii_fields == ["email", "password"]
        assert c.log_shipping is not None
        assert c.log_shipping.type == "http"
        assert c.log_shipping.endpoint == "https://logs.example.com/ingest"
        assert c.log_shipping.tls_enabled is True


class TestLogShippingConfig:
    """Tests for log shipping configuration model."""

    def test_defaults(self) -> None:
        c = LogShippingConfig()
        assert c.type == "http"
        assert c.endpoint == ""
        assert c.headers is None
        assert c.tls_enabled is True

    def test_custom_values(self) -> None:
        c = LogShippingConfig(
            type="syslog",
            endpoint="udp://logs.example.com:514",
            headers=None,
            tls_enabled=False,
        )
        assert c.type == "syslog"
        assert c.endpoint == "udp://logs.example.com:514"
        assert c.tls_enabled is False

    def test_with_headers(self) -> None:
        c = LogShippingConfig(
            type="http",
            endpoint="https://logs.example.com/ingest",
            headers={"X-API-Key": "abc123"},
        )
        assert c.headers == {"X-API-Key": "abc123"}


class TestCSPDirectiveConfig:
    """Tests for CSP directive configuration model."""

    def test_defaults(self) -> None:
        c = CSPDirectiveConfig()
        assert "'self'" in c.default_src
        assert "'self'" in c.script_src
        assert "'none'" in c.object_src
        assert c.report_uri is None
        assert c.upgrade_insecure_requests is False

    def test_custom_values(self) -> None:
        c = CSPDirectiveConfig(
            default_src=["'self'", "https://cdn.example.com"],
            script_src=["'self'", "'unsafe-inline'"],
            upgrade_insecure_requests=True,
        )
        assert "https://cdn.example.com" in c.default_src
        assert "'unsafe-inline'" in c.script_src
        assert c.upgrade_insecure_requests is True


class TestSecureHeadersConfig:
    """Tests for secure headers configuration model."""

    def test_defaults(self) -> None:
        c = SecureHeadersConfig()
        assert c.enabled is True
        assert c.hsts_max_age == 31_536_000
        assert c.frame_options == "DENY"
        assert c.coop == "same-origin"
        assert c.coep is None
        assert c.corp == "same-origin"
        assert c.hide_server is True
        assert c.csp_directives is None

    def test_custom_values(self) -> None:
        c = SecureHeadersConfig(
            coop="unsafe-none",
            coep="require-corp",
            corp="cross-origin",
            hide_server=False,
            csp_directives=CSPDirectiveConfig(
                default_src=["'self'"],
                script_src=["'self'"],
            ),
        )
        assert c.coop == "unsafe-none"
        assert c.coep == "require-corp"
        assert c.corp == "cross-origin"
        assert c.hide_server is False
        assert c.csp_directives is not None
        assert "'self'" in c.csp_directives.default_src
        assert "'self'" in c.csp_directives.script_src


class TestSanitizeConfig:
    """Tests for sanitize configuration model."""

    def test_defaults(self) -> None:
        c = SanitizeConfig()
        assert c.enabled is True
        assert c.block_sqli is True
        assert c.strip_xss is True
        assert c.scan_query_params is False
        assert c.scan_headers is False
        assert c.check_nosql_injection is False
        assert c.check_command_injection is False
        assert c.check_path_traversal is False

    def test_custom_values(self) -> None:
        c = SanitizeConfig(
            scan_query_params=True,
            scan_headers=True,
            check_nosql_injection=True,
            check_command_injection=True,
            check_path_traversal=True,
        )
        assert c.scan_query_params is True
        assert c.scan_headers is True
        assert c.check_nosql_injection is True
        assert c.check_command_injection is True
        assert c.check_path_traversal is True


class TestNewConfigsInAraxysConfig:
    """Tests that new config fields are accessible via AraxysConfig."""

    def test_defaults_unchanged(self) -> None:
        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        assert c.jwt.jwks_enabled is False
        assert c.rate_limit.per_user is False
        assert c.audit.async_write is False
        assert c.sanitize.scan_query_params is False
        assert c.secure_headers.coop == "same-origin"

    def test_nested_config_provided(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            jwt={"private_key": "pem-key", "jwks_enabled": True},  # type: ignore[arg-type]
            audit={"async_write": True, "pii_fields": ["email"]},  # type: ignore[arg-type]
        )
        assert c.jwt.private_key == "pem-key"
        assert c.jwt.jwks_enabled is True
        assert c.audit.async_write is True
        assert c.audit.pii_fields == ["email"]


class TestDatabaseSecurityConfig:
    """DatabaseSecurityConfig and nested sub-configs (v0.5 db_security)."""

    def test_redis_pool_config_defaults(self) -> None:
        c = RedisPoolConfig()
        assert c.url == "redis://localhost:6379"
        assert c.max_size == 10
        assert c.idle_timeout_seconds == 300
        assert c.acquire_timeout_seconds == 5.0
        assert c.leak_threshold == 10
        assert c.health_check_interval_seconds == 30

    def test_tls_config_defaults(self) -> None:
        c = TLSConfig()
        assert c.enabled is False
        assert c.ca_cert_path is None
        assert c.cert_pin_sha256 is None
        assert c.min_tls_version == "TLSv1.2"

    def test_secrets_config_defaults(self) -> None:
        c = SecretsConfig()
        assert c.enabled is False
        assert c.vault_url is None
        assert c.vault_token is None
        assert c.vault_mount_path == "araxys"
        assert c.aws_region is None
        assert c.aws_secret_prefix == "araxys/"

    def test_query_audit_config_defaults(self) -> None:
        c = QueryAuditConfig()
        assert c.enabled is True
        assert c.slow_query_threshold_ms == 100

    def test_database_security_config_defaults(self) -> None:
        c = DatabaseSecurityConfig()
        assert c.enabled is False
        assert isinstance(c.redis_pool, RedisPoolConfig)
        assert isinstance(c.tls, TLSConfig)
        assert isinstance(c.secrets, SecretsConfig)
        assert isinstance(c.query_audit, QueryAuditConfig)
        # Verify nested defaults
        assert c.redis_pool.url == "redis://localhost:6379"
        assert c.tls.min_tls_version == "TLSv1.2"
        assert c.query_audit.slow_query_threshold_ms == 100

    def test_database_security_config_custom(self) -> None:
        c = DatabaseSecurityConfig(
            enabled=True,
            redis_pool={"url": "redis://custom:6379", "max_size": 5},  # type: ignore[arg-type]
            tls={"enabled": True, "min_tls_version": "TLSv1.3"},  # type: ignore[arg-type]
        )
        assert c.enabled is True
        assert c.redis_pool.url == "redis://custom:6379"
        assert c.redis_pool.max_size == 5
        assert c.tls.enabled is True
        assert c.tls.min_tls_version == "TLSv1.3"

    def test_redis_pool_ge_validation(self) -> None:
        with pytest.raises(
            Exception, match=re.escape("Input should be greater than or equal to 1")
        ):
            RedisPoolConfig(max_size=0)

        with pytest.raises(
            Exception, match=re.escape("Input should be greater than or equal to 1")
        ):
            QueryAuditConfig(slow_query_threshold_ms=0)


class TestDatabaseSecurityInAraxysConfig:
    """db_security must be optional in AraxysConfig."""

    def test_db_security_defaults_to_none(self) -> None:
        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        assert c.db_security is None

    def test_db_security_explicit_none(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            db_security=None,
        )
        assert c.db_security is None

    def test_db_security_with_defaults(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            db_security={},  # type: ignore[arg-type]
        )
        assert c.db_security is not None
        assert c.db_security.enabled is False
        assert c.db_security.redis_pool.url == "redis://localhost:6379"

    def test_db_security_custom_values(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            db_security={  # type: ignore[arg-type]
                "enabled": True,
                "redis_pool": {"url": "redis://secure:6380", "max_size": 20},
                "tls": {"enabled": True},
                "query_audit": {"slow_query_threshold_ms": 500},
            },
        )
        assert c.db_security is not None
        assert c.db_security.enabled is True
        assert c.db_security.redis_pool.url == "redis://secure:6380"
        assert c.db_security.redis_pool.max_size == 20
        assert c.db_security.tls.enabled is True
        assert c.db_security.query_audit.slow_query_threshold_ms == 500
