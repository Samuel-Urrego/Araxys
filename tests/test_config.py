"""Tests for v0.3 configuration models."""

from araxys.core.config import (
    AraxysConfig,
    BruteForceConfig,
    CORSConfig,
    CSRFConfig,
    IPControlConfig,
    MetricsConfig,
    SessionConfig,
    TelemetryConfig,
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
