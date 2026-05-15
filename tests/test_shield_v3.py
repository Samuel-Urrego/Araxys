"""Tests for Shield v3 wiring (Task 4.2).

Tests cover:
- Shield initializes with all new configs (no crash)
- CORS config → middleware registered
- IP control enabled → middleware registered
- Brute force enabled → middleware registered
- Telemetry enabled → middleware registered
- Without new configs → works as before (backward compat)
- Shield event_bus accessible after init
- Shield.shutdown() cleans up gracefully
- Middleware chain order correct (check app middleware stack)
- Metrics endpoint mounted when enabled
- Webhook delivery subscribed when enabled
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

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

# ── Fixtures ─────────────────────────────────────────────────────────────  # noqa: E501


@pytest.fixture
def minimal_config() -> AraxysConfig:
    """Minimal v0.2.1-compatible config (no new modules)."""
    return AraxysConfig(secret_key="test-secret-key-1234567890abcdef")


@pytest.fixture
def full_config() -> AraxysConfig:
    """Config with all v0.3 modules enabled."""
    return AraxysConfig(
        secret_key="test-secret-key-1234567890abcdef",
        cors=CORSConfig(allow_origins=["https://example.com"]),
        ip_control=IPControlConfig(
            enabled=True,
            mode="block",
            blocklist=["10.0.0.0/8"],
        ),
        brute_force=BruteForceConfig(
            enabled=True,
            max_attempts=3,
            lockout_duration_seconds=60,
        ),
        csrf=CSRFConfig(enabled=True),
        session=SessionConfig(
            enabled=True,
            max_concurrent_per_user=2,
        ),
        webhooks=WebhookConfig(
            enabled=True,
            urls={"rate_limit_exceeded": ["https://hooks.example.com/alert"]},
        ),
        metrics=MetricsConfig(enabled=True),
        telemetry=TelemetryConfig(enabled=True),
    )


# ── Test: Basic Initialization ───────────────────────────────────────────  # noqa: E501


class TestShieldInit:
    """Shield initialization with various configurations."""

    def test_with_minimal_config_no_crash(self, minimal_config: AraxysConfig) -> None:
        """Shield initializes with v0.2.1 config (backward compat)."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, minimal_config)
        assert shield.config == minimal_config

    async def test_with_full_config_no_crash(self, full_config: AraxysConfig) -> None:
        """Shield initializes with all v0.3 configs (no crash)."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, full_config)
        assert shield.config == full_config

    async def test_event_bus_accessible(self, full_config: AraxysConfig) -> None:
        """Shield.event_bus is accessible after init."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, full_config)
        assert shield.event_bus is not None

    def test_event_bus_none_when_disabled(self, minimal_config: AraxysConfig) -> None:
        """event_bus is None when webhooks not enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, minimal_config)
        assert shield.event_bus is None

    async def test_shutdown_graceful(self, full_config: AraxysConfig) -> None:
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, full_config)
        # Run shutdown — should not raise
        await shield.shutdown()

    def test_shutdown_without_modules(self, minimal_config: AraxysConfig) -> None:
        """Shutdown works even with no optional modules."""
        import asyncio

        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, minimal_config)
        asyncio.run(shield.shutdown())

    async def test_csrf_handler_stored(self, full_config: AraxysConfig) -> None:
        """CSRFHandler is stored on shield for dependency access."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, full_config)
        assert shield.csrf_handler is not None

    def test_csrf_handler_none_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """CSRFHandler is None when CSRF not enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, minimal_config)
        assert shield.csrf_handler is None

    async def test_session_manager_stored(self, full_config: AraxysConfig) -> None:
        """SessionManager is stored on shield when enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, full_config)
        assert shield._session_manager is not None

    def test_session_manager_none_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """SessionManager is None when sessions not enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        shield = AraxysShield(app, minimal_config)
        assert shield._session_manager is None


# ── Test: Middleware Registration ─────────────────────────────────────────  # noqa: E501


class TestMiddlewareRegistration:
    """Verify middlewares are registered correctly."""

    async def test_cors_middleware_registered(self, full_config: AraxysConfig) -> None:
        """CORS middleware is in the app's middleware stack."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, full_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        cors_names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "CORSMiddleware" in cors_names

    async def test_telemetry_middleware_registered(self, full_config: AraxysConfig) -> None:  # noqa: E501
        """Telemetry middleware is in the stack when enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, full_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "TelemetryMiddleware" in names

    async def test_brute_force_middleware_registered(self, full_config: AraxysConfig) -> None:  # noqa: E501
        """BruteForceMiddleware is in the stack when enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, full_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "BruteForceMiddleware" in names

    async def test_ip_access_middleware_registered(self, full_config: AraxysConfig) -> None:  # noqa: E501
        """IPAccessMiddleware is in the stack when enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, full_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "IPAccessMiddleware" in names

    async def test_existing_middlewares_still_present(self, full_config: AraxysConfig) -> None:  # noqa: E501
        """Existing v0.2.1 middlewares still registered."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, full_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "SecureHeadersMiddleware" in names
        assert "RateLimitMiddleware" in names
        assert "HoneypotMiddleware" in names
        assert "SanitizeMiddleware" in names

    def test_telemetry_not_registered_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """Telemetry not registered when disabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, minimal_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "TelemetryMiddleware" not in names

    def test_brute_force_not_registered_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """BruteForce not registered when disabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, minimal_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "BruteForceMiddleware" not in names

    def test_ip_access_not_registered_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """IP Access not registered when disabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, minimal_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "IPAccessMiddleware" not in names

    def test_cors_registered_by_default(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """CORS is registered by default (fail-closed with empty allowlist)."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, minimal_config)

        middleware_classes = [m.cls for m in app.user_middleware]
        names = [cast("Any", cls).__name__ for cls in middleware_classes]
        assert "CORSMiddleware" in names


# ── Test: Metrics Endpoint ────────────────────────────────────────────────  # noqa: E501


class TestMetricsEndpoint:
    """Metrics endpoint mounted when enabled."""

    async def test_metrics_endpoint_accessible(self, full_config: AraxysConfig) -> None:
        """Metrics endpoint returns 200 when enabled."""
        app = FastAPI()
        from araxys import AraxysShield

        with patch("araxys.metrics.collector._prometheus") as mock_prom:
            mock_prom.Counter = MagicMock()
            mock_prom.Histogram = MagicMock()
            mock_prom.generate_latest = MagicMock(return_value=b"# HELP\n")
            mock_prom.__bool__ = MagicMock(return_value=True)

            AraxysShield(app, full_config)
            client = TestClient(app)
            response = client.get("/metrics")
            assert response.status_code == 200

    def test_metrics_endpoint_not_mounted_when_disabled(self, minimal_config: AraxysConfig) -> None:  # noqa: E501
        """Metrics endpoint not available when disabled."""
        app = FastAPI()
        from araxys import AraxysShield

        AraxysShield(app, minimal_config)
        client = TestClient(app)
        response = client.get("/metrics")
        assert response.status_code == 404
