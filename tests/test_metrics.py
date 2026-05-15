"""Tests for the Prometheus Metrics module (Task 4.1).

Tests cover:
- MetricsRegistry disabled → all methods no-op
- Counter increment via record_* methods (mocked prometheus_client)
- No crash when prometheus_client not available
- subscribe_to_event_bus wiring
- metrics_endpoint returns prometheus format / 404 when disabled
- mount_metrics registers route on FastAPI app
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from araxys.core.config import MetricsConfig
from araxys.core.types import SecurityEvent, SecurityEventType

# ── Fixtures ─────────────────────────────────────────────────────────────  # noqa: E501


@pytest.fixture
def mock_prometheus() -> Any:
    """Mock the prometheus_client module for testing."""
    with patch("araxys.metrics.collector._prometheus") as mock:
        # Fake Counter that tracks labels and inc calls
        class FakeCounter:
            def __init__(  # noqa: PLR0913
                self,
                name: str,
                desc: str,
                labelnames: tuple[str, ...] | None = None,
                **kwargs: object,
            ) -> None:
                self.name = name
                self.desc = desc
                self.labelnames = labelnames or ()
                self._label_calls: list[dict[str, str]] = []
                self._inc_calls: list[float] = []

            def labels(self, **labels: str) -> FakeCounter:
                self._label_calls.append(labels)
                return self

            def inc(self, value: float = 1) -> None:
                self._inc_calls.append(value)

        class FakeHistogram:
            def __init__(  # noqa: PLR0913
                self,
                name: str,
                desc: str,
                labelnames: tuple[str, ...] | None = None,
                **kwargs: object,
            ) -> None:
                self.name = name
                self.desc = desc
                self.labelnames = labelnames or ()
                self._label_calls: list[dict[str, str]] = []
                self._observe_calls: list[float] = []

            def labels(self, **labels: str) -> FakeHistogram:
                self._label_calls.append(labels)
                return self

            def observe(self, amount: float) -> None:
                self._observe_calls.append(amount)

        mock.Counter = FakeCounter
        mock.Histogram = FakeHistogram
        mock.generate_latest = MagicMock(return_value=b"# HELP araxys mock metrics\n")
        mock.__bool__ = MagicMock(return_value=True)
        yield mock


@pytest.fixture
def mock_prometheus_unavailable() -> Any:
    """Simulate prometheus_client not being installed."""
    with patch("araxys.metrics.collector._prometheus", None):
        yield


# ── Test MetricsRegistry ──────────────────────────────────────────────────  # noqa: E501


class TestMetricsRegistryDisabled:
    """MetricsRegistry with enabled=False → all methods no-op."""

    def test_disabled_no_crash(self) -> None:
        """No crash when calling any method on disabled registry."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=False)
        registry = MetricsRegistry(config)

        # All of these should be no-ops
        registry.record_rate_limit_exceeded("/api/login")
        registry.record_honeypot_triggered("/wp-admin")
        registry.record_sanitize_blocked("sqli")
        registry.record_jwt_token_rotated()
        registry.record_csrf_validation_failed()
        registry.record_brute_force_lockout("admin")
        registry.record_ip_blocked("allow")
        registry.record_session_revoked()
        registry.record_security_event("test_event")
        registry.record_middleware_duration("rate_limit", 0.05)

    def test_disabled_no_counters_created(self) -> None:
        """Disabled registry should create no counters."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=False)
        registry = MetricsRegistry(config)
        assert registry._counters == {}
        assert registry._histograms == {}


class TestMetricsRegistryEnabled:
    """MetricsRegistry with enabled=True and prometheus_client available."""

    def test_creates_all_counters_on_init(self, mock_prometheus: Any) -> None:
        """All expected counters are created at init time."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)

        assert "rate_limit_exceeded" in registry._counters
        assert "honeypot_triggered" in registry._counters
        assert "sanitize_blocked" in registry._counters
        assert "jwt_token_rotated" in registry._counters
        assert "csrf_validation_failed" in registry._counters
        assert "brute_force_lockout" in registry._counters
        assert "ip_blocked" in registry._counters
        assert "session_revoked" in registry._counters
        assert "security_events" in registry._counters

    def test_creates_histogram_on_init(self, mock_prometheus: Any) -> None:
        """Middleware duration histogram is created at init time."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)

        assert "middleware_duration" in registry._histograms

    def test_record_rate_limit_exceeded(self, mock_prometheus: Any) -> None:
        """record_rate_limit_exceeded increments the counter with endpoint label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["rate_limit_exceeded"]

        registry.record_rate_limit_exceeded("/api/login")

        assert len(counter._label_calls) == 1
        assert counter._label_calls[0] == {"endpoint": "/api/login"}
        assert counter._inc_calls == [1]

    def test_record_honeypot_triggered(self, mock_prometheus: Any) -> None:
        """record_honeypot_triggered increments counter with path label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["honeypot_triggered"]

        registry.record_honeypot_triggered("/wp-admin")

        assert counter._label_calls[0] == {"path": "/wp-admin"}
        assert counter._inc_calls == [1]

    def test_record_sanitize_blocked(self, mock_prometheus: Any) -> None:
        """record_sanitize_blocked increments counter with attack_type label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["sanitize_blocked"]

        registry.record_sanitize_blocked("sqli")

        assert counter._label_calls[0] == {"attack_type": "sqli"}
        assert counter._inc_calls == [1]

    def test_record_jwt_token_rotated(self, mock_prometheus: Any) -> None:
        """record_jwt_token_rotated increments a label-less counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["jwt_token_rotated"]

        registry.record_jwt_token_rotated()

        assert counter._inc_calls == [1]

    def test_record_csrf_validation_failed(self, mock_prometheus: Any) -> None:
        """record_csrf_validation_failed increments a label-less counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["csrf_validation_failed"]

        registry.record_csrf_validation_failed()

        assert counter._inc_calls == [1]

    def test_record_brute_force_lockout(self, mock_prometheus: Any) -> None:
        """record_brute_force_lockout increments counter with identifier label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["brute_force_lockout"]

        registry.record_brute_force_lockout("admin")

        assert counter._label_calls[0] == {"identifier": "admin"}
        assert counter._inc_calls == [1]

    def test_record_ip_blocked(self, mock_prometheus: Any) -> None:
        """record_ip_blocked increments counter with mode label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["ip_blocked"]

        registry.record_ip_blocked("block")

        assert counter._label_calls[0] == {"mode": "block"}
        assert counter._inc_calls == [1]

    def test_record_session_revoked(self, mock_prometheus: Any) -> None:
        """record_session_revoked increments a label-less counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["session_revoked"]

        registry.record_session_revoked()

        assert counter._inc_calls == [1]

    def test_record_security_event(self, mock_prometheus: Any) -> None:
        """record_security_event increments the catchall counter with event_type label."""  # noqa: E501
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["security_events"]

        registry.record_security_event("password_validation_failed")

        assert counter._label_calls[0] == {"event_type": "password_validation_failed"}
        assert counter._inc_calls == [1]

    def test_record_middleware_duration(self, mock_prometheus: Any) -> None:
        """record_middleware_duration records duration with middleware_name label."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        histogram = registry._histograms["middleware_duration"]

        registry.record_middleware_duration("rate_limit", 0.05)

        assert histogram._label_calls[0] == {"middleware_name": "rate_limit"}
        assert histogram._observe_calls == [0.05]

    def test_subscribe_to_event_bus(self, mock_prometheus: Any) -> None:
        """subscribe_to_event_bus wires up correctly."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        event_bus = MagicMock()
        event_bus.subscribe = MagicMock()

        registry.subscribe_to_event_bus(event_bus)

        event_bus.subscribe.assert_called_once_with(registry._on_event)

    def test_event_bus_mapping_rate_limit_exceeded(self, mock_prometheus: Any) -> None:
        """Rate limit security event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["rate_limit_exceeded"]

        event = SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity="warning",
            message="Too many requests",
            metadata={"endpoint": "/api/login"},
        )

        # Run the event handler
        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"endpoint": "/api/login"}
        assert counter._inc_calls == [1]

    def test_event_bus_mapping_honeypot_triggered(self, mock_prometheus: Any) -> None:
        """Honeypot security event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["honeypot_triggered"]

        event = SecurityEvent(
            event_type=SecurityEventType.HONEYPOT_TRIGGERED,
            severity="warning",
            message="Honeypot hit",
            metadata={"path": "/wp-admin"},
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"path": "/wp-admin"}
        assert counter._inc_calls == [1]

    def test_event_bus_mapping_brute_force_lockout(self, mock_prometheus: Any) -> None:
        """Brute force lockout event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["brute_force_lockout"]

        event = SecurityEvent(
            event_type=SecurityEventType.BRUTE_FORCE_LOCKOUT,
            severity="warning",
            message="Locked out",
            metadata={"identifier": "admin"},
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"identifier": "admin"}
        assert counter._inc_calls == [1]

    def test_event_bus_mapping_ip_blocked(self, mock_prometheus: Any) -> None:
        """IP blocked event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["ip_blocked"]

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="warning",
            message="IP blocked",
            metadata={"mode": "allow"},
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"mode": "allow"}
        assert counter._inc_calls == [1]

    def test_event_bus_mapping_csrf_failed(self, mock_prometheus: Any) -> None:
        """CSRF validation failed event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["csrf_validation_failed"]

        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VALIDATION_FAILED,
            severity="warning",
            message="CSRF mismatch",
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._inc_calls == [1]

    def test_event_bus_mapping_token_rotated(self, mock_prometheus: Any) -> None:
        """Token rotated event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["jwt_token_rotated"]

        event = SecurityEvent(
            event_type=SecurityEventType.TOKEN_ROTATED,
            severity="info",
            message="Token rotated",
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._inc_calls == [1]

    def test_event_bus_mapping_session_revoked(self, mock_prometheus: Any) -> None:
        """Session revoked event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["session_revoked"]

        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_REVOKED,
            severity="info",
            message="Session revoked",
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._inc_calls == [1]

    def test_event_bus_mapping_sanitize_blocked(self, mock_prometheus: Any) -> None:
        """Sanitize blocked event increments correct counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["sanitize_blocked"]

        event = SecurityEvent(
            event_type=SecurityEventType.SANITIZE_BLOCKED,
            severity="critical",
            message="SQLi blocked",
            metadata={"attack_type": "sqli"},
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"attack_type": "sqli"}
        assert counter._inc_calls == [1]

    def test_event_bus_mapping_catchall_security_event(self, mock_prometheus: Any) -> None:  # noqa: E501
        """Unmapped event types increment catchall security_events counter."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        counter = registry._counters["security_events"]

        event = SecurityEvent(
            event_type=SecurityEventType.PASSWORD_VALIDATION_FAILED,
            severity="warning",
            message="Password validation failed",
        )

        import asyncio
        asyncio.run(registry._on_event(event))

        assert counter._label_calls[0] == {"event_type": "password_validation_failed"}
        assert counter._inc_calls == [1]


class TestMetricsRegistryUnavailable:
    """MetricsRegistry when prometheus_client is not installed."""

    def test_unavailable_no_crash(self, mock_prometheus_unavailable: Any) -> None:
        """No crash when prometheus is not available."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)

        # All methods should be no-ops
        registry.record_rate_limit_exceeded("/api/login")
        registry.record_honeypot_triggered("/wp-admin")
        registry.record_middleware_duration("rate_limit", 0.05)
        registry.record_jwt_token_rotated()

    def test_unavailable_counters_empty(self, mock_prometheus_unavailable: Any) -> None:
        """No counters created when prometheus unavailable."""
        from araxys.metrics.collector import MetricsRegistry

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        assert registry._counters == {}
        assert registry._histograms == {}


# ── Test metrics_endpoint ──────────────────────────────────────────────────  # noqa: E501


class TestMetricsEndpoint:
    """Tests for the metrics endpoint."""

    def test_endpoint_returns_prometheus_format(self, mock_prometheus: Any) -> None:
        """Enabled endpoint returns prometheus text format."""
        from fastapi import FastAPI

        from araxys.metrics.collector import MetricsRegistry
        from araxys.metrics.endpoint import metrics_endpoint

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        app = FastAPI()
        app.add_route("/metrics", metrics_endpoint(registry), methods=["GET"])

        client = TestClient(app)
        response = client.get("/metrics")

        assert response.status_code == 200
        assert (
            response.headers["content-type"]
            == "text/plain; version=0.0.4; charset=utf-8"
        )

    def test_endpoint_returns_404_when_disabled(self, mock_prometheus: Any) -> None:
        """Disabled endpoint returns 404."""
        from fastapi import FastAPI

        from araxys.metrics.collector import MetricsRegistry
        from araxys.metrics.endpoint import metrics_endpoint

        config = MetricsConfig(enabled=False)
        registry = MetricsRegistry(config)
        app = FastAPI()
        app.add_route("/metrics", metrics_endpoint(registry), methods=["GET"])

        client = TestClient(app)
        response = client.get("/metrics")

        assert response.status_code == 404

    def test_endpoint_unavailable_returns_404(self, mock_prometheus_unavailable: Any) -> None:  # noqa: E501
        """When prometheus unavailable, endpoint returns 404."""
        from fastapi import FastAPI

        from araxys.metrics.collector import MetricsRegistry
        from araxys.metrics.endpoint import metrics_endpoint

        config = MetricsConfig(enabled=True)
        registry = MetricsRegistry(config)
        app = FastAPI()
        app.add_route("/metrics", metrics_endpoint(registry), methods=["GET"])

        client = TestClient(app)
        response = client.get("/metrics")

        assert response.status_code == 404


class TestMountMetrics:
    """Tests for mount_metrics helper."""

    def test_mount_metrics_registers_route(self, mock_prometheus: Any) -> None:
        """mount_metrics registers the /metrics route on a FastAPI app."""
        from fastapi import FastAPI

        from araxys.metrics.collector import MetricsRegistry
        from araxys.metrics.endpoint import mount_metrics

        config = MetricsConfig(enabled=True, path="/custom-metrics")
        registry = MetricsRegistry(config)
        app = FastAPI()

        mount_metrics(app, config, registry)

        client = TestClient(app)
        response = client.get("/custom-metrics")
        assert response.status_code == 200

    def test_mount_metrics_does_not_register_when_disabled(self, mock_prometheus: Any) -> None:  # noqa: E501
        """mount_metrics does not register route when metrics disabled."""
        from fastapi import FastAPI

        from araxys.metrics.collector import MetricsRegistry
        from araxys.metrics.endpoint import mount_metrics

        config = MetricsConfig(enabled=False)
        registry = MetricsRegistry(config)
        app = FastAPI()

        mount_metrics(app, config, registry)

        client = TestClient(app)
        response = client.get("/metrics")
        assert response.status_code == 404
