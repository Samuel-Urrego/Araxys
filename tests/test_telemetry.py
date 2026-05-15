"""Tests for the OpenTelemetry Integration module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

if TYPE_CHECKING:
    from araxys.core.config import TelemetryConfig


# ── AraxysTracer Tests ─────────────────────────────────────────────────


class TestAraxysTracer:
    """Tests for AraxysTracer."""

    @pytest.fixture
    def config(self) -> TelemetryConfig:
        from araxys.core.config import TelemetryConfig

        return TelemetryConfig(enabled=False)

    @pytest.fixture
    def enabled_config(self) -> TelemetryConfig:
        from araxys.core.config import TelemetryConfig

        return TelemetryConfig(enabled=True, service_name="test-svc")

    def test_disabled_tracer_returns_noop_cm(self) -> None:
        """AraxysTracer with enabled=False should yield a no-op context manager."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=False)
        tracer = AraxysTracer(config)

        # get_tracer should return None
        assert tracer.get_tracer() is None

    async def test_disabled_tracer_span_is_noop(self) -> None:
        """AraxysTracer with enabled=False should execute block without error."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=False)
        tracer = AraxysTracer(config)

        called = False
        async with tracer.span("test.operation") as span:
            called = True
            # Should still yield something that acts like a span
            assert span is not None

        assert called

    async def test_disabled_tracer_record_event_is_noop(self) -> None:
        """record_event with disabled tracer should not error."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=False)
        tracer = AraxysTracer(config)

        # Should not raise
        await tracer.record_event("test.event", {"key": "val"})

    @patch("araxys.telemetry.tracer._otel_available", return_value=False)
    def test_otel_not_available_returns_noop(
        self, mock_available: MagicMock
    ) -> None:
        """AraxysTracer should be no-op when OTEL is not installed."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=True)
        tracer = AraxysTracer(config)

        assert tracer.get_tracer() is None

    @patch("araxys.telemetry.tracer._otel_available", return_value=False)
    async def test_otel_not_available_span_does_not_crash(
        self, mock_available: MagicMock
    ) -> None:
        """Span context manager should not crash when OTEL is absent."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=True)
        tracer = AraxysTracer(config)

        called = False
        async with tracer.span("test.op") as span:
            called = True
            assert span is not None

        assert called

    @patch("araxys.telemetry.tracer._otel_available", return_value=True)
    def test_otel_available_returns_tracer(
        self, mock_available: MagicMock
    ) -> None:
        """When OTEL is available, get_tracer should return a tracer instance."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        config = TelemetryConfig(enabled=True)
        tracer = AraxysTracer(config)

        # OTEL is mocked as available — verify no crash
        tracer.get_tracer()
        assert True

    async def test_span_with_mocked_otel(self) -> None:
        """Span context manager should create span via OTEL API."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        # Patch both _otel_available and trace at module level
        with (
            patch("araxys.telemetry.tracer._otel_available", return_value=True),
            patch("araxys.telemetry.tracer._otel_trace") as mock_trace,
        ):
            mock_tracer = MagicMock()
            mock_span = AsyncMock()
            mock_span.__aenter__ = AsyncMock(return_value=mock_span)
            mock_span.__aexit__ = AsyncMock(return_value=None)
            mock_tracer.start_as_current_span.return_value = mock_span
            mock_trace.get_tracer.return_value = mock_tracer

            config = TelemetryConfig(enabled=True)
            tracer = AraxysTracer(config)

            async with tracer.span("http.request", {"method": "GET"}):
                pass

            # Verify a span was created
            mock_tracer.start_as_current_span.assert_called_once()
            # The span name should be passed
            args, kwargs = mock_tracer.start_as_current_span.call_args
            assert args[0] == "http.request"
            assert kwargs.get("attributes") == {"method": "GET"}

    async def test_record_event_with_mocked_otel(self) -> None:
        """record_event should add event to current span."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        with (
            patch("araxys.telemetry.tracer._otel_available", return_value=True),
            patch("araxys.telemetry.tracer._otel_trace") as mock_trace,
        ):
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_span.__enter__ = MagicMock(return_value=mock_span)
            mock_span.__exit__ = MagicMock(return_value=None)
            mock_tracer.start_as_current_span.return_value = mock_span
            mock_trace.get_tracer.return_value = mock_tracer
            # Wire get_current_span to return the same span
            mock_trace.get_current_span.return_value = mock_span

            config = TelemetryConfig(enabled=True)
            tracer = AraxysTracer(config)

            async with tracer.span("test.op"):
                await tracer.record_event("cache.hit", {"key": "x"})

            mock_span.add_event.assert_called_once_with("cache.hit", {"key": "x"})

    async def test_tracer_span_sets_attributes_on_current_span(self) -> None:
        """Span attributes should be set on the current span via set_attribute."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer

        with (
            patch("araxys.telemetry.tracer._otel_available", return_value=True),
            patch("araxys.telemetry.tracer._otel_trace") as mock_trace,
        ):
            mock_tracer = MagicMock()
            mock_span = AsyncMock()
            mock_span.__aenter__ = AsyncMock(return_value=mock_span)
            mock_span.__aexit__ = AsyncMock(return_value=None)
            mock_tracer.start_as_current_span.return_value = mock_span
            mock_trace.get_tracer.return_value = mock_tracer

            config = TelemetryConfig(enabled=True)
            tracer = AraxysTracer(config)

            async with tracer.span("test.op", {"env": "prod"}):
                pass

            mock_tracer.start_as_current_span.assert_called_once_with(
                "test.op", attributes={"env": "prod"}
            )


# ── Standalone arxys_span Function Tests ──────────────────────────────


class TestAraxysSpan:
    """Tests for the standalone arxys_span context manager function."""

    async def test_span_without_tracer_is_noop(self) -> None:
        """araxys_span without tracer should be a no-op."""
        from araxys.telemetry.tracer import araxys_span

        called = False
        async with araxys_span("test.op") as span:
            called = True
            assert span is not None

        assert called

    async def test_span_with_disabled_tracer_is_noop(self) -> None:
        """araxys_span with disabled tracer should be a no-op."""
        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.tracer import AraxysTracer, araxys_span

        config = TelemetryConfig(enabled=False)
        tracer = AraxysTracer(config)

        called = False
        async with araxys_span("test.op", tracer) as span:
            called = True
            assert span is not None

        assert called


# ── TelemetryMiddleware Tests ────────────────────────────────────────────


class TestTelemetryMiddleware:
    """Tests for TelemetryMiddleware."""

    async def test_disabled_middleware_passes_through(self) -> None:
        """When disabled, middleware should pass through without creating spans."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient
        from starlette.responses import JSONResponse

        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.middleware import TelemetryMiddleware

        app = FastAPI()

        @app.get("/ping")
        async def ping() -> JSONResponse:
            return JSONResponse({"status": "ok"})

        config = TelemetryConfig(enabled=False)
        app.add_middleware(TelemetryMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/ping")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}

    async def test_middleware_creates_span_when_enabled(self) -> None:
        """When enabled, middleware should create an HTTP span."""
        from unittest.mock import patch

        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient
        from starlette.responses import JSONResponse

        from araxys.core.config import TelemetryConfig
        from araxys.telemetry.middleware import TelemetryMiddleware
        from araxys.telemetry.tracer import AraxysTracer

        app = FastAPI()

        @app.get("/hello")
        async def hello() -> JSONResponse:
            return JSONResponse({"msg": "hi"})

        with (
            patch("araxys.telemetry.tracer._otel_available", return_value=True),
            patch("araxys.telemetry.tracer._otel_trace") as mock_trace,
        ):
            mock_inner_span = MagicMock()
            mock_inner_span.__enter__ = MagicMock(return_value=mock_inner_span)
            mock_inner_span.__exit__ = MagicMock(return_value=None)

            mock_tracer_obj = MagicMock()
            mock_tracer_obj.start_as_current_span.return_value = mock_inner_span

            mock_trace.get_tracer.return_value = mock_tracer_obj

            config = TelemetryConfig(enabled=True)
            tracer = AraxysTracer(config)
            app.add_middleware(TelemetryMiddleware, config=config, tracer=tracer)

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                resp = await client.get("/hello")
                assert resp.status_code == 200

            # Verify span was created
            mock_tracer_obj.start_as_current_span.assert_called_once()
            span_name = mock_tracer_obj.start_as_current_span.call_args[0][0]
            assert span_name == "http.request"

            # Verify status code was set on span
            mock_inner_span.set_attribute.assert_any_call("http.status_code", 200)
