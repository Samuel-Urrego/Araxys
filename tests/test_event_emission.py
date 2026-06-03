"""Integration tests for event emission from middleware (Phase 5, task 5.5).

Verifies that rate_limit, sanitize, and honeypot emit correct
SecurityEventType events when blocking requests.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from araxys.core.types import SecurityEvent, SecurityEventType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_request(
    path: str = "/test",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> MagicMock:
    """Build a Starlette-compatible mock Request."""
    from starlette.datastructures import URL

    header_dict = headers or {}

    req = MagicMock()
    req.url = URL(f"http://testserver{path}")
    req.method = method

    # Headers — support both .get() and .items()
    req.headers = MagicMock()
    req.headers.get = MagicMock(
        side_effect=lambda k, default=None: header_dict.get(k, default)
    )
    req.headers.items = MagicMock(return_value=iter(header_dict.items()))

    # Request.client for IP extraction
    req.client = MagicMock()
    req.client.host = "1.2.3.4"

    req.state = MagicMock()
    req.body = AsyncMock(return_value=body or b"")
    return req


# ---------------------------------------------------------------------------
# Rate Limit event emission
# ---------------------------------------------------------------------------


class TestRateLimitEventEmission:
    """RateLimitMiddleware must emit RATE_LIMIT_EXCEEDED before returning 429."""

    def test_rate_limit_emits_event_on_exceeded(self) -> None:
        """When rate limit is exceeded, dispatch() emits RATE_LIMIT_EXCEEDED."""
        from araxys.core.config import RateLimitConfig
        from araxys.rate_limit.backends import InMemoryBackend
        from araxys.rate_limit.middleware import RateLimitMiddleware

        # Set up a mock event bus
        mock_bus = MagicMock()
        mock_bus.emit = AsyncMock()

        import araxys.rate_limit.middleware as rate_mw
        rate_mw._event_bus = mock_bus

        config = RateLimitConfig(max_requests=1, window_seconds=60, exclude_paths=[])
        backend = InMemoryBackend()
        mw = RateLimitMiddleware(AsyncMock(), backend=backend, config=config)

        async def _run() -> None:
            # First request — passes (count goes to 1)
            req1 = _make_mock_request(path="/api/test", method="GET")
            call_next1 = AsyncMock(return_value=MagicMock(status_code=200))
            result1 = await mw.dispatch(req1, call_next1)
            assert result1.status_code == 200

            # Second request — exceeds limit (count was 1)
            req2 = _make_mock_request(path="/api/test", method="GET")
            call_next2 = AsyncMock()
            result2 = await mw.dispatch(req2, call_next2)
            assert result2.status_code == 429

        asyncio.run(_run())

        # Verify emit was called
        mock_bus.emit.assert_called()
        event = mock_bus.emit.call_args[0][0]
        assert isinstance(event, SecurityEvent)
        assert event.event_type == SecurityEventType.RATE_LIMIT_EXCEEDED
        assert event.source_ip == "1.2.3.4"

    def test_rate_limit_does_not_emit_on_normal_request(self) -> None:
        """When rate limit is NOT exceeded, no RATE_LIMIT_EXCEEDED is emitted."""
        from araxys.core.config import RateLimitConfig
        from araxys.rate_limit.backends import InMemoryBackend
        from araxys.rate_limit.middleware import RateLimitMiddleware

        mock_bus = MagicMock()
        mock_bus.emit = AsyncMock()

        import araxys.rate_limit.middleware as rate_mw
        rate_mw._event_bus = mock_bus

        config = RateLimitConfig(max_requests=1000, window_seconds=60)
        backend = InMemoryBackend()
        mw = RateLimitMiddleware(
            AsyncMock(),
            backend=backend,
            config=config,
        )
        request = _make_mock_request(path="/api/health", method="GET")

        async def _run() -> None:
            call_next = AsyncMock(return_value=MagicMock(status_code=200))
            result = await mw.dispatch(request, call_next)
            assert result.status_code == 200

        asyncio.run(_run())

        mock_bus.emit.assert_not_called()

    def test_rate_limit_no_emit_when_event_bus_none(self) -> None:
        """When _event_bus is None, no error is raised and no emit happens."""
        import araxys.rate_limit.middleware as rate_mw
        from araxys.core.config import RateLimitConfig
        from araxys.rate_limit.backends import InMemoryBackend
        from araxys.rate_limit.middleware import RateLimitMiddleware
        rate_mw._event_bus = None

        config = RateLimitConfig(max_requests=1000, window_seconds=60)
        backend = InMemoryBackend()
        mw = RateLimitMiddleware(AsyncMock(), backend=backend, config=config)
        request = _make_mock_request(path="/api/test", method="GET")

        async def _run() -> None:
            call_next = AsyncMock(return_value=MagicMock(status_code=200))
            result = await mw.dispatch(request, call_next)
            assert result.status_code == 200

        asyncio.run(_run())  # Should not raise


# ---------------------------------------------------------------------------
# Sanitize event emission
# ---------------------------------------------------------------------------


class TestSanitizeEventEmission:
    """SanitizeMiddleware must emit SANITIZE_BLOCKED before returning 400."""

    def test_sanitize_emits_event_on_scan_header_threat(self) -> None:
        """When a header scan detects a threat, SANITIZE_BLOCKED is emitted."""
        from araxys.core.config import SanitizeConfig
        from araxys.sanitize.middleware import SanitizeMiddleware

        mock_bus = MagicMock()
        mock_bus.emit = AsyncMock()

        import araxys.sanitize.middleware as sanitize_mw
        sanitize_mw._event_bus = mock_bus

        config = SanitizeConfig(
            enabled=True,
            scan_headers=True,
            scan_query_params=False,
            block_sqli=True,
            strip_xss=False,
            check_nosql_injection=True,
            check_command_injection=False,
            check_path_traversal=False,
            exclude_paths=[],
        )
        mw = SanitizeMiddleware(AsyncMock(), config=config)

        request = _make_mock_request(
            path="/api/data",
            method="GET",
            headers={"x-custom": '{"$gt": ""}'},
        )

        async def _run() -> None:
            call_next = AsyncMock()
            result = await mw.dispatch(request, call_next)
            assert result.status_code == 400

        asyncio.run(_run())

        mock_bus.emit.assert_called()
        event = mock_bus.emit.call_args[0][0]
        assert isinstance(event, SecurityEvent)
        assert event.event_type == SecurityEventType.SANITIZE_BLOCKED
        assert event.source_ip == "1.2.3.4"

    def test_sanitize_no_emit_when_event_bus_none(self) -> None:
        """When _event_bus is None, sanitize blocks without raising errors."""
        import araxys.sanitize.middleware as sanitize_mw
        from araxys.core.config import SanitizeConfig
        from araxys.sanitize.middleware import SanitizeMiddleware
        sanitize_mw._event_bus = None

        config = SanitizeConfig(
            enabled=True,
            scan_headers=True,
            scan_query_params=False,
            block_sqli=True,
            strip_xss=False,
            check_nosql_injection=True,
            check_command_injection=False,
            check_path_traversal=False,
            exclude_paths=[],
        )
        mw = SanitizeMiddleware(AsyncMock(), config=config)

        request = _make_mock_request(
            path="/api/data",
            method="GET",
            headers={"x-custom": '{"$gt": ""}'},
        )

        async def _run() -> None:
            call_next = AsyncMock()
            result = await mw.dispatch(request, call_next)
            assert result.status_code == 400

        asyncio.run(_run())  # Should not raise


# ---------------------------------------------------------------------------
# Honeypot event emission
# ---------------------------------------------------------------------------


class TestHoneypotEventEmission:
    """Honeypot must emit HONEYPOT_TRIGGERED when a trap is triggered."""

    def test_honeypot_emits_event_on_trap(self) -> None:
        """When a honeypot trap is hit, HONEYPOT_TRIGGERED is emitted."""
        from araxys.core.config import HoneypotConfig
        from araxys.honeypot.trap import HoneypotTrap
        from araxys.rate_limit.backends import InMemoryBackend

        mock_bus = MagicMock()
        mock_bus.emit = AsyncMock()

        import araxys.honeypot.trap as honeypot_trap
        honeypot_trap._event_bus = mock_bus

        config = HoneypotConfig(
            enabled=True,
            paths=["/wp-admin"],
            ban_duration_seconds=300,
            fake_response_code=200,
        )
        backend = InMemoryBackend()
        trap = HoneypotTrap(backend=backend, config=config)

        request = _make_mock_request(path="/wp-admin", method="GET")

        async def _run() -> None:
            result = await trap._handle_trap(request, "/wp-admin")
            assert result.status_code == 200

        asyncio.run(_run())

        mock_bus.emit.assert_called()
        event = mock_bus.emit.call_args[0][0]
        assert isinstance(event, SecurityEvent)
        assert event.event_type == SecurityEventType.HONEYPOT_TRIGGERED
        assert event.source_ip == "1.2.3.4"

    def test_honeypot_no_emit_when_event_bus_none(self) -> None:
        """When _event_bus is None, honeypot still bans without error."""
        import araxys.honeypot.trap as honeypot_trap
        from araxys.core.config import HoneypotConfig
        from araxys.honeypot.trap import HoneypotTrap
        from araxys.rate_limit.backends import InMemoryBackend
        honeypot_trap._event_bus = None

        config = HoneypotConfig(
            enabled=True,
            paths=["/wp-admin"],
            ban_duration_seconds=300,
            fake_response_code=200,
        )
        backend = InMemoryBackend()
        trap = HoneypotTrap(backend=backend, config=config)

        request = _make_mock_request(path="/wp-admin", method="GET")

        async def _run() -> None:
            result = await trap._handle_trap(request, "/wp-admin")
            assert result.status_code == 200

        asyncio.run(_run())  # Should not raise
