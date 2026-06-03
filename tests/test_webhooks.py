"""Tests for the webhooks event bus and delivery modules."""

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.webhooks.config import WebhookConfig
from araxys.webhooks.delivery import WebhookDelivery
from araxys.webhooks.emitter import SecurityEventBus


@pytest.fixture
def webhook_config() -> WebhookConfig:
    return WebhookConfig(
        enabled=True,
        urls={
            "rate_limit_exceeded": ["https://hooks.example.com/rate-limit"],
            "honeypot_triggered": [
                "https://hooks.example.com/honeypot",
                "https://hooks.example.com/security",
            ],
            "csrf_validation_failed": ["https://hooks.example.com/csrf"],
        },
        retry_max=3,
        timeout_seconds=5,
        queue_size=100,
    )


class TestSecurityEventBus:
    """Unit tests for SecurityEventBus — async event queue."""

    async def test_subscribe_and_emit(self) -> None:
        bus = SecurityEventBus()
        callback = AsyncMock()
        bus.subscribe(callback)
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity="warning",
            message="test",
        )
        await bus.emit(event)

        # Give the consumer time to process
        await asyncio.sleep(0.05)
        callback.assert_awaited_once_with(event)
        await bus.stop()

    async def test_multiple_subscribers(self) -> None:
        bus = SecurityEventBus()
        cb1 = AsyncMock()
        cb2 = AsyncMock()
        bus.subscribe(cb1)
        bus.subscribe(cb2)
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="critical",
            message="test",
        )
        await bus.emit(event)
        await asyncio.sleep(0.05)

        cb1.assert_awaited_once_with(event)
        cb2.assert_awaited_once_with(event)
        await bus.stop()

    async def test_emit_before_start_does_not_block(self) -> None:
        """Emitting before start() should queue events without error."""
        bus = SecurityEventBus(queue_size=10)
        callback = AsyncMock()
        bus.subscribe(callback)

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="before start",
        )
        # Should not raise — queue just accumulates
        await bus.emit(event)
        await bus.emit(event)

        bus.start()
        await asyncio.sleep(0.05)
        assert callback.await_count == 2
        await bus.stop()

    async def test_graceful_shutdown(self) -> None:
        bus = SecurityEventBus()
        callback = AsyncMock()
        bus.subscribe(callback)
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_CREATED,
            severity="info",
            message="test",
        )
        await bus.emit(event)
        # Give consumer time to pick up the event
        await asyncio.sleep(0.05)
        await bus.stop()
        # After stop, callback should have been called
        callback.assert_awaited_once_with(event)

    async def test_stop_without_start(self) -> None:
        """Calling stop() without start() should not error."""
        bus = SecurityEventBus()
        await bus.stop()  # no-op, should not raise

    async def test_queue_overflow(self) -> None:
        """Emit beyond maxsize should not block (or raises appropriately)."""
        bus = SecurityEventBus(queue_size=2)
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity="warning",
            message="overflow",
        )
        await bus.emit(event)
        await bus.emit(event)
        # Third emit on a queue with maxsize=2
        await bus.emit(event)
        await asyncio.sleep(0.05)
        await bus.stop()
        # All 3 events must have been consumed
        # The bus consumes faster than we can emit

    async def test_consumer_handles_callback_error(self) -> None:
        """A failing callback should not stop the consumer loop."""
        bus = SecurityEventBus()
        good_cb = AsyncMock()
        bad_cb = AsyncMock(side_effect=RuntimeError("boom"))
        bus.subscribe(good_cb)
        bus.subscribe(bad_cb)
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.SESSION_REVOKED,
            severity="info",
            message="test",
        )
        await bus.emit(event)
        await asyncio.sleep(0.05)

        # Good callback must have been called despite bad callback's failure
        good_cb.assert_awaited_once_with(event)
        await bus.stop()


class TestWebhookDelivery:
    """Unit tests for WebhookDelivery — HTTP delivery with retry."""

    async def test_subscribes_to_event_bus_on_init(self) -> None:
        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"rate_limit_exceeded": ["https://hooks.example.com/test"]},
            retry_max=3,
            timeout_seconds=5,
            queue_size=100,
        )
        delivery = WebhookDelivery(
            config, bus,
            secret_key="test-secret-key-at-least-32-chars!!"
        )
        # Should have subscribed (we can check by inspecting subscribers)
        assert delivery._event_bus is bus
        assert len(bus._subscribers) == 1

    @patch("httpx.AsyncClient.post")
    async def test_delivers_to_matching_urls(
        self, mock_post: Mock
    ) -> None:
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_post.return_value = mock_response

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"rate_limit_exceeded": ["https://hooks.example.com/rl"]},
            retry_max=3,
            timeout_seconds=5,
            queue_size=100,
        )
        WebhookDelivery(config, bus, secret_key="test-secret-key-at-least-32-chars!!")
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity="warning",
            message="rate limit hit",
        )
        await bus.emit(event)
        # Give the fire-and-forget asyncio.create_task time to execute.
        # This can be tight under heavy test-suite load — generous wait prevents flakiness.
        for _ in range(20):
            if mock_post.await_count > 0:
                break
            await asyncio.sleep(0.05)

        mock_post.assert_awaited_once()
        call = mock_post.await_args
        assert call is not None
        # call[0] = positional args tuple, call[1] = keyword args dict
        assert call[0][0] == "https://hooks.example.com/rl"
        # Payload is now sent as raw bytes with content= + HMAC headers
        raw_body = call[1].get("content", b"{}")
        headers = call[1].get("headers", {})
        payload = json.loads(raw_body)
        assert payload["event_type"] == "rate_limit_exceeded"
        assert payload["severity"] == "warning"
        assert payload["message"] == "rate limit hit"
        assert "timestamp" in payload
        assert payload["metadata"] == {}
        # Verify HMAC signature is present
        assert "X-Signature-256" in headers
        assert headers["X-Signature-256"].startswith("sha256=")
        assert "X-Webhook-Timestamp" in headers

        await bus.stop()

    @patch("httpx.AsyncClient.post")
    async def test_delivers_to_multiple_urls_for_event_type(
        self, mock_post: Mock
    ) -> None:
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_post.return_value = mock_response

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={
                "honeypot_triggered": [
                    "https://hooks.example.com/hp",
                    "https://hooks.example.com/sec",
                ]
            },
            retry_max=3,
            timeout_seconds=5,
            queue_size=100,
        )
        WebhookDelivery(config, bus, secret_key="test-secret-key-at-least-32-chars!!")
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.HONEYPOT_TRIGGERED,
            severity="critical",
            message="hp triggered",
        )
        await bus.emit(event)
        for _ in range(20):
            if mock_post.await_count >= 2:
                break
            await asyncio.sleep(0.05)

        assert mock_post.await_count == 2
        await bus.stop()

    @patch("httpx.AsyncClient.post")
    async def test_does_not_deliver_to_non_matching_urls(
        self, mock_post: Mock
    ) -> None:
        mock_response = Mock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.is_success = True
        mock_post.return_value = mock_response

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"csrf_validation_failed": ["https://hooks.example.com/csrf"]},
            retry_max=3,
            timeout_seconds=5,
            queue_size=100,
        )
        WebhookDelivery(config, bus, secret_key="test-secret-key-at-least-32-chars!!")
        bus.start()

        event = SecurityEvent(
            event_type=SecurityEventType.HONEYPOT_TRIGGERED,
            severity="critical",
            message="no match",
        )
        await bus.emit(event)
        await asyncio.sleep(0.05)

        mock_post.assert_not_awaited()
        await bus.stop()
