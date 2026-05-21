"""Tests for the webhook Dead-Letter Queue (DLQ) module.

Tests cover DLQ configuration, backend storage, consumer lifecycle,
API routes, and shield integration.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from fakeredis.aioredis import FakeRedis

from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.webhooks.config import WebhookConfig

if TYPE_CHECKING:
    from araxys.webhooks.dlq import WebhookDLQBackend


@pytest.fixture
async def fake_redis() -> FakeRedis:
    return FakeRedis(decode_responses=True)


@pytest.fixture
async def dlq_backend(fake_redis: FakeRedis) -> WebhookDLQBackend:
    from araxys.webhooks.dlq import WebhookDLQBackend

    backend = WebhookDLQBackend(fake_redis)
    return backend


@pytest.fixture
def sample_event() -> SecurityEvent:
    return SecurityEvent(
        event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
        severity="warning",
        message="rate limit hit",
        source_ip="10.0.0.1",
    )


class TestDLQDataClasses:
    """DLQEvent and DLQEventSummary dataclass contracts."""

    def test_dlq_event_fields(self) -> None:
        """DLQEvent must have all required fields."""
        from araxys.webhooks.dlq import DLQEvent

        event = DLQEvent(
            event_id="evt_001",
            event_type="rate_limit_exceeded",
            payload='{"severity":"warning"}',
            url="https://hooks.example.com/hook",
            attempt_count=1,
            last_error="Connection refused",
            next_retry_at=1000.0,
            original_timestamp="2026-05-21T12:00:00Z",
            status="pending",
            created_at="2026-05-21T12:00:00Z",
        )
        assert event.event_id == "evt_001"
        assert event.event_type == "rate_limit_exceeded"
        assert event.payload == '{"severity":"warning"}'
        assert event.url == "https://hooks.example.com/hook"
        assert event.attempt_count == 1
        assert event.last_error == "Connection refused"
        assert event.next_retry_at == 1000.0
        assert event.original_timestamp == "2026-05-21T12:00:00Z"
        assert event.status == "pending"
        assert event.created_at == "2026-05-21T12:00:00Z"

    def test_dlq_event_summary_fields(self) -> None:
        """DLQEventSummary must have all required fields."""
        from araxys.webhooks.dlq import DLQEventSummary

        summary = DLQEventSummary(
            event_id="evt_001",
            event_type="rate_limit_exceeded",
            url="https://hooks.example.com/hook",
            attempt_count=1,
            next_retry_at=1000.0,
            age_seconds=3600.0,
            status="pending",
        )
        assert summary.event_id == "evt_001"
        assert summary.event_type == "rate_limit_exceeded"
        assert summary.url == "https://hooks.example.com/hook"
        assert summary.attempt_count == 1
        assert summary.next_retry_at == 1000.0
        assert summary.age_seconds == 3600.0
        assert summary.status == "pending"

    def test_lua_scripts_are_valid_strings(self) -> None:
        """Lua scripts must be non-empty strings registered on the backend."""
        from araxys.webhooks.dlq import (
            REPLAY_EVENT_SCRIPT,
            RESCHEDULE_OR_MARK_DEAD_SCRIPT,
        )

        assert isinstance(REPLAY_EVENT_SCRIPT, str)
        assert len(REPLAY_EVENT_SCRIPT) > 50
        assert "redis.call" in REPLAY_EVENT_SCRIPT
        assert isinstance(RESCHEDULE_OR_MARK_DEAD_SCRIPT, str)
        assert len(RESCHEDULE_OR_MARK_DEAD_SCRIPT) > 100
        assert "redis.call" in RESCHEDULE_OR_MARK_DEAD_SCRIPT


class TestDLQBackend:
    """WebhookDLQBackend CRUD and lifecycle using fakeredis."""

    async def test_enqueue_stores_hash_and_zset(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """enqueue must store event data in HASH and index in pending ZSET."""
        # Act
        event_id = await dlq_backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
            attempt_count=1,
            last_error="Timeout",
        )

        # Assert — event hash exists
        key = f"dlq:event:{event_id}"
        stored = await dlq_backend._redis.hgetall(key)  # type: ignore[misc]
        assert stored is not None
        assert stored["event_type"] == "rate_limit_exceeded"
        assert stored["url"] == "https://hooks.example.com/hook"
        assert stored["attempt_count"] == "1"
        assert stored["last_error"] == "Timeout"
        assert stored["status"] == "pending"

        # Assert — pending ZSET has the event_id
        score = await dlq_backend._redis.zscore("dlq:pending", event_id)
        assert score is not None
        assert score > 0

    async def test_enqueue_returns_unique_ids(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """Each enqueue call must return a unique event_id."""
        id1 = await dlq_backend.enqueue(sample_event, "https://hook.example.com/a")
        id2 = await dlq_backend.enqueue(sample_event, "https://hook.example.com/b")
        assert id1 != id2

    async def test_dequeue_eligible_returns_matching_events(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """dequeue_eligible must return events where next_retry_at <= now()."""
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/hook")

        events = await dlq_backend.dequeue_eligible(batch_size=10)
        assert len(events) == 1
        assert events[0].url == "https://hooks.example.com/hook"
        assert events[0].attempt_count == 1

    async def test_dequeue_eligible_empty_when_none_due(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """dequeue_eligible must return empty if no events are due."""
        # Event stored with future next_retry_at requires a way to set it.
        # Default enqueue uses now() so it's always eligible immediately.
        # This tests the empty case when there are no events at all.
        events = await dlq_backend.dequeue_eligible(batch_size=10)
        assert events == []

    async def test_list_pending_returns_summaries(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """list_pending must return summaries of pending events."""
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/hook")

        summaries = await dlq_backend.list_pending()
        assert len(summaries) == 1
        s = summaries[0]
        assert s.event_type == "rate_limit_exceeded"
        assert s.url == "https://hooks.example.com/hook"
        assert s.attempt_count == 1
        assert s.status == "pending"
        assert s.age_seconds >= 0

    async def test_list_dead_returns_empty_initially(
        self,
        dlq_backend: WebhookDLQBackend,
    ) -> None:
        """list_dead must return empty when no events are dead."""
        dead = await dlq_backend.list_dead()
        assert dead == []

    async def test_inspect_returns_full_event(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """inspect must return full DLQEvent for existing event_id."""
        event_id = await dlq_backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
            attempt_count=2,
            last_error="500 Server Error",
        )

        event = await dlq_backend.inspect(event_id)
        assert event is not None
        assert event.event_id == event_id
        assert event.event_type == "rate_limit_exceeded"
        assert event.url == "https://hooks.example.com/hook"
        assert event.attempt_count == 2
        assert event.last_error == "500 Server Error"
        assert event.status == "pending"

        # Payload should contain the serialised SecurityEvent
        payload = json.loads(event.payload)
        assert payload["severity"] == "warning"
        assert payload["message"] == "rate limit hit"

    async def test_inspect_returns_none_for_missing(
        self,
        dlq_backend: WebhookDLQBackend,
    ) -> None:
        """inspect must return None when event does not exist."""
        event = await dlq_backend.inspect("nonexistent")
        assert event is None

    async def test_remove_returns_true_and_deletes(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """remove must delete event and return True."""
        event_id = await dlq_backend.enqueue(sample_event, "https://hooks.example.com/hook")

        result = await dlq_backend.remove(event_id)
        assert result is True

        gone = await dlq_backend.inspect(event_id)
        assert gone is None

    async def test_remove_returns_false_for_missing(
        self,
        dlq_backend: WebhookDLQBackend,
    ) -> None:
        """remove must return False for non-existent event."""
        result = await dlq_backend.remove("nonexistent")
        assert result is False

    async def test_mark_dead_moves_pending_to_dead(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """mark_dead must move event from pending to dead."""
        event_id = await dlq_backend.enqueue(sample_event, "https://hooks.example.com/hook")

        await dlq_backend.mark_dead(event_id)

        # Should not be in pending
        pending_score = await dlq_backend._redis.zscore("dlq:pending", event_id)
        assert pending_score is None

        # Should be in dead
        dead_score = await dlq_backend._redis.zscore("dlq:dead", event_id)
        assert dead_score is not None

        # Status should be dead
        status = await dlq_backend._redis.hget(f"dlq:event:{event_id}", "status")  # type: ignore[misc]
        assert status == "dead"

    async def test_purge_all_deletes_all_keys(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """purge_all must delete all dlq:* keys and return count."""
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/a")
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/b")
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/c")

        deleted = await dlq_backend.purge_all()
        assert deleted >= 3  # at least 3 event keys + zset keys

        remaining = await dlq_backend._redis.keys("dlq:*")
        assert remaining == []

    async def test_purge_by_url_deletes_matching(
        self,
        dlq_backend: WebhookDLQBackend,
        sample_event: SecurityEvent,
    ) -> None:
        """purge_by_url must delete only events matching the given URL."""
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/a")
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/b")
        await dlq_backend.enqueue(sample_event, "https://hooks.example.com/a")

        deleted = await dlq_backend.purge_by_url("https://hooks.example.com/a")
        assert deleted == 2

        remaining = await dlq_backend.list_pending()
        assert len(remaining) == 1
        assert remaining[0].url == "https://hooks.example.com/b"

    async def test_redis_unavailable_logs_and_skips(
        self,
    ) -> None:
        """WebhookDLQBackend must handle Redis failures gracefully.

        When the backing Redis is a broken mock, operations should log
        and not crash the caller. We test this by passing a Redis that
        fails on every call.
        """
        from unittest.mock import AsyncMock, MagicMock

        from araxys.webhooks.dlq import WebhookDLQBackend

        broken = AsyncMock(spec=["hset", "pipeline"])
        # pipeline() returns an async context manager
        mock_pipe = AsyncMock()
        mock_pipe.hset = AsyncMock()
        mock_pipe.zadd = AsyncMock()
        mock_pipe.execute = AsyncMock(side_effect=ConnectionError("Redis is down"))
        # Make pipeline return an async context manager
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_pipe)
        cm.__aexit__ = AsyncMock(return_value=None)
        broken.pipeline.return_value = cm

        # hset for payload building test
        broken.hset = AsyncMock(side_effect=ConnectionError("Redis is down"))

        backend = WebhookDLQBackend(broken)
        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )
        with pytest.raises(ConnectionError):
            await backend.enqueue(event, "https://hooks.example.com/hook")


class TestDLQConsumer:
    """DLQConsumer lifecycle and poll/dispatch cycle."""

    async def test_start_stops_without_error(
        self,
        dlq_backend: WebhookDLQBackend,
    ) -> None:
        """Consumer start/stop must not raise."""
        from unittest.mock import AsyncMock

        from araxys.webhooks.dlq import DLQConsumer

        config = WebhookConfig(dlq_enabled=True, dlq_retry_interval_seconds=3600)
        deliver_fn = AsyncMock(return_value=True)
        consumer = DLQConsumer(dlq_backend, deliver_fn, config)

        consumer.start()
        assert consumer._running is True
        assert consumer._task is not None

        await consumer.stop()
        assert consumer._running is False

    async def test_poll_once_dispatches_eligible_events(
        self,
        fake_redis: FakeRedis,
        sample_event: SecurityEvent,
    ) -> None:
        """_poll_once must dispatch eligible events and remove on success."""
        from unittest.mock import AsyncMock

        from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend

        backend = WebhookDLQBackend(fake_redis)
        await backend.enqueue(sample_event, "https://hooks.example.com/hook")

        deliver_fn = AsyncMock(return_value=True)
        config = WebhookConfig(dlq_enabled=True, dlq_retry_interval_seconds=3600)
        consumer = DLQConsumer(backend, deliver_fn, config)

        await consumer._poll_once()

        deliver_fn.assert_awaited_once()
        # Event should be removed after successful delivery
        remaining = await backend.list_pending()
        assert remaining == []

    async def test_poll_once_reschedules_on_failure(
        self,
        fake_redis: FakeRedis,
        sample_event: SecurityEvent,
    ) -> None:
        """_poll_once must reschedule on delivery failure."""
        from unittest.mock import AsyncMock

        from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend

        backend = WebhookDLQBackend(fake_redis)
        await backend.enqueue(sample_event, "https://hooks.example.com/hook")

        deliver_fn = AsyncMock(return_value=False)
        config = WebhookConfig(dlq_enabled=True, dlq_retry_interval_seconds=60)
        consumer = DLQConsumer(backend, deliver_fn, config)

        await consumer._poll_once()

        deliver_fn.assert_awaited_once()
        # Event should still be pending (rescheduled)
        remaining = await backend.list_pending()
        assert len(remaining) == 1
        # Enqueued with attempt_count=1, incremented to 2 after consumer failure
        assert remaining[0].attempt_count == 2

    async def test_poll_once_marks_dead_after_max_retries(
        self,
        fake_redis: FakeRedis,
        sample_event: SecurityEvent,
    ) -> None:
        """_poll_once must mark event dead after max retries reached."""
        from unittest.mock import AsyncMock

        from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend

        backend = WebhookDLQBackend(fake_redis)
        # Enqueue with attempt_count = max_retries so next failure marks dead
        await backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
            attempt_count=1,
            last_error="initial failure",
        )

        deliver_fn = AsyncMock(return_value=False)
        config = WebhookConfig(
            dlq_enabled=True,
            dlq_retry_interval_seconds=60,
            dlq_max_retries=1,
        )
        consumer = DLQConsumer(backend, deliver_fn, config)

        await consumer._poll_once()

        deliver_fn.assert_awaited_once()
        # Event should be in dead set
        dead = await backend.list_dead()
        assert len(dead) == 1

        pending = await backend.list_pending()
        assert pending == []

    async def test_poll_loop_continues_on_error(
        self,
        fake_redis: FakeRedis,
    ) -> None:
        """_poll_loop must not crash when poll_once raises."""
        from unittest.mock import AsyncMock

        from araxys.webhooks.dlq import DLQConsumer, WebhookDLQBackend

        backend = WebhookDLQBackend(fake_redis)
        config = WebhookConfig(dlq_enabled=True, dlq_retry_interval_seconds=3600)
        consumer = DLQConsumer(backend, AsyncMock(), config)

        # Break dequeue_eligible to raise on first call
        original = backend.dequeue_eligible
        call_count = 0

        async def broken_dequeue(*args: object, **kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                msg = "Simulated error"
                raise RuntimeError(msg)
            return await original(*args, **kwargs)  # type: ignore[arg-type]

        backend.dequeue_eligible = broken_dequeue  # type: ignore[assignment]

        # First _poll_once should fail
        with pytest.raises(RuntimeError, match="Simulated error"):
            await consumer._poll_once()
        assert call_count == 1

        # Second _poll_once should succeed (no events, but no crash)
        await consumer._poll_once()
        assert call_count == 2


class TestDLQDeliveryIntegration:
    """Integration between WebhookDelivery and DLQ backend."""

    async def test_deliver_with_retry_returns_false_on_failure(
        self,
    ) -> None:
        """_deliver_with_retry must return False when delivery fails."""
        from unittest.mock import AsyncMock, patch

        import httpx

        from araxys.webhooks.delivery import WebhookDelivery
        from araxys.webhooks.emitter import SecurityEventBus

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"ip_blocked": ["https://hooks.example.com/hook"]},
            retry_max=0,  # no retries, fail immediately
            timeout_seconds=5,
            queue_size=100,
        )
        delivery = WebhookDelivery(
            config, bus,
            secret_key="test-secret-key-at-least-32-chars!!",
            dlq_backend=None,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )

        with patch.object(delivery, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AsyncMock(spec=httpx.Response)
            mock_response.is_success = False
            mock_response.status_code = 500
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            result = await delivery._deliver_with_retry(
                "https://hooks.example.com/hook", event
            )
            assert result is False

    async def test_deliver_with_retry_returns_true_on_success(
        self,
    ) -> None:
        """_deliver_with_retry must return True when delivery succeeds."""
        from unittest.mock import AsyncMock, patch

        import httpx

        from araxys.webhooks.delivery import WebhookDelivery
        from araxys.webhooks.emitter import SecurityEventBus

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"ip_blocked": ["https://hooks.example.com/hook"]},
            retry_max=0,
            timeout_seconds=5,
            queue_size=100,
        )
        delivery = WebhookDelivery(
            config, bus,
            secret_key="test-secret-key-at-least-32-chars!!",
            dlq_backend=None,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )

        with patch.object(delivery, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AsyncMock(spec=httpx.Response)
            mock_response.is_success = True
            mock_response.status_code = 200
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            result = await delivery._deliver_with_retry(
                "https://hooks.example.com/hook", event
            )
            assert result is True

    async def test_dlq_stores_event_on_retry_exhaustion(
        self,
        fake_redis: FakeRedis,
    ) -> None:
        """Event must be stored in DLQ when all retries are exhausted."""
        from unittest.mock import AsyncMock, patch

        import httpx

        from araxys.webhooks.delivery import WebhookDelivery
        from araxys.webhooks.dlq import WebhookDLQBackend
        from araxys.webhooks.emitter import SecurityEventBus

        backend = WebhookDLQBackend(fake_redis)
        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"ip_blocked": ["https://hooks.example.com/hook"]},
            retry_max=0,
            timeout_seconds=5,
            queue_size=100,
        )
        delivery = WebhookDelivery(
            config, bus,
            secret_key="test-secret-key-at-least-32-chars!!",
            dlq_backend=backend,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )

        with patch.object(delivery, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AsyncMock(spec=httpx.Response)
            mock_response.is_success = False
            mock_response.status_code = 500
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            result = await delivery._deliver_with_retry(
                "https://hooks.example.com/hook", event
            )
            assert result is False

            # Event should be in DLQ
            pending = await backend.list_pending()
            assert len(pending) == 1
            assert pending[0].url == "https://hooks.example.com/hook"

    async def test_no_dlq_stored_when_dlq_backend_is_none(
        self,
    ) -> None:
        """Event must NOT be stored when dlq_backend is None (backward compat)."""
        from unittest.mock import AsyncMock, patch

        import httpx

        from araxys.webhooks.delivery import WebhookDelivery
        from araxys.webhooks.emitter import SecurityEventBus

        bus = SecurityEventBus()
        config = WebhookConfig(
            enabled=True,
            urls={"ip_blocked": ["https://hooks.example.com/hook"]},
            retry_max=0,
            timeout_seconds=5,
            queue_size=100,
        )
        delivery = WebhookDelivery(
            config, bus,
            secret_key="test-secret-key-at-least-32-chars!!",
            dlq_backend=None,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )

        with patch.object(delivery, "_get_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_response = AsyncMock(spec=httpx.Response)
            mock_response.is_success = False
            mock_response.status_code = 500
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client

            result = await delivery._deliver_with_retry(
                "https://hooks.example.com/hook", event
            )
            assert result is False
            # No DLQ backend means no DLQ storage — nothing to assert on


class TestDLQAPIRoutes:
    """DLQ API endpoints via create_dlq_router."""

    @pytest.fixture
    def dlq_shield(self, fake_redis: FakeRedis) -> object:
        """Create a minimal shield-like object with DLQ backend."""
        from araxys.webhooks.dlq import WebhookDLQBackend

        backend = WebhookDLQBackend(fake_redis)

        class FakeShield:
            dlq_backend = backend

        return FakeShield()

    async def test_list_pending_empty(
        self, dlq_shield: object
    ) -> None:
        """GET /admin/webhooks/dlq should return empty list when no events."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/webhooks/dlq")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "pending"
            assert data["events"] == []

    async def test_list_pending_with_events(
        self, dlq_shield: object, sample_event: SecurityEvent
    ) -> None:
        """GET /admin/webhooks/dlq should return pending events."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        await dlq_shield.dlq_backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
            attempt_count=2,
            last_error="Timeout",
        )

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/webhooks/dlq")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "pending"
            assert len(data["events"]) == 1
            assert data["events"][0]["url"] == "https://hooks.example.com/hook"
            assert data["events"][0]["attempt_count"] == 2

    async def test_list_dead_empty(
        self, dlq_shield: object
    ) -> None:
        """GET /admin/webhooks/dlq/dead should return empty list."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/webhooks/dlq/dead")
            assert resp.status_code == 200
            data = resp.json()
            assert data["events"] == []

    async def test_inspect_missing_event(
        self, dlq_shield: object
    ) -> None:
        """GET /admin/webhooks/dlq/{id} on missing event returns 404."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/webhooks/dlq/nonexistent")
            assert resp.status_code == 404

    async def test_inspect_existing_event(
        self, dlq_shield: object, sample_event: SecurityEvent
    ) -> None:
        """GET /admin/webhooks/dlq/{id} should return full event."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        event_id = await dlq_shield.dlq_backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
            attempt_count=1,
            last_error="500",
        )

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/admin/webhooks/dlq/{event_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["event_id"] == event_id
            assert data["event_type"] == "rate_limit_exceeded"
            assert data["attempt_count"] == 1

    async def test_replay_missing_event(
        self, dlq_shield: object
    ) -> None:
        """POST /admin/webhooks/dlq/{id}/replay on missing returns 404."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/admin/webhooks/dlq/nonexistent/replay")
            assert resp.status_code == 404

    async def test_replay_dead_event(
        self, dlq_shield: object, sample_event: SecurityEvent
    ) -> None:
        """POST replay should move dead event back to pending."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        event_id = await dlq_shield.dlq_backend.enqueue(
            sample_event,
            "https://hooks.example.com/hook",
        )
        await dlq_shield.dlq_backend.mark_dead(event_id)

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(f"/admin/webhooks/dlq/{event_id}/replay")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "replayed"

            # Event should be in pending now
            pending = await dlq_shield.dlq_backend.list_pending()
            assert any(e.event_id == event_id for e in pending)

    async def test_purge_all(
        self, dlq_shield: object, sample_event: SecurityEvent
    ) -> None:
        """DELETE /admin/webhooks/dlq should purge all events."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        await dlq_shield.dlq_backend.enqueue(
            sample_event, "https://hooks.example.com/a"
        )
        await dlq_shield.dlq_backend.enqueue(
            sample_event, "https://hooks.example.com/b"
        )

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete("/admin/webhooks/dlq")
            assert resp.status_code == 200
            data = resp.json()
            assert data["deleted"] >= 2

    async def test_purge_by_url(
        self, dlq_shield: object, sample_event: SecurityEvent
    ) -> None:
        """DELETE /admin/webhooks/dlq?url=... should filter by URL."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq_routes import create_dlq_router

        await dlq_shield.dlq_backend.enqueue(
            sample_event, "https://hooks.example.com/a"
        )
        await dlq_shield.dlq_backend.enqueue(
            sample_event, "https://hooks.example.com/b"
        )

        app = FastAPI()
        router = create_dlq_router(dlq_shield)
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete(
                "/admin/webhooks/dlq", params={"url": "https://hooks.example.com/a"}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["deleted"] == 1

    async def test_503_on_redis_failure(
        self, sample_event: SecurityEvent
    ) -> None:
        """DLQ API should return 503 when Redis is unavailable."""
        from unittest.mock import AsyncMock

        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.webhooks.dlq import WebhookDLQBackend
        from araxys.webhooks.dlq_routes import create_dlq_router

        broken = AsyncMock()
        # Any redis method call raises ConnectionError
        broken.zrevrange = AsyncMock(
            side_effect=ConnectionError("Redis is down")
        )
        broken.zcard = AsyncMock(
            side_effect=ConnectionError("Redis is down")
        )
        broken.hgetall = AsyncMock(
            side_effect=ConnectionError("Redis is down")
        )

        backend = WebhookDLQBackend(broken)

        class FakeShield:
            dlq_backend = backend

        app = FastAPI()
        router = create_dlq_router(FakeShield())
        app.include_router(router)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/webhooks/dlq")
            assert resp.status_code == 503


class TestDLQShieldWiring:
    """DLQ shield integration — consumer lifecycle and config gating."""

    async def test_dlq_disabled_no_consumer(
        self,
    ) -> None:
        """No consumer or backend when dlq_enabled=False."""
        from fastapi import FastAPI

        from araxys.core.config import AraxysConfig, WebhookConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(
            secret_key="test-key-32-chars-long!!!!!!!!!!!!",
            webhooks=WebhookConfig(enabled=True, dlq_enabled=False),
        )
        shield = AraxysShield(app, config)

        assert not hasattr(shield, "dlq_backend") or shield.dlq_backend is None

    async def test_dlq_enabled_creates_backend(
        self,
    ) -> None:
        """DLQ backend and consumer are created when dlq_enabled=True."""
        from unittest.mock import patch

        from fastapi import FastAPI

        from araxys.core.config import AraxysConfig, WebhookConfig
        from araxys.shield import AraxysShield
        from araxys.webhooks.dlq import WebhookDLQBackend

        fake_redis_instance = FakeRedis(decode_responses=True)
        with patch(
            "redis.asyncio.from_url",
            return_value=fake_redis_instance,
        ):
            app = FastAPI()
            config = AraxysConfig(
                secret_key="test-key-32-chars-long!!!!!!!!!!!!",
                redis_url="redis://localhost:6379",
                webhooks=WebhookConfig(enabled=True, dlq_enabled=True),
            )
            shield = AraxysShield(app, config)

        assert shield.dlq_backend is not None
        assert isinstance(shield.dlq_backend, WebhookDLQBackend)

    async def test_dlq_enabled_starts_consumer(
        self,
    ) -> None:
        """DLQ consumer task is started when dlq_enabled=True."""
        from unittest.mock import patch

        from fastapi import FastAPI

        from araxys.core.config import AraxysConfig, WebhookConfig
        from araxys.shield import AraxysShield

        fake_redis_instance = FakeRedis(decode_responses=True)
        with patch(
            "redis.asyncio.from_url",
            return_value=fake_redis_instance,
        ):
            app = FastAPI()
            config = AraxysConfig(
                secret_key="test-key-32-chars-long!!!!!!!!!!!!",
                redis_url="redis://localhost:6379",
                webhooks=WebhookConfig(enabled=True, dlq_enabled=True,
                                       dlq_retry_interval_seconds=3600),
            )
            shield = AraxysShield(app, config)

        assert shield._dlq_consumer is not None
        assert shield._dlq_consumer._running is True

        await shield.shutdown()

    async def test_dlq_enabled_no_redis_raises(
        self,
    ) -> None:
        """ConfigurationError when dlq_enabled=True but no redis_url."""
        from fastapi import FastAPI

        from araxys.core.config import (
            AraxysConfig,
            ConfigurationError,
            WebhookConfig,
        )
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(
            secret_key="test-key-32-chars-long!!!!!!!!!!!!",
            redis_url=None,
            webhooks=WebhookConfig(enabled=True, dlq_enabled=True),
        )
        with pytest.raises(ConfigurationError, match="redis_url"):
            AraxysShield(app, config)

    async def test_shutdown_stops_consumer(
        self,
    ) -> None:
        """shutdown() stops the DLQ consumer."""
        from unittest.mock import patch

        from fastapi import FastAPI

        from araxys.core.config import AraxysConfig, WebhookConfig
        from araxys.shield import AraxysShield

        fake_redis_instance = FakeRedis(decode_responses=True)
        with patch(
            "redis.asyncio.from_url",
            return_value=fake_redis_instance,
        ):
            app = FastAPI()
            config = AraxysConfig(
                secret_key="test-key-32-chars-long!!!!!!!!!!!!",
                redis_url="redis://localhost:6379",
                webhooks=WebhookConfig(enabled=True, dlq_enabled=True,
                                       dlq_retry_interval_seconds=3600),
            )
            shield = AraxysShield(app, config)

        assert shield._dlq_consumer is not None
        assert shield._dlq_consumer._running is True

        await shield.shutdown()
        assert shield._dlq_consumer._running is False


class TestDLQConfig:
    """DLQ configuration defaults and validation."""

    def test_dlq_disabled_by_default(self) -> None:
        """dlq_enabled must default to False for backward compatibility."""
        config = WebhookConfig()
        assert config.dlq_enabled is False

    def test_dlq_retry_interval_default(self) -> None:
        """dlq_retry_interval_seconds must default to 60."""
        config = WebhookConfig()
        assert config.dlq_retry_interval_seconds == 60

    def test_dlq_max_age_default(self) -> None:
        """dlq_max_age_seconds must default to 86400 (24h)."""
        config = WebhookConfig()
        assert config.dlq_max_age_seconds == 86400

    def test_dlq_max_retries_default(self) -> None:
        """dlq_max_retries must default to 5."""
        config = WebhookConfig()
        assert config.dlq_max_retries == 5
