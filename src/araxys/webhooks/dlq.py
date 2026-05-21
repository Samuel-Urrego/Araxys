"""Dead-Letter Queue for failed webhook deliveries.

Persists failed webhook events in Redis, retries them on a schedule
via a background consumer task, and exposes an API for inspection
and management.

All operations are opt-in — ``dlq_enabled=False`` (the default) means
zero Redis calls, no consumer task, no API routes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from redis.asyncio import Redis

    from araxys.core.config import WebhookConfig

from araxys.core.types import SecurityEvent, SecurityEventType

logger = logging.getLogger("araxys.webhooks.dlq")

# ── Lua scripts ──────────────────────────────────────────────────────────────

REPLAY_EVENT_SCRIPT: str = """
local event_id = KEYS[1]
local next_retry_at = tonumber(ARGV[1])
redis.call('ZREM', 'dlq:dead', event_id)
redis.call('HSET', 'dlq:event:' .. event_id,
    'attempt_count', 0,
    'status', 'pending',
    'next_retry_at', next_retry_at)
redis.call('ZADD', 'dlq:pending', next_retry_at, event_id)
return 1
"""

RESCHEDULE_OR_MARK_DEAD_SCRIPT: str = """
local event_id = KEYS[1]
local max_retries = tonumber(ARGV[1])
local next_retry = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local last_error = ARGV[4]
local key = 'dlq:event:' .. event_id
local current = tonumber(redis.call('HGET', key, 'attempt_count') or '0')
local new_count = current + 1
redis.call('HSET', key,
    'attempt_count', new_count,
    'last_error', last_error)
if new_count >= max_retries then
    redis.call('ZREM', 'dlq:pending', event_id)
    redis.call('ZADD', 'dlq:dead', now, event_id)
    redis.call('HSET', key, 'status', 'dead')
    return 0
else
    redis.call('ZADD', 'dlq:pending', next_retry, event_id)
    redis.call('HSET', key, 'next_retry_at', next_retry)
    return 1
end
"""

# ── Dataclasses ──────────────────────────────────────────────────────────────


@dataclass
class DLQEvent:
    """Full DLQ event stored in a Redis HASH."""

    event_id: str
    event_type: str
    payload: str  # JSON of SecurityEvent
    url: str
    attempt_count: int
    last_error: str
    next_retry_at: float  # Unix timestamp
    original_timestamp: str  # ISO format
    status: Literal["pending", "dead"]
    created_at: str  # ISO format


@dataclass
class DLQEventSummary:
    """Lightweight summary returned by list endpoints (no payload)."""

    event_id: str
    event_type: str
    url: str
    attempt_count: int
    next_retry_at: float
    age_seconds: float
    status: str


# ── Redis backend ────────────────────────────────────────────────────────────


class WebhookDLQBackend:
    """Redis-backed dead-letter queue for failed webhook deliveries.

    Events are stored as Redis HASH entries keyed by ``dlq:event:{event_id}``
    and indexed in sorted sets ``dlq:pending`` / ``dlq:dead`` for scheduling
    and status tracking.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def enqueue(
        self,
        event: SecurityEvent,
        url: str,
        *,
        attempt_count: int = 1,
        last_error: str = "",
    ) -> str:
        """Persist a failed delivery to the DLQ.

        Stores event data in a HASH and indexes the event ID in
        ``dlq:pending`` with a score of ``next_retry_at``.
        Returns the generated ``event_id``.
        """
        event_id = uuid.uuid4().hex
        now = time.time()
        now_iso = datetime.now(UTC).isoformat()

        payload = {
            "event_type": event.event_type.value,
            "payload": json.dumps(self._build_event_dict(event), default=str),
            "url": url,
            "attempt_count": attempt_count,
            "last_error": last_error,
            "next_retry_at": now,  # eligible immediately
            "original_timestamp": event.timestamp.isoformat(),
            "status": "pending",
            "created_at": now_iso,
        }

        key = f"dlq:event:{event_id}"
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.hset(key, mapping=payload)
            pipe.zadd("dlq:pending", {event_id: now})
            await pipe.execute()

        return event_id

    async def dequeue_eligible(
        self, *, batch_size: int = 10
    ) -> list[DLQEvent]:
        """Return events where ``next_retry_at <= now()`` from ``dlq:pending``.

        Uses ``ZRANGEBYSCORE`` with ``LIMIT`` for a safe non-destructive
        read — events are removed from the sorted set only when
        rescheduled or marked dead by the caller.
        """
        now = time.time()
        event_ids: list[str] = await self._redis.zrangebyscore(
            "dlq:pending", 0, now, start=0, num=batch_size
        )
        if not event_ids:
            return []

        events = await self._fetch_events(event_ids)
        return [e for e in events if e is not None]

    async def mark_dead(self, event_id: str) -> None:
        """Move an event from ``dlq:pending`` to ``dlq:dead``."""
        now = time.time()
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.zrem("dlq:pending", event_id)
            pipe.zadd("dlq:dead", {event_id: now})
            pipe.hset(f"dlq:event:{event_id}", "status", "dead")
            await pipe.execute()

    async def remove(self, event_id: str) -> bool:
        """Remove an event entirely from Redis.

        Returns ``True`` if the event existed, ``False`` otherwise.
        """
        key = f"dlq:event:{event_id}"
        exists = await self._redis.exists(key)
        if not exists:
            return False

        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            pipe.zrem("dlq:pending", event_id)
            pipe.zrem("dlq:dead", event_id)
            await pipe.execute()
        return True

    async def list_pending(
        self, limit: int = 100, offset: int = 0
    ) -> list[DLQEventSummary]:
        """Return summaries of pending events, newest first."""
        return await self._list_summaries("dlq:pending", limit, offset)

    async def list_dead(
        self, limit: int = 100, offset: int = 0
    ) -> list[DLQEventSummary]:
        """Return summaries of dead events, newest first."""
        return await self._list_summaries("dlq:dead", limit, offset)

    async def inspect(self, event_id: str) -> DLQEvent | None:
        """Return the full event data for a given ``event_id``.

        Returns ``None`` if the event does not exist.
        """
        key = f"dlq:event:{event_id}"
        data: dict[Any, Any] = await self._redis.hgetall(key)  # type: ignore[misc]
        if not data:
            return None
        return self._hash_to_event(event_id, data)

    async def purge_all(self) -> int:
        """Delete ALL DLQ keys from Redis.

        Returns the total number of keys deleted.
        """
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor, match="dlq:*", count=100
            )
            if keys:
                await self._redis.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
        return deleted

    async def purge_by_url(self, url: str) -> int:
        """Delete all DLQ events matching a specific webhook URL.

        Uses SCAN to find matching ``dlq:event:*`` keys, then
        filters client-side by inspecting the HASH ``url`` field.
        Returns the number of events deleted.
        """
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor, match="dlq:event:*", count=100
            )
            for key in keys:
                stored_url = await self._redis.hget(key, "url")  # type: ignore[misc]
                if stored_url == url:
                    event_id = key.split(":", 2)[2]
                    async with self._redis.pipeline(transaction=True) as pipe:
                        pipe.delete(key)
                        pipe.zrem("dlq:pending", event_id)
                        pipe.zrem("dlq:dead", event_id)
                        await pipe.execute()
                    deleted += 1
            if cursor == 0:
                break
        return deleted

    async def _fetch_events(self, event_ids: list[str]) -> list[DLQEvent | None]:
        """Fetch full event data for multiple event IDs."""
        keys = [f"dlq:event:{eid}" for eid in event_ids]
        results = await asyncio.gather(
            *(self._redis.hgetall(key) for key in keys),  # type: ignore[arg-type]
            return_exceptions=True,
        )
        events: list[DLQEvent | None] = []
        for i, eid in enumerate(event_ids):
            data = results[i]
            if isinstance(data, dict) and data:
                events.append(self._hash_to_event(eid, data))
            else:
                events.append(None)
        return events

    async def _list_summaries(
        self, zset_key: str, limit: int, offset: int
    ) -> list[DLQEventSummary]:
        """Return event summaries from a sorted set, ordered by score DESC."""
        total = await self._redis.zcard(zset_key)
        if offset >= total:
            return []

        # ZREVRANGE by rank to get newest first
        end = offset + limit - 1
        event_ids: list[str] = await self._redis.zrevrange(
            zset_key, offset, end
        )
        if not event_ids:
            return []

        summaries: list[DLQEventSummary] = []
        for eid in event_ids:
            data: dict[Any, Any] = await self._redis.hgetall(f"dlq:event:{eid}")  # type: ignore[misc]
            if data:
                next_retry = float(
                    data.get(b"next_retry_at", data.get("next_retry_at", 0))
                )
                created_raw = data.get(
                    b"created_at", data.get("created_at", "")
                )
                created_val = (
                    created_raw.decode()
                    if isinstance(created_raw, bytes)
                    else str(created_raw)
                )

                try:
                    created_dt = datetime.fromisoformat(created_val)
                    age = (datetime.now(UTC) - created_dt).total_seconds()
                except (ValueError, TypeError):
                    age = 0.0

                summaries.append(
                    DLQEventSummary(
                        event_id=eid,
                        event_type=self._decode_field(data, "event_type", ""),
                        url=self._decode_field(data, "url", ""),
                        attempt_count=int(
                            self._decode_field(data, "attempt_count", "0")
                        ),
                        next_retry_at=next_retry,
                        age_seconds=age,
                        status=self._decode_field(data, "status", "unknown"),
                    )
                )
        return summaries

    @staticmethod
    def _hash_to_event(event_id: str, data: dict[Any, Any]) -> DLQEvent:
        """Convert a raw Redis HASH to a ``DLQEvent`` instance."""
        return DLQEvent(
            event_id=event_id,
            event_type=WebhookDLQBackend._decode_field(data, "event_type", ""),
            payload=WebhookDLQBackend._decode_field(data, "payload", "{}"),
            url=WebhookDLQBackend._decode_field(data, "url", ""),
            attempt_count=int(
                WebhookDLQBackend._decode_field(data, "attempt_count", "0")
            ),
            last_error=WebhookDLQBackend._decode_field(data, "last_error", ""),
            next_retry_at=float(
                WebhookDLQBackend._decode_field(data, "next_retry_at", "0")
            ),
            original_timestamp=WebhookDLQBackend._decode_field(
                data, "original_timestamp", ""
            ),
            status=WebhookDLQBackend._decode_field(
                data, "status", "pending"
            ),  # type: ignore[arg-type]
            created_at=WebhookDLQBackend._decode_field(data, "created_at", ""),
        )

    @staticmethod
    def _decode_field(
        data: dict[Any, Any], field: str, default: str
    ) -> str:
        """Decode a Redis HASH field that may be ``bytes`` or ``str``."""
        val = data.get(field) or data.get(field.encode())
        if val is None:
            return default
        if isinstance(val, bytes):
            return val.decode("utf-8")
        return str(val)

    @staticmethod
    def _build_event_dict(event: SecurityEvent) -> dict[str, object]:
        """Build a serialisable dict from a SecurityEvent."""
        return {
            "event_type": event.event_type.value,
            "severity": event.severity,
            "message": event.message,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "metadata": event.metadata,
        }


# ── Background consumer ──────────────────────────────────────────────────────


class DLQConsumer:
    """Background task that polls the DLQ and re-dispatches eligible events.

    Runs an infinite loop that:
    1. Polls ``dlq:pending`` for events with ``next_retry_at <= now()``
    2. Re-dispatches each event via ``WebhookDelivery._deliver_with_retry()``
    3. On success, removes the event from the DLQ
    4. On failure, reschedules via Lua script or marks as dead
    """

    def __init__(
        self,
        backend: WebhookDLQBackend,
        deliver_fn: Callable[[str, SecurityEvent], Awaitable[bool]],
        config: WebhookConfig,
    ) -> None:
        self._backend = backend
        self._deliver_fn = deliver_fn
        self._config = config
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def start(self) -> None:
        """Start the background consumer poll loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop the consumer poll loop."""
        self._running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    @staticmethod
    def _reconstruct_event(event: DLQEvent) -> SecurityEvent:
        """Reconstruct a SecurityEvent from the DLQEvent's stored payload."""
        payload = json.loads(event.payload)
        return SecurityEvent(
            event_type=SecurityEventType(payload["event_type"]),
            severity=payload["severity"],
            message=payload["message"],
            timestamp=datetime.fromisoformat(payload["timestamp"]),
            source_ip=payload.get("source_ip"),
            metadata=payload.get("metadata", {}),
        )

    async def _poll_loop(self) -> None:
        """Infinite loop: poll, dispatch, sleep."""
        while self._running:
            try:
                await self._poll_once()
            except Exception:
                logger.exception("DLQ consumer poll cycle failed")

            await asyncio.sleep(self._config.dlq_retry_interval_seconds)

    async def _poll_once(self) -> None:
        """Single poll cycle: fetch eligible events and dispatch each."""
        events = await self._backend.dequeue_eligible(batch_size=10)
        for event in events:
            try:
                sec_event = self._reconstruct_event(event)
                success = await self._deliver_fn(event.url, sec_event)
            except Exception:
                logger.exception(
                    "DLQ consumer dispatch failed for %s", event.event_id
                )
                success = False

            if success:
                await self._backend.remove(event.event_id)
            else:
                await self._reschedule_or_mark_dead(event)

    async def _reschedule_or_mark_dead(self, event: DLQEvent) -> None:
        """Increment retry count and reschedule or mark as dead.

        Uses a Redis pipeline for atomic read-and-update.
        """
        redis = self._backend._redis  # noqa: SLF001
        key = f"dlq:event:{event.event_id}"
        max_retries = self._config.dlq_max_retries

        # Read current attempt count
        raw = await redis.hget(key, "attempt_count")  # type: ignore[misc]
        current = int(raw) if raw else 0
        new_count = current + 1

        now = time.time()
        pipe = redis.pipeline(transaction=True)

        if new_count >= max_retries:
            pipe.zrem("dlq:pending", event.event_id)
            pipe.zadd("dlq:dead", {event.event_id: now})
            pipe.hset(key, "attempt_count", str(new_count))
            pipe.hset(key, "status", "dead")
            pipe.hset(key, "last_error", event.last_error)
            await pipe.execute()
            logger.info(
                "DLQ event %s marked dead after %d retries",
                event.event_id,
                max_retries,
            )
        else:
            next_retry = now + self._config.dlq_retry_interval_seconds
            pipe.zadd("dlq:pending", {event.event_id: next_retry})
            pipe.hset(key, "attempt_count", str(new_count))
            pipe.hset(key, "next_retry_at", str(next_retry))
            pipe.hset(key, "last_error", event.last_error)
            await pipe.execute()
