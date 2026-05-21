"""DLQ Admin API — inspection and management endpoints.

Provides a FastAPI router factory that exposes dead-letter queue
inspection, replay, and purge operations.

Usage::

    from araxys.webhooks.dlq_routes import create_dlq_router

    app.include_router(create_dlq_router(shield))
"""

# mypy: disable-error-code="attr-defined,union-attr"
# The DLQ router uses runtime attribute access on the shield —
# static type checking on dynamic attributes is not useful here.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Query

if TYPE_CHECKING:
    from araxys.shield import AraxysShield


def create_dlq_router(
    shield: AraxysShield,
    *,
    prefix: str = "/admin/webhooks",
) -> APIRouter:
    """Create a FastAPI router with DLQ management endpoints.

    All endpoints require the DLQ backend to be available.
    Returns 503 when the backend is unavailable.

    Parameters
    ----------
    shield:
        The ``AraxysShield`` instance.
    prefix:
        URL prefix for DLQ routes (default ``/admin/webhooks``).

    Routes
    ------
    ``GET /admin/webhooks/dlq`` — List pending events (optional ``?status=dead``)
    ``GET /admin/webhooks/dlq/dead`` — List dead events
    ``GET /admin/webhooks/dlq/{event_id}`` — Inspect a single event
    ``POST /admin/webhooks/dlq/{event_id}/replay`` — Re-enqueue a dead event
    ``DELETE /admin/webhooks/dlq`` — Purge all or by ``?url=``
    """
    router = APIRouter(prefix=prefix, tags=["dlq"])

    def _get_backend() -> Any:
        """Get the DLQ backend from the shield, or raise 503."""
        backend = getattr(shield, "dlq_backend", None)
        if backend is None:
            raise HTTPException(
                503, detail="DLQ backend not available"
            )
        return backend

    # ── List pending ────────────────────────────────────────────

    @router.get("/dlq")
    async def list_pending(
        status: str = Query(default="pending", pattern="^(pending|dead)$"),
    ) -> dict[str, Any]:
        """List DLQ events by status (pending or dead)."""
        backend = _get_backend()
        try:
            if status == "dead":
                events = await backend.list_dead()
            else:
                events = await backend.list_pending()
        except (ConnectionError, OSError):
            raise HTTPException(503, detail="Redis unavailable") from None

        return {
            "status": status,
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "url": e.url,
                    "attempt_count": e.attempt_count,
                    "next_retry_at": e.next_retry_at,
                    "age_seconds": e.age_seconds,
                    "status": e.status,
                }
                for e in events
            ],
        }

    # ── List dead ───────────────────────────────────────────────

    @router.get("/dlq/dead")
    async def list_dead() -> dict[str, Any]:
        """List dead DLQ events."""
        backend = _get_backend()
        try:
            events = await backend.list_dead()
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        return {
            "status": "dead",
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "url": e.url,
                    "attempt_count": e.attempt_count,
                    "next_retry_at": e.next_retry_at,
                    "age_seconds": e.age_seconds,
                    "status": e.status,
                }
                for e in events
            ],
        }

    # ── Inspect ─────────────────────────────────────────────────

    @router.get("/dlq/{event_id}")
    async def inspect_event(event_id: str) -> dict[str, Any]:
        """Return full event details by event_id."""
        backend = _get_backend()
        try:
            event = await backend.inspect(event_id)
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        if event is None:
            raise HTTPException(404, detail="Event not found")

        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "payload": event.payload,
            "url": event.url,
            "attempt_count": event.attempt_count,
            "last_error": event.last_error,
            "next_retry_at": event.next_retry_at,
            "original_timestamp": event.original_timestamp,
            "status": event.status,
            "created_at": event.created_at,
        }

    # ── Replay ──────────────────────────────────────────────────

    @router.post("/dlq/{event_id}/replay")
    async def replay_event(event_id: str) -> dict[str, str]:
        """Re-enqueue a dead event back to pending."""
        backend = _get_backend()
        try:
            event = await backend.inspect(event_id)
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        if event is None:
            raise HTTPException(404, detail="Event not found")

        # Move from dead to pending with reset attempt count
        try:
            await backend._redis.zrem("dlq:dead", event_id)  # noqa: SLF001
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        import time

        now = time.time()
        async with backend._redis.pipeline(transaction=True) as pipe:  # noqa: SLF001
            pipe.hset(f"dlq:event:{event_id}", "attempt_count", "0")
            pipe.hset(f"dlq:event:{event_id}", "status", "pending")
            pipe.hset(f"dlq:event:{event_id}", "next_retry_at", str(now))
            pipe.zadd("dlq:pending", {event_id: now})
            await pipe.execute()

        return {"status": "replayed", "event_id": event_id}

    # ── Purge ───────────────────────────────────────────────────

    @router.delete("/dlq")
    async def purge(
        url: str | None = Query(default=None),
    ) -> dict[str, Any]:
        """Purge DLQ events.

        If ``url`` is provided, only events matching that URL are
        purged.  Otherwise all events are purged.
        """
        backend = _get_backend()
        try:
            if url:
                deleted = await backend.purge_by_url(url)
            else:
                deleted = await backend.purge_all()
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        return {"deleted": deleted}

    return router
