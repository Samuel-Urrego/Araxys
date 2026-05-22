"""Security event bus — async pub/sub with asyncio.Queue."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from araxys.core.types import SecurityEvent

logger = logging.getLogger("araxys.webhooks")


class SecurityEventBus:
    """Async event bus for security events.

    Uses an ``asyncio.Queue`` internally. Subscribers are async callables
    invoked in sequence for every event. A failing subscriber does NOT
    prevent other subscribers from receiving the event.
    """

    def __init__(self, queue_size: int = 1000) -> None:
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(
            maxsize=queue_size
        )
        self._subscribers: list[Callable[[SecurityEvent], Awaitable[None]]] = []
        self._consumer_task: asyncio.Task[None] | None = None
        self._running = False

    def subscribe(
        self, callback: Callable[[SecurityEvent], Awaitable[None]]
    ) -> None:
        """Register a subscriber callback."""
        self._subscribers.append(callback)

    async def emit(self, event: SecurityEvent) -> None:
        """Publish an event to the queue.

        If the queue is full, the event is dropped and a warning is logged.
        This prevents backpressure from blocking the middleware call chain
        (IP Access, Brute Force) when the webhook consumer stalls.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning(
                "Webhook event queue full (%d) — dropping event %s",
                self._queue.maxsize,
                event.event_type,
            )

    def start(self) -> None:
        """Begin consuming the event queue in a background task."""
        if self._running:
            return
        self._running = True
        self._consumer_task = asyncio.create_task(self._consume())

    async def stop(self, *, immediate: bool = False) -> None:
        """Graceful shutdown.

        By default, waits for the queue to drain. Use *immediate=True*
        to cancel the consumer right away.
        """
        self._running = False
        if self._consumer_task is None or self._consumer_task.done():
            self._consumer_task = None
            return

        if not immediate:
            # Wait for queued events to be processed
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._queue.join(), timeout=5.0)

        if not self._consumer_task.done():
            self._consumer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._consumer_task
            self._consumer_task = None

    async def _consume(self) -> None:
        """Internal loop: get events from the queue and dispatch."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._queue.get(), timeout=0.5
                )
            except TimeoutError:
                # Periodic wake-up so we can check _running flag
                continue
            except asyncio.CancelledError:
                # Mark the event as done so join() doesn't hang
                with contextlib.suppress(ValueError):
                    self._queue.task_done()
                raise

            await self._dispatch(event)
            self._queue.task_done()

        # Drain remaining events after _running is False
        while True:
            try:
                event = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            await self._dispatch(event)
            self._queue.task_done()

    async def _dispatch(self, event: SecurityEvent) -> None:
        """Call all subscribers, isolating failures."""
        for cb in self._subscribers:
            try:
                await cb(event)
            except Exception:
                logger.exception(
                    "Webhook subscriber failed for event %s",
                    event.event_type,
                )
