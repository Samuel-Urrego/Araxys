"""Webhook delivery — HTTP POST with retry logic."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from araxys.core.config import WebhookConfig
    from araxys.core.types import SecurityEvent
    from araxys.webhooks.emitter import SecurityEventBus

logger = logging.getLogger("araxys.webhooks.delivery")

_RETRY_DELAYS = [1.0, 2.0, 4.0]  # exponential backoff (seconds)


class WebhookDelivery:
    """Delivers security events to registered webhook URLs.

    Subscribes to a ``SecurityEventBus`` on init and dispatches matching
    events via HTTP POST with exponential backoff retry.
    """

    def __init__(
        self, config: WebhookConfig, event_bus: SecurityEventBus
    ) -> None:
        self._config = config
        self._event_bus = event_bus
        self._http_client: httpx.AsyncClient | None = None
        event_bus.subscribe(self._on_event)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout_seconds)
            )
        return self._http_client

    async def _on_event(self, event: SecurityEvent) -> None:
        """Match event type to URLs and fire-and-forget deliveries."""
        event_key = event.event_type.value
        urls = self._config.urls.get(event_key, [])
        if not urls:
            return

        # Fire-and-forget: spawn tasks so we don't block the event bus
        for url in urls:
            asyncio.create_task(self._deliver_with_retry(url, event))

    async def _deliver_with_retry(
        self, url: str, event: SecurityEvent
    ) -> None:
        """POST the event to *url* with exponential backoff retry."""
        client = await self._get_client()
        payload = self._build_payload(event)

        for attempt in range(self._config.retry_max + 1):
            try:
                response = await client.post(url, json=payload)
                if response.is_success:
                    return
                logger.warning(
                    "Webhook delivery to %s returned %d (attempt %d/%d)",
                    url,
                    response.status_code,
                    attempt + 1,
                    self._config.retry_max + 1,
                )
            except httpx.RequestError as exc:
                logger.warning(
                    "Webhook delivery to %s failed: %s (attempt %d/%d)",
                    url,
                    exc,
                    attempt + 1,
                    self._config.retry_max + 1,
                )

            if attempt < self._config.retry_max:
                delay = _RETRY_DELAYS[attempt]
                await asyncio.sleep(delay)

    @staticmethod
    def _build_payload(event: SecurityEvent) -> dict[str, object]:
        """Build the standard webhook JSON payload."""
        return {
            "event_type": event.event_type.value,
            "severity": event.severity,
            "message": event.message,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "metadata": event.metadata,
        }
