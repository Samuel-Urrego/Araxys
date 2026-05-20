"""Webhook delivery — HTTP POST with retry and HMAC-SHA256 signing.

Outgoing payloads are signed with ``HMAC-SHA256(secret, body_bytes)``
and sent with ``X-Signature-256`` and ``X-Webhook-Timestamp`` headers
so that receiving endpoints can verify authenticity and detect replay
attacks.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from araxys.core.config import WebhookConfig
    from araxys.core.types import SecurityEvent
    from araxys.webhooks.emitter import SecurityEventBus

logger = logging.getLogger("araxys.webhooks.delivery")

_RETRY_DELAYS = [1.0, 2.0, 4.0]  # exponential backoff (seconds)


def _is_valid_url(url: str) -> bool:
    """Return ``True`` if the URL uses an allowed scheme (https only)."""
    return url.startswith("https://")


class WebhookDelivery:
    """Delivers security events to registered webhook URLs.

    Subscribes to a ``SecurityEventBus`` on init and dispatches matching
    events via HTTP POST with exponential backoff retry.  Every payload
    is signed with ``HMAC-SHA256`` using the configured secret key and
    includes a timestamp for replay protection.

    Parameters
    ----------
    config:
        Webhook configuration (URLs, retries, timeout).
    event_bus:
        The security event bus to subscribe to.
    secret_key:
        The master secret key used for HMAC-SHA256 signing.
    """

    def __init__(
        self,
        config: WebhookConfig,
        event_bus: SecurityEventBus,
        secret_key: str,
    ) -> None:
        self._config = config
        self._event_bus = event_bus
        self._secret_key = secret_key.encode("utf-8")
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
            if not _is_valid_url(url):
                logger.warning("Webhook URL rejected (insecure scheme): %s", url)
                continue
            asyncio.create_task(self._deliver_with_retry(url, event))

    async def _deliver_with_retry(
        self, url: str, event: SecurityEvent
    ) -> None:
        """POST the event to *url* with exponential backoff retry."""
        client = await self._get_client()
        payload = self._build_payload(event)
        body = json.dumps(payload, default=str).encode("utf-8")  # raw bytes for signing
        timestamp = str(int(time.time()))

        signature = "sha256=" + hmac.new(
            self._secret_key, body, hashlib.sha256
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Signature-256": signature,
            "X-Webhook-Timestamp": timestamp,
        }

        for attempt in range(self._config.retry_max + 1):
            try:
                response = await client.post(url, content=body, headers=headers)
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

    @staticmethod
    def verify_signature(
        body: bytes,
        signature_header: str,
        secret_key: str,
        *,
        tolerance_seconds: int = 300,
        timestamp_header: str | None = None,
    ) -> bool:
        """Verify an incoming webhook's HMAC-SHA256 signature.

        Use this to validate webhooks received FROM external services
        that use the same signing scheme.

        Parameters
        ----------
        body:
            The raw request body bytes.
        signature_header:
            The ``X-Signature-256`` header value (``sha256=<hex>``).
        secret_key:
            The shared secret used for signing.
        tolerance_seconds:
            Maximum allowed age of the timestamp to prevent replay
            attacks.  Set to ``0`` to skip timestamp validation.
        timestamp_header:
            Optional ``X-Webhook-Timestamp`` header value.

        Returns
        -------
        bool
            ``True`` if the signature is valid and the timestamp is
            within tolerance.
        """
        if not signature_header.startswith("sha256="):
            return False

        expected = signature_header.removeprefix("sha256=")
        computed = hmac.new(
            secret_key.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(computed, expected):
            return False

        if timestamp_header is not None and tolerance_seconds > 0:
            try:
                age = int(time.time()) - int(timestamp_header)
            except (ValueError, TypeError):
                return False
            if age < 0 or age > tolerance_seconds:
                return False

        return True
