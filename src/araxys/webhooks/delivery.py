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
import ipaddress
import json
import logging
import socket
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if TYPE_CHECKING:
    from araxys.core.config import WebhookConfig
    from araxys.core.types import SecurityEvent
    from araxys.webhooks.dlq import WebhookDLQBackend
    from araxys.webhooks.emitter import SecurityEventBus

logger = logging.getLogger("araxys.webhooks.delivery")

_RETRY_DELAYS = [1.0, 2.0, 4.0]  # exponential backoff (seconds)


def _derive_webhook_key(master_key: bytes) -> bytes:
    """Derive a webhook-specific HMAC key from the master secret via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"webhook_signing",
        info=b"hmac-sha256",
    )
    return hkdf.derive(master_key)


_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),       # "This" network
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC 1918
    ipaddress.IPv4Network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC 1918
    ipaddress.IPv4Network("192.0.0.0/29"),     # DS-Lite
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.IPv4Network("192.88.99.0/24"),   # 6to4 relay
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC 1918
    ipaddress.IPv4Network("198.18.0.0/15"),    # Benchmarking
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved
]


def _is_private_host(host: str) -> bool:
    """Return ``True`` if *host* resolves to a private/loopback/link-local IP.

    Direct IP addresses are checked immediately. Hostnames that fail
    DNS resolution are allowed (they cannot be used as an SSRF vector
    since the attacker cannot control DNS for arbitrary domains).

    .. warning::

        This check is vulnerable to DNS rebinding TOCTOU: a domain can
        resolve to a public IP at validation time and to 127.0.0.1 when
        ``httpx`` connects.  This is a fundamental limitation of
        hostname-based SSRF protection without a custom transport that
        pins the resolved address.  Production deployments should use
        network-level egress filtering (firewall rules, service mesh)
        to block outbound connections to private IP ranges.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, OSError):
            return False  # DNS unresolvable — not a private IP attack
    if addr.version == 6:
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
            return (
                any(addr in net for net in _PRIVATE_NETWORKS)
                or addr.is_loopback
                or addr.is_multicast
            )
        return (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_private
            or addr.is_unspecified
        )
    return (
        any(addr in net for net in _PRIVATE_NETWORKS)
        or addr.is_loopback
        or addr.is_multicast
    )


def _is_valid_url(url: str) -> bool:
    """Return ``True`` if the URL uses HTTPS and does not point to a private address."""
    if not url.startswith("https://"):
        return False
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            return False
        return not _is_private_host(host)
    except Exception:
        return False


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
        dlq_backend: WebhookDLQBackend | None = None,
        max_concurrent_deliveries: int = 50,
    ) -> None:
        self._config = config
        self._event_bus = event_bus
        self._secret_key = _derive_webhook_key(secret_key.encode("utf-8"))
        self._dlq_backend = dlq_backend
        self._http_client: httpx.AsyncClient | None = None
        self._delivery_semaphore = asyncio.Semaphore(max_concurrent_deliveries)
        event_bus.subscribe(self._on_event)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout_seconds),
                follow_redirects=False,
            )
        return self._http_client

    async def _on_event(self, event: SecurityEvent) -> None:
        """Match event type to URLs and fire-and-forget deliveries."""
        event_key = event.event_type.value
        urls = self._config.urls.get(event_key, [])
        if not urls:
            return

        # Fire-and-forget: spawn tasks so we don't block the event bus
        # Semaphore limits concurrent outgoing deliveries to prevent memory exhaustion
        for url in urls:
            if not _is_valid_url(url):
                logger.warning("Webhook URL rejected (insecure scheme): %s", url)
                continue
            asyncio.create_task(self._deliver_guarded(url, event))

    async def _deliver_guarded(self, url: str, event: SecurityEvent) -> None:
        """Acquire semaphore before delivering to prevent unbounded concurrency."""
        async with self._delivery_semaphore:
            await self._deliver_with_retry(url, event)

    async def _deliver_with_retry(
        self, url: str, event: SecurityEvent
    ) -> bool:
        """POST the event to *url* with exponential backoff retry.

        Returns ``True`` if delivery succeeded, ``False`` otherwise.
        When all retries are exhausted and a DLQ backend is configured,
        the event is enqueued for later retry.
        """
        client = await self._get_client()
        payload = self._build_payload(event)
        body = json.dumps(payload, default=str).encode("utf-8")  # raw bytes for signing
        timestamp = str(int(time.time()))

        signature = "sha256=" + hmac.new(
            self._secret_key, body, hashlib.sha256
        ).hexdigest()

        last_error: str = ""
        headers = {
            "Content-Type": "application/json",
            "X-Signature-256": signature,
            "X-Webhook-Timestamp": timestamp,
        }

        for attempt in range(self._config.retry_max + 1):
            try:
                response = await client.post(url, content=body, headers=headers)
                if response.is_success:
                    return True
                last_error = f"HTTP {response.status_code}"
                logger.warning(
                    "Webhook delivery to %s returned %d (attempt %d/%d)",
                    url,
                    response.status_code,
                    attempt + 1,
                    self._config.retry_max + 1,
                )
            except httpx.RequestError as exc:
                last_error = str(exc)
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

        # All retries exhausted — enqueue to DLQ if configured
        if self._dlq_backend is not None:
            try:
                await self._dlq_backend.enqueue(
                    event,
                    url,
                    attempt_count=self._config.retry_max + 1,
                    last_error=last_error,
                )
            except Exception:
                logger.exception(
                    "Failed to enqueue webhook event to DLQ for %s", url
                )

        return False

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
