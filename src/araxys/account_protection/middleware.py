"""Timing normalisation, error masking and enumeration detection middleware."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import random
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.account_protection.detection import EnumerationDetector
from araxys.core.ip import get_client_ip
from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from starlette.requests import Request

    from araxys.core.config import AccountProtectionConfig

logger = logging.getLogger("araxys.account_protection")

# Module-level event bus reference, set by AraxysShield when webhooks
# are enabled. Used to emit SecurityEvent objects for enumeration
# detection, consumed by the event bus for webhook/metrics delivery.
_event_bus: Any | None = None


class AccountProtectionMiddleware(BaseHTTPMiddleware):
    """Normalizes auth response timing and error messages.

    Protects against account enumeration by:
    * Masking 401/403 response details with a generic message.
    * Adding configurable jitter and a minimum time floor to auth
      endpoint responses.
    * Tracking failure patterns per IP to detect enumeration activity.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Account protection configuration.
    on_audit:
        Optional async callback for security event emission. Called
        when the enumeration detection threshold is exceeded.
    """

    def __init__(
        self,
        app: Any,
        config: AccountProtectionConfig,
        on_audit: Callable[[SecurityEvent], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        super().__init__(app)
        self._config = config
        self._on_audit = on_audit
        self._detector = (
            EnumerationDetector.from_config(config)
            if config.enabled
            else None
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # When disabled or path is not protected, pass through with no overhead
        if not self._config.enabled or not self._is_protected_path(
            request.url.path
        ):
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)

        # 1. Normalize error messages for 401/403
        if response.status_code in (401, 403):
            response = await self._normalize_error(response)

        # 2. Track 401 failures for enumeration detection
        if self._detector and response.status_code == 401:
            await self._track_enumeration(request)

        # 3. Timing normalization — jitter + minimum floor
        elapsed_ms = (time.monotonic() - start) * 1000
        await self._apply_timing_padding(elapsed_ms)

        return response

    def _is_protected_path(self, path: str) -> bool:
        """Check if a path matches any of the protected path patterns.

        Uses ``fnmatch`` for glob-style pattern matching so that
        patterns like ``/auth/*`` match ``/auth/login``.
        """
        for pattern in self._config.enumeration_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    async def _normalize_error(self, response: Response) -> Response:
        """Replace the response body's ``detail`` with the generic message.

        Reads the body via ``body_iterator`` (the only way to access the
        body of a ``_StreamingResponse`` returned by ``BaseHTTPMiddleware``).
        """
        # _StreamingResponse from BaseHTTPMiddleware has body_iterator
        # but it is not in the Response type stubs.
        chunks: list[bytes] = []
        async for chunk in response.body_iterator:  # type: ignore[attr-defined]
            chunks.append(chunk)
        body_bytes = b"".join(chunks)

        try:
            parsed = json.loads(body_bytes)
        except (json.JSONDecodeError, ValueError, TypeError):
            return response

        parsed["detail"] = self._config.generic_unauthorized_message
        return JSONResponse(
            content=parsed,
            status_code=response.status_code,
            headers=dict(response.headers),
        )

    async def _track_enumeration(self, request: Request) -> None:
        """Record a 401 failure and emit an event if threshold exceeded."""
        identifier = request.url.path
        ip = get_client_ip(request)

        assert self._detector is not None  # checked before calling
        detected = await self._detector.record_failure(identifier, ip)

        if detected and self._on_audit is not None:
            await self._emit_enumeration_event(ip, identifier)

    async def _apply_timing_padding(self, elapsed_ms: float) -> None:
        """Add jitter and pad response to the minimum time floor."""
        target = self._config.minimum_response_time_ms
        jitter = random.uniform(
            -self._config.timing_jitter_ms,
            self._config.timing_jitter_ms,
        )
        delay = max(0.0, target - elapsed_ms + jitter)
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)

    async def _emit_enumeration_event(
        self, ip: str, identifier: str
    ) -> None:
        """Build and dispatch a security event for enumeration detection."""
        event = SecurityEvent(
            event_type=SecurityEventType.ACCOUNT_ENUMERATION_DETECTED,
            severity="warning",
            message=f"Enumeration detected from {ip} targeting {identifier}",
            timestamp=datetime.now(UTC),
            source_ip=ip,
            metadata={
                "identifier": identifier,
                "threshold": self._config.enumeration_threshold,
                "window_seconds": self._config.enumeration_window_seconds,
            },
        )
        # Emit to audit callback (used for audit log)
        if self._on_audit is not None:
            await self._on_audit(event)
        # Emit to shared event bus (used for webhooks / metrics)
        global _event_bus
        if _event_bus is not None:
            await _event_bus.emit(event)
