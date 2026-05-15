"""IPAccessMiddleware — allow/block/hybrid IP access control.

Evaluates every incoming request's client IP against configurable
allowlist and/or blocklist, then either allows the request or returns
403. Emits security events for every decision.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import IPControlConfig
    from araxys.ip_access.backends import IPAccessBackend

# Module-level event bus reference — set by shield.py on init.
# This avoids circular imports on startup.
_event_bus: Any = None


class IPAccessMiddleware(BaseHTTPMiddleware):
    """IP Access Control middleware.

    Supports three modes:
    - ``allow`` (default-deny): only IPs in the allowlist pass.
    - ``block`` (default-allow): only IPs in the blocklist are denied.
    - ``hybrid``: blocklist checked first, then allowlist. IP must be
      in allowlist AND not in blocklist to pass.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        IP access control configuration.
    backend:
        Backend for rule storage (default: InMemoryIPAccessBackend
        seeded from config).
    """

    def __init__(
        self,
        app: Any,
        config: IPControlConfig,
        backend: IPAccessBackend,
    ) -> None:
        super().__init__(app)
        self._config = config
        self._backend = backend

    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP, respecting reverse proxy headers."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = self._get_client_ip(request)
        mode = self._config.mode

        if mode == "allow":
            allowed = await self._backend.is_allowed(ip)
            if not allowed:
                return await self._deny(ip, event_type=SecurityEventType.IP_BLOCKED)

        elif mode == "block":
            blocked = await self._backend.is_blocked(ip)
            if blocked:
                return await self._deny(ip, event_type=SecurityEventType.IP_BLOCKED)

        elif mode == "hybrid":
            blocked = await self._backend.is_blocked(ip)
            if blocked:
                return await self._deny(ip, event_type=SecurityEventType.IP_BLOCKED)
            allowed = await self._backend.is_allowed(ip)
            if not allowed:
                return await self._deny(ip, event_type=SecurityEventType.IP_BLOCKED)

        # If we get here, the IP is allowed
        await self._emit_event(ip, SecurityEventType.IP_ALLOWED)
        return await call_next(request)

    async def _deny(self, ip: str, *, event_type: SecurityEventType) -> Response:
        """Return a 403 response and emit a security event."""
        detail = "IP not allowed" if self._config.mode == "allow" else "IP blocked"
        await self._emit_event(ip, event_type)
        return JSONResponse(
            status_code=403,
            content={"detail": detail, "ip": ip},
        )

    async def _emit_event(
        self, ip: str, event_type: SecurityEventType
    ) -> None:
        """Emit a security event to the global event bus."""
        if _event_bus is None:
            return
        severity = (
            "warning" if event_type == SecurityEventType.IP_BLOCKED else "info"
        )
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            message=f"IP {event_type.value}: {ip}",
            timestamp=datetime.now(UTC),
            source_ip=ip,
            metadata={"mode": self._config.mode},
        )
        await _event_bus.emit(event)
