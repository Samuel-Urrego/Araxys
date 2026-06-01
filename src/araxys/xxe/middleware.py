"""Read-only ASGI middleware for XXE (XML External Entity) attack detection.

Intercepts XML content types, reads the request body, scans it using
:class:`XXEScanner`, and returns a 400 JSON response when a threat
is detected — **without mutating** the request body so downstream
handlers receive the original payload.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.xxe.scanner import XXEScanner

if TYPE_CHECKING:
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.requests import Request

    from araxys.xxe.config import XXEConfig

# ── Audit event bus (set from shield) ─────────────────────────────────────────

_event_bus: Any = None

# ── XML content-type set ──────────────────────────────────────────────────────

_XML_CONTENT_TYPES: frozenset[str] = frozenset({
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "image/svg+xml",
})


class XXEMiddleware(BaseHTTPMiddleware):
    """Read-only ASGI middleware that scans XML bodies for XXE attacks.

    Scanning phases:

    1. **Excluded paths** — skip paths listed in ``exclude_paths``.
    2. **Content-type guard** — check for XML content types
       (exact set match + ``+xml`` suffix matching).
    3. **Excluded content types** — skip excluded content types.
    4. **Body scanning** — read body via ``request.body()``, scan with
       :class:`XXEScanner`, return 400 on threat.
    5. **Audit emission** — emit ``SecurityEvent`` via module-level
       ``_event_bus`` when a threat is detected.

    On detection the middleware returns a 400 JSON response **without**
    forwarding the request to the downstream application.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        XXE detection configuration.
    """

    def __init__(self, app: Any, config: XXEConfig) -> None:  # noqa: ANN401
        super().__init__(app)
        self._config = config
        self._scanner = XXEScanner(config)
        self._exclude_paths = frozenset(config.exclude_paths)
        self._exclude_content_types = frozenset(
            ct.lower() for ct in config.exclude_content_types
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Phase 0 — skip excluded paths
        if request.url.path in self._exclude_paths:
            return await call_next(request)

        # Phase 1 — content-type guard (XML types only)
        raw_ct = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if not self._is_xml_content_type(raw_ct):
            return await call_next(request)

        # Phase 2 — check excluded content types
        if raw_ct in self._exclude_content_types:
            return await call_next(request)

        # Phase 3 — read body and scan
        body = await request.body()
        if not body:
            return await call_next(request)

        result = self._scanner.scan(body)

        if not result.is_threat:
            return await call_next(request)

        # Phase 4 — threat detected: build response + emit audit
        threats = result.metadata.get("xxe_threats", [{}])
        threat = threats[0] if threats else {}
        detection_type = threat.get("detection_type", "unknown")
        detail = threat.get("detail", result.matched_pattern or "XXE detected")

        # Emit audit event via module-level event bus
        await self._emit_audit_event(
            detection_type=detection_type,
            detail=detail,
            source_ip=request.client.host if request.client else None,
        )

        return JSONResponse(
            status_code=400,
            content={
                "error": "XXEDetected",
                "detail": detail,
                "detection_type": detection_type,
            },
        )

    # ── Internals ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_xml_content_type(raw_ct: str) -> bool:
        """Check if *raw_ct* is an XML content type.

        Matches against the explicit set of XML types and any content
        type ending with ``+xml``.
        """
        if raw_ct in _XML_CONTENT_TYPES:
            return True
        return raw_ct.endswith("+xml")

    async def _emit_audit_event(
        self,
        detection_type: str,
        detail: str,
        source_ip: str | None,
    ) -> None:
        """Emit a ``SecurityEvent`` to the module-level event bus."""
        # Local import to avoid circular dependency at module level

        if _event_bus is None:
            return

        event = SecurityEvent(
            event_type=SecurityEventType.XXE_DETECTED,
            severity="warning",
            message=f"XXE detected: {detection_type} — {detail}",
            source_ip=source_ip,
            metadata={
                "detection_type": detection_type,
                "detail": detail,
                "module": "xxe",
            },
        )
        await _event_bus.emit(event)
