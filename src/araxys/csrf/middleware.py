"""CSRFMiddleware — automatic CSRF protection for state-changing methods.

Intercepts PUT/POST/DELETE/PATCH requests and validates the double-submit
cookie pattern via ``CSRFHandler``.  Safe methods (GET/HEAD/OPTIONS/TRACE)
and excluded paths pass through without validation.

Follows the same pattern as ``IPAccessMiddleware``: ``BaseHTTPMiddleware``,
module-level ``_event_bus``, ``JSONResponse`` for errors.
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import CSRFConfig
    from araxys.csrf.tokens import CSRFHandler

# Module-level event bus reference — set by shield.py on init.
# This avoids circular imports on startup.
_event_bus: Any = None


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware using the double-submit cookie pattern.

    Automatically validates ``X-CSRF-Token`` header against the ``csrf_token``
    cookie for all state-changing HTTP methods (PUT/POST/DELETE/PATCH).
    Safe methods and excluded paths pass without validation.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        CSRF configuration (safe methods, exclude paths, cookie attrs).
    handler:
        The CSRF handler for token generation and validation.
    """

    def __init__(
        self,
        app: Any,
        config: CSRFConfig,
        handler: CSRFHandler,
    ) -> None:
        super().__init__(app)
        self._config = config
        self._handler = handler

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # 1. Safe methods pass through without validation
        if request.method in self._config.safe_methods:
            return await call_next(request)

        # 2. Excluded paths pass through
        path = request.url.path
        for pattern in self._config.exclude_paths:
            if fnmatch.fnmatch(path, pattern):
                return await call_next(request)

        # 3. Extract tokens
        header_token = request.headers.get(self._config.header_name)
        cookie_token = request.cookies.get(self._config.cookie_name)

        # 4. Validate
        if not header_token or not cookie_token:
            return await self._deny(
                request=request,
                detail="CSRF token missing",
            )

        if not self._handler.validate_token(header_token, cookie_token):
            return await self._deny(
                request=request,
                detail="CSRF token mismatch",
            )

        # 5. Success — pass through
        response = await call_next(request)

        # 6. Auto-refresh cookie on response
        if self._config.auto_refresh_cookie:
            new_token = self._handler.generate_token(
                expiry_seconds=self._config.token_expiry_seconds,
            )
            cookie_value = self._handler.create_cookie(new_token, self._config)
            response.headers.append("Set-Cookie", cookie_value)

        return response

    async def _deny(
        self,
        request: Request,
        *,
        detail: str,
    ) -> Response:
        """Return a 403 response and emit a security event."""
        await self._emit_event(request, detail=detail)
        return JSONResponse(
            status_code=403,
            content={
                "error": "CSRF validation failed",
                "detail": detail,
            },
        )

    async def _emit_event(
        self,
        request: Request,
        *,
        detail: str,
    ) -> None:
        """Emit a security event to the global event bus."""
        if _event_bus is None:
            return
        ip = request.client.host if request.client else "unknown"
        event = SecurityEvent(
            event_type=SecurityEventType.CSRF_VALIDATION_FAILED,
            severity="warning",
            message=f"CSRF validation failed: {detail}",
            timestamp=datetime.now(UTC),
            source_ip=ip,
            metadata={
                "source_ip": ip,
                "path": str(request.url.path),
                "detail": detail,
            },
        )
        await _event_bus.emit(event)
