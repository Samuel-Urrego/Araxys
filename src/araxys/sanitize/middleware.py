"""ASGI middleware for automatic request payload sanitization.

Intercepts POST/PUT/PATCH requests with JSON bodies, scans them
for SQL injection and XSS, and either blocks or cleans the payload
before it reaches the route handler.
"""


from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.exceptions import SanitizationError
from araxys.sanitize.filters import sanitize_payload

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import SanitizeConfig


class SanitizeMiddleware(BaseHTTPMiddleware):
    """Middleware that sanitizes JSON request bodies.

    Only processes requests with ``Content-Type: application/json``
    and methods that typically carry a body (POST, PUT, PATCH).

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Sanitization configuration.
    """

    METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}

    def __init__(self, app: Any, config: SanitizeConfig) -> None:
        super().__init__(app)
        self._config = config

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip methods without body
        if request.method not in self.METHODS_WITH_BODY:
            return await call_next(request)

        # Skip excluded paths
        if request.url.path in self._config.exclude_paths:
            return await call_next(request)

        # Only process JSON content
        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return await call_next(request)

        # Read and parse body
        body = await request.body()
        if not body:
            return await call_next(request)

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not valid JSON — let the framework handle the error
            return await call_next(request)

        try:
            sanitized = sanitize_payload(
                data,
                block_sqli=self._config.block_sqli,
                strip_xss_content=self._config.strip_xss,
                max_depth=self._config.max_depth,
            )
        except SanitizationError as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Request blocked — malicious content detected",
                    "threat_type": exc.threat_type,
                },
            )

        # Replace the request body with the sanitized version
        sanitized_body = json.dumps(sanitized).encode()

        # Create a new scope with the updated body
        # We use request.state to pass the sanitized body
        request.state._araxys_sanitized_body = sanitized_body
        request._body = sanitized_body

        return await call_next(request)
