"""ASGI middleware for automatic request payload sanitization.

Intercepts requests, scans headers and query parameters for injection
patterns (NoSQL, command injection, path traversal), and sanitizes
JSON request bodies for SQL injection and XSS.
"""


from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.exceptions import SanitizationError
from araxys.sanitize.filters import sanitize_payload
from araxys.sanitize.scanner import scan_headers, scan_query_params

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import SanitizeConfig


class SanitizeMiddleware(BaseHTTPMiddleware):
    """Middleware that sanitizes HTTP requests.

    Scanning phases (all methods):
    1. Header scanning — when ``scan_headers`` is enabled
    2. Query param scanning — when ``scan_query_params`` is enabled

    Body sanitization (POST/PUT/PATCH only with JSON):
    3. JSON body sanitization — SQLi blocking and XSS stripping

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

    def _block_response(self, threat_type: str) -> JSONResponse:
        """Create a 400 rejection response."""
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Request blocked — malicious content detected",
                "threat_type": threat_type,
            },
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Phase 1 — Header scanning (all methods)
        if self._config.scan_headers:
            threat = scan_headers(request, self._config)
            if threat is not None:
                return self._block_response(threat)

        # Phase 2 — Query param scanning (all methods)
        if self._config.scan_query_params:
            threat = scan_query_params(request, self._config)
            if threat is not None:
                return self._block_response(threat)

        # Skip methods without body for body sanitization
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
