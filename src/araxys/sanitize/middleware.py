"""ASGI middleware for automatic request payload sanitization.

Intercepts requests, scans headers and query parameters for injection
patterns (NoSQL, command injection, path traversal), and sanitizes
request bodies (JSON, form-urlencoded, and multipart form-data) for
SQL injection and XSS.
"""


from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.exceptions import SanitizationError
from araxys.sanitize.filters import sanitize_payload
from araxys.sanitize.scanner import scan_headers, scan_query_params, scan_value

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

    @staticmethod
    def _scan_body_leaves(
        data: Any, config: SanitizeConfig
    ) -> str | None:
        """Recursively walk *data* leaf strings and run *scan_value* on each.

        Returns the first threat description found, or ``None``.
        """
        if isinstance(data, str):
            return scan_value(data, config)

        if isinstance(data, dict):
            for value in data.values():
                threat = SanitizeMiddleware._scan_body_leaves(value, config)
                if threat is not None:
                    return threat

        if isinstance(data, list):
            for item in data:
                threat = SanitizeMiddleware._scan_body_leaves(item, config)
                if threat is not None:
                    return threat

        # int, float, bool, None — skip
        return None

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

        # Body size limit — check Content-Length before reading body
        content_length_header = request.headers.get("content-length")
        if content_length_header is not None:
            try:
                if int(content_length_header) > self._config.max_body_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            except (ValueError, TypeError):
                pass  # Malformed Content-Length header — let body reading handle

        # Only process known content types
        content_type = request.headers.get("content-type", "")
        is_json = "application/json" in content_type
        is_form = "application/x-www-form-urlencoded" in content_type
        is_multipart = "multipart/form-data" in content_type

        if not (is_json or is_form or is_multipart):
            return await call_next(request)

        # Read body
        body = await request.body()

        # Fallback body size check
        if content_length_header is None and len(body) > self._config.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        if not body:
            return await call_next(request)

        if is_json:
            return await self._process_json_body(request, body, call_next)
        elif is_form:
            return await self._process_form_body(request, body, call_next)
        else:
            return await self._process_multipart_body(request, call_next)

    async def _process_json_body(
        self, request: Request, body: bytes, call_next: RequestResponseEndpoint
    ) -> Response:
        """Sanitize an ``application/json`` body."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
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

        # Scan leaf strings
        if self._scanning_enabled:
            threat = self._scan_body_leaves(sanitized, self._config)
            if threat is not None:
                return self._block_response(threat)

        sanitized_bytes = json.dumps(sanitized).encode()
        request.state._araxys_sanitized_body = sanitized_bytes
        request._body = sanitized_bytes
        return await call_next(request)

    async def _process_form_body(
        self, request: Request, body: bytes, call_next: RequestResponseEndpoint
    ) -> Response:
        """Sanitize an ``application/x-www-form-urlencoded`` body."""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return await call_next(request)

        parsed = parse_qs(text, keep_blank_values=True)

        if self._scanning_enabled:
            for key, values in parsed.items():
                threat = scan_value(key, self._config)
                if threat:
                    return self._block_response(threat)
                for value in values:
                    threat = scan_value(value, self._config)
                    if threat:
                        return self._block_response(threat)

        # XSS strip and SQLi-aware sanitize on form values
        if self._config.strip_xss or self._config.block_sqli:
            sanitized: dict[str, list[str]] = {}
            for key, values in parsed.items():
                sanitized_values: list[str] = []
                for value in values:
                    try:
                        s = sanitize_payload(
                            value,
                            block_sqli=self._config.block_sqli,
                            strip_xss_content=self._config.strip_xss,
                            max_depth=1,
                        )
                        sanitized_values.append(s if isinstance(s, str) else str(s))
                    except SanitizationError as exc:
                        return JSONResponse(
                            status_code=400,
                            content={
                                "detail": "Request blocked — malicious content detected",
                                "threat_type": exc.threat_type,
                            },
                        )
                sanitized[key] = sanitized_values
        else:
            sanitized = parsed

        sanitized_bytes = urlencode(sanitized, doseq=True).encode("utf-8")
        request.state._araxys_sanitized_body = sanitized_bytes
        request._body = sanitized_bytes
        return await call_next(request)

    async def _process_multipart_body(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Sanitize text fields in a ``multipart/form-data`` body.

        File uploads are passed through untouched — only text form
        fields are scanned.
        """
        try:
            form = await request.form()
        except Exception:
            return await call_next(request)

        if not self._scanning_enabled and not self._config.strip_xss and not self._config.block_sqli:
            return await call_next(request)

        from starlette.datastructures import UploadFile

        sanitized_form: dict[str, Any] = {}
        for field_name, field_value in form.multi_items():
            if isinstance(field_value, UploadFile):
                sanitized_form[field_name] = field_value
                continue
            # It's a text form field
            str_value = str(field_value)
            if self._scanning_enabled:
                threat = scan_value(str_value, self._config)
                if threat:
                    return self._block_response(threat)
            try:
                s = sanitize_payload(
                    str_value,
                    block_sqli=self._config.block_sqli,
                    strip_xss_content=self._config.strip_xss,
                    max_depth=1,
                )
                sanitized_form[field_name] = s if isinstance(s, str) else str(s)
            except SanitizationError as exc:
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": "Request blocked — malicious content detected",
                        "threat_type": exc.threat_type,
                    },
                )

        # Store sanitized form data on request state
        request.state._araxys_sanitized_form = sanitized_form
        return await call_next(request)

    @property
    def _scanning_enabled(self) -> bool:
        """True when any leaf-scanning detector is enabled."""
        return any((
            self._config.check_nosql_injection,
            self._config.check_command_injection,
            self._config.check_path_traversal,
        ))
