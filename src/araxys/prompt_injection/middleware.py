"""Read-only ASGI middleware for prompt injection detection.

Intercepts requests, scans query parameters and request body fields
(JSON, form data, multipart) for prompt injection patterns, and returns
a 400 response when a threat is detected — **without mutating** the
request body so downstream handlers receive the original payload.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.prompt_injection.scanner import PromptInjectionScanner

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import PromptInjectionConfig


class PromptInjectionMiddleware(BaseHTTPMiddleware):
    """Read-only ASGI middleware that scans requests for prompt injection.

    Scanning phases:

    1. **Excluded paths** — skip paths listed in ``exclude_paths``.
    2. **Query parameters** — scan each query param name and value.
    3. **JSON body** — recursively scan all string leaf values.
    4. **Form body** — scan ``application/x-www-form-urlencoded`` fields.
    5. **Multipart** — scan text form fields and upload filenames.

    On detection the middleware returns a 400 JSON response **without**
    forwarding the request to the downstream application.  The body is
    **not modified** — this is a read-only scan.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Prompt injection configuration.
    """

    METHODS_WITH_BODY = {"POST", "PUT", "PATCH", "DELETE"}

    def __init__(self, app: Any, config: PromptInjectionConfig) -> None:  # noqa: ANN401
        super().__init__(app)
        self._config = config
        self._scanner = PromptInjectionScanner(config)
        self._exclude_paths = frozenset(config.exclude_paths)
        self._exclude_content_types = frozenset(
            ct.lower() for ct in config.exclude_content_types
        )

    # ── Dispatch ───────────────────────────────────────────────────────────

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Phase 0 — skip excluded paths
        if request.url.path in self._exclude_paths:
            return await call_next(request)

        # Phase 1 — scan query params (all methods)
        threat = self._scan_query_params(request)
        if threat is not None:
            return self._block_response(*threat)

        # Skip body scanning for methods without a body
        if request.method not in self.METHODS_WITH_BODY:
            return await call_next(request)

        # Phase 2 — check content-type exclusion
        raw_ct = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if raw_ct in self._exclude_content_types:
            return await call_next(request)

        # Read body (caches for downstream)
        body = await request.body()
        if not body:
            return await call_next(request)

        # Phase 3 — route by content type
        if raw_ct == "application/json":
            return await self._scan_json_body(request, body, call_next)
        elif raw_ct == "application/x-www-form-urlencoded":
            return await self._scan_form_body(request, body, call_next)
        elif raw_ct == "multipart/form-data":
            return await self._scan_multipart_body(request, call_next)
        else:
            return await call_next(request)

    # ── Query param scanning ───────────────────────────────────────────────

    def _scan_query_params(self, request: Request) -> tuple[str, str] | None:
        """Scan all query parameter names and values.

        Returns ``(detector_name, matched_pattern)`` or ``None``.
        """
        for key, value in request.query_params.multi_items():
            for candidate in (key, value):
                result = self._scanner.scan_text(candidate)
                if result.is_threat:
                    detector = (
                        result.detectors_triggered[0]
                        if result.detectors_triggered
                        else "unknown"
                    )
                    return (detector, result.matched_pattern or candidate)
        return None

    # ── JSON body scanning ─────────────────────────────────────────────────

    async def _scan_json_body(
        self, request: Request, body: bytes, call_next: RequestResponseEndpoint
    ) -> Response:
        """Scan an ``application/json`` body."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return await call_next(request)

        threat = self._scan_data_leaves(data)
        if threat is not None:
            return self._block_response(*threat)

        return await call_next(request)

    def _scan_data_leaves(self, data: Any) -> tuple[str, str] | None:  # noqa: ANN401
        """Recursively walk *data* string leaves and scan each.

        Returns ``(detector_name, matched_pattern)`` or ``None``.
        """
        if isinstance(data, str):
            result = self._scanner.scan_text(data)
            if result.is_threat:
                detector = (
                    result.detectors_triggered[0]
                    if result.detectors_triggered
                    else "unknown"
                )
                return (detector, result.matched_pattern or data)
            return None

        if isinstance(data, dict):
            for value in data.values():
                threat = self._scan_data_leaves(value)
                if threat is not None:
                    return threat

        if isinstance(data, list):
            for item in data:
                threat = self._scan_data_leaves(item)
                if threat is not None:
                    return threat

        return None

    # ── Form body scanning ─────────────────────────────────────────────────

    async def _scan_form_body(
        self, request: Request, body: bytes, call_next: RequestResponseEndpoint
    ) -> Response:
        """Scan an ``application/x-www-form-urlencoded`` body."""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return await call_next(request)

        parsed = parse_qs(text, keep_blank_values=True)

        for key, values in parsed.items():
            for candidate in (key, *values):
                result = self._scanner.scan_text(candidate)
                if result.is_threat:
                    detector = (
                        result.detectors_triggered[0]
                        if result.detectors_triggered
                        else "unknown"
                    )
                    return self._block_response(
                        detector, result.matched_pattern or candidate
                    )

        return await call_next(request)

    # ── Multipart body scanning ────────────────────────────────────────────

    async def _scan_multipart_body(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Scan text fields and upload filenames in a multipart body."""
        try:
            form = await request.form()
        except Exception:
            return await call_next(request)

        from starlette.datastructures import UploadFile

        for _field_name, field_value in form.multi_items():
            if isinstance(field_value, UploadFile):
                # Scan filename
                if field_value.filename:
                    result = self._scanner.scan_text(field_value.filename)
                    if result.is_threat:
                        detector = (
                            result.detectors_triggered[0]
                            if result.detectors_triggered
                            else "unknown"
                        )
                        return self._block_response(
                            detector,
                            result.matched_pattern or field_value.filename,
                        )
                continue

            # Text form field
            str_value = str(field_value)
            result = self._scanner.scan_text(str_value)
            if result.is_threat:
                detector = (
                    result.detectors_triggered[0]
                    if result.detectors_triggered
                    else "unknown"
                )
                return self._block_response(
                    detector, result.matched_pattern or str_value
                )

        return await call_next(request)

    # ── Response helpers ───────────────────────────────────────────────────

    def _block_response(
        self, detector_name: str, matched_pattern: str | None
    ) -> JSONResponse:
        """Return a 400 JSON rejection response."""
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Prompt injection detected",
                "detector_name": detector_name,
                "matched_pattern": matched_pattern,
            },
        )
