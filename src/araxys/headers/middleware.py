"""Secure HTTP headers middleware.

Automatically injects security headers into every response following
OWASP recommendations.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from araxys.core.config import SecureHeadersConfig


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers into all HTTP responses.

    Headers injected (when enabled):
    - ``Strict-Transport-Security`` — HSTS
    - ``X-Content-Type-Options: nosniff``
    - ``X-Frame-Options`` — clickjacking protection
    - ``Referrer-Policy``
    - ``Content-Security-Policy`` (if configured)
    - ``Permissions-Policy`` (if configured)
    - ``X-XSS-Protection: 0`` — disabled per modern best practice

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Secure headers configuration.
    """

    def __init__(self, app: Any, config: SecureHeadersConfig) -> None:
        super().__init__(app)
        self._headers = self._build_headers(config)

    @staticmethod
    def _build_headers(config: SecureHeadersConfig) -> dict[str, str]:
        """Pre-build the header dict from config (computed once at startup)."""
        headers: dict[str, str] = {}

        # HSTS
        hsts = f"max-age={config.hsts_max_age}"
        if config.hsts_include_subdomains:
            hsts += "; includeSubDomains"
        headers["Strict-Transport-Security"] = hsts

        # Content-Type sniffing
        if config.content_type_nosniff:
            headers["X-Content-Type-Options"] = "nosniff"

        # Clickjacking
        headers["X-Frame-Options"] = config.frame_options

        # XSS Protection — disabled per modern recommendation
        # Modern browsers use CSP instead; the old filter can introduce XSS
        headers["X-XSS-Protection"] = "0"

        # Referrer
        headers["Referrer-Policy"] = config.referrer_policy

        # CSP
        if config.content_security_policy:
            headers["Content-Security-Policy"] = config.content_security_policy

        # Permissions Policy
        if config.permissions_policy:
            headers["Permissions-Policy"] = config.permissions_policy

        return headers

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        for header, value in self._headers.items():
            response.headers[header] = value

        return response
