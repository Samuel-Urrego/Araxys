"""Secure HTTP headers middleware.

Automatically injects security headers into every response following
OWASP recommendations.
"""


from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from araxys.headers.csp import build_csp_header

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from araxys.core.config import PermissionsPolicyConfig, SecureHeadersConfig


def _build_permissions_policy(config: PermissionsPolicyConfig) -> str:
    """Build a ``Permissions-Policy`` header from structured config.

    Each directive with a non-``None`` value becomes a directive in
    the header: ``camera=(), microphone=self``, etc.
    """
    directives: list[str] = []
    for field_name in config.model_fields:
        value = getattr(config, field_name)
        if value is None:
            continue
        # Convert snake_case field name to kebab-case directive name
        directive = field_name.replace("_", "-")
        if value == "none":
            directives.append(f"{directive}=()")
        elif value == "*":
            directives.append(f"{directive}=*")
        else:
            directives.append(f"{directive}={value}")
    return ", ".join(directives)


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Injects security headers into all HTTP responses.

    Headers injected (when enabled):
    - ``Strict-Transport-Security`` — HSTS
    - ``X-Content-Type-Options: nosniff``
    - ``X-Frame-Options`` — clickjacking protection
    - ``Referrer-Policy``
    - ``Content-Security-Policy`` (if configured, via raw string or structured
      ``csp_directives``)
    - ``Permissions-Policy`` (if configured)
    - ``Cross-Origin-Opener-Policy`` (COOP, if configured)
    - ``Cross-Origin-Embedder-Policy`` (COEP, if configured)
    - ``Cross-Origin-Resource-Policy`` (CORP, if configured)
    - ``X-XSS-Protection: 0`` — disabled per modern best practice
    - ``Server`` header stripping (if ``hide_server`` is ``True``)

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
        self._hide_server = config.hide_server

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

        # CSP — structured directives take precedence over raw string
        if config.csp_directives is not None:
            headers["Content-Security-Policy"] = build_csp_header(
                config.csp_directives
            )
        elif config.content_security_policy:
            headers["Content-Security-Policy"] = config.content_security_policy

        # Permissions Policy — structured directives take precedence over raw
        if config.permissions_policy_directives is not None:
            headers["Permissions-Policy"] = _build_permissions_policy(
                config.permissions_policy_directives
            )
        elif config.permissions_policy:
            headers["Permissions-Policy"] = config.permissions_policy

        # Cross-Origin-Opener-Policy (COOP)
        if config.coop is not None:
            headers["Cross-Origin-Opener-Policy"] = config.coop

        # Cross-Origin-Embedder-Policy (COEP)
        if config.coep is not None:
            headers["Cross-Origin-Embedder-Policy"] = config.coep

        # Cross-Origin-Resource-Policy (CORP)
        if config.corp is not None:
            headers["Cross-Origin-Resource-Policy"] = config.corp

        return headers

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        for header, value in self._headers.items():
            response.headers[header] = value

        # Strip the Server header when configured
        if self._hide_server:
            with suppress(KeyError):
                del response.headers["server"]

        return response
