"""TelemetryMiddleware — optional Starlette middleware for HTTP tracing.

Creates an ``http.request`` span for every incoming request when the
module is enabled. Graceful no-op when disabled.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from araxys.core.ip import get_client_ip

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from araxys.core.config import TelemetryConfig
    from araxys.telemetry.tracer import AraxysTracer


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Optional middleware that wraps every HTTP request in an OTEL span.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Telemetry configuration — if ``enabled=False``, the middleware
        passes through without creating spans.
    tracer:
        An ``AraxysTracer`` instance. If ``None``, a default one is
        created from config.
    trusted_proxies:
        Optional list of IPs/CIDRs of trusted reverse proxies.
    """

    def __init__(
        self,
        app: Any,
        config: TelemetryConfig,
        tracer: AraxysTracer | None = None,
        trusted_proxies: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._config = config
        from araxys.telemetry.tracer import AraxysTracer

        self._tracer = tracer or AraxysTracer(config)
        self._trusted_proxies = trusted_proxies or []

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self._config.enabled:
            return await call_next(request)

        client_ip = get_client_ip(request, trusted_proxies=self._trusted_proxies)

        async with self._tracer.span(
            "http.request",
            attributes={
                "http.method": request.method,
                "http.path": request.url.path,
                "client.ip": client_ip,
            },
        ) as span:
            response = await call_next(request)
            span.set_attribute("http.status_code", response.status_code)
            return response
