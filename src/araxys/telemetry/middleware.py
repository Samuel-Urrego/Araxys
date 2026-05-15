"""TelemetryMiddleware — optional Starlette middleware for HTTP tracing.

Creates an ``http.request`` span for every incoming request when the
module is enabled. Graceful no-op when disabled.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

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
    """

    def __init__(
        self,
        app: Any,
        config: TelemetryConfig,
        tracer: AraxysTracer | None = None,
    ) -> None:
        super().__init__(app)
        self._config = config
        from araxys.telemetry.tracer import AraxysTracer

        self._tracer = tracer or AraxysTracer(config)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if not self._config.enabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

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
