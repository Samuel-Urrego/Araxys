"""Honeypot IP-ban enforcement middleware.

Checks every incoming request against the ban list maintained by
the honeypot traps. Banned IPs receive a 403 on ALL endpoints.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from araxys.rate_limit.backends import RateLimitBackend


class HoneypotMiddleware(BaseHTTPMiddleware):
    """Blocks requests from IPs banned by the honeypot system.

    This middleware sits high in the stack and rejects banned IPs
    before they reach any real endpoint.

    Parameters
    ----------
    app:
        The ASGI application.
    backend:
        Shared rate-limit backend that stores ban state.
    """

    def __init__(self, app: Any, backend: RateLimitBackend) -> None:
        super().__init__(app)
        self._backend = backend

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = self._get_client_ip(request)

        if await self._backend.is_banned(ip):
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
            )

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"
