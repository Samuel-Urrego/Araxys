"""Honeypot IP-ban enforcement middleware.

Checks every incoming request against the ban list maintained by
the honeypot traps. Banned IPs receive a 403 on ALL endpoints.
"""


from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.ip import get_client_ip

if TYPE_CHECKING:
    from starlette.requests import Request

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
    trusted_proxies:
        Optional list of IPs/CIDRs of trusted reverse proxies.
    """

    def __init__(
        self,
        app: Any,
        backend: RateLimitBackend,
        trusted_proxies: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._backend = backend
        self._trusted_proxies = trusted_proxies or []

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = get_client_ip(request, trusted_proxies=self._trusted_proxies)

        if await self._backend.is_banned(ip):
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
            )

        return await call_next(request)
