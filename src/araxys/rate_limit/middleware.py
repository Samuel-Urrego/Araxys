"""ASGI middleware for automatic rate limiting.

Intercepts every incoming request, checks the rate limit, and injects
``X-RateLimit-*`` headers into the response. Returns ``429 Too Many Requests``
when the limit is exceeded.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from araxys.core.config import RateLimitConfig
from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.backends import RateLimitBackend
from araxys.rate_limit.limiter import RateLimiter


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware for dynamic rate limiting.

    Parameters
    ----------
    app:
        The ASGI application.
    backend:
        Rate limit storage backend.
    config:
        Rate limiting configuration.
    """

    def __init__(
        self,
        app: Any,
        backend: RateLimitBackend,
        config: RateLimitConfig,
    ) -> None:
        super().__init__(app)
        self._limiter = RateLimiter(backend=backend, config=config)

    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP, respecting reverse proxy headers."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # Take the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Skip excluded paths
        if await self._limiter.is_path_excluded(path):
            return await call_next(request)

        ip = self._get_client_ip(request)

        try:
            rate_headers = await self._limiter.check(ip, path)
        except RateLimitExceeded as exc:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests",
                    "retry_after": exc.retry_after,
                },
                headers={
                    "Retry-After": str(exc.retry_after),
                    "X-RateLimit-Limit": "0",
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # Inject rate limit headers into successful responses
        for header, value in rate_headers.items():
            response.headers[header] = str(value)

        return response
