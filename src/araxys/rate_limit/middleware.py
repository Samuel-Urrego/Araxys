"""ASGI middleware for automatic rate limiting.

Intercepts every incoming request, checks the rate limit, and injects
``X-RateLimit-*`` headers into the response. Returns ``429 Too Many Requests``
when the limit is exceeded.
"""


from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.identity import extract_api_key, extract_user_id
from araxys.rate_limit.limiter import RateLimiter

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import RateLimitConfig
    from araxys.rate_limit.backends import RateLimitBackend


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
        self._config = config

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

        # Extract identity when per-user or per-key tracking is enabled
        # (graceful fallback to None if headers are missing)
        user_id: str | None = None
        api_key: str | None = None
        if self._config.per_user:
            user_id = extract_user_id(request)
        if self._config.per_api_key:
            api_key = extract_api_key(request)

        try:
            rate_headers = await self._limiter.check(
                ip, path, user_id=user_id, api_key=api_key
            )
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
