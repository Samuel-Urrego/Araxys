"""ASGI middleware for automatic rate limiting.

Intercepts every incoming request, checks the rate limit, and injects
``X-RateLimit-*`` headers into the response. Returns ``429 Too Many Requests``
when the limit is exceeded.
"""


from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.exceptions import RateLimitExceeded
from araxys.core.ip import get_client_ip
from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.rate_limit.identity import extract_api_key, extract_user_id
from araxys.rate_limit.limiter import RateLimiter

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import RateLimitConfig
    from araxys.rate_limit.backends import RateLimitBackend

# Module-level event bus reference — set by shield.py on init.
_event_bus: Any = None


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
    trusted_proxies:
        Optional list of IPs/CIDRs of trusted reverse proxies.
    """

    def __init__(
        self,
        app: Any,
        backend: RateLimitBackend,
        config: RateLimitConfig,
        trusted_proxies: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._limiter = RateLimiter(backend=backend, config=config)
        self._config = config
        self._trusted_proxies = trusted_proxies or []

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # Skip excluded paths
        if await self._limiter.is_path_excluded(path):
            return await call_next(request)

        ip = get_client_ip(request, trusted_proxies=self._trusted_proxies)

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
            if _event_bus is not None:
                await _event_bus.emit(
                    SecurityEvent(
                        event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                        severity="warning",
                        message=f"Rate limit exceeded: {ip} on {path}",
                        timestamp=datetime.now(UTC),
                        source_ip=ip,
                        metadata={
                            "path": request.url.path,
                            "method": request.method,
                            "retry_after": exc.retry_after,
                        },
                    )
                )
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

