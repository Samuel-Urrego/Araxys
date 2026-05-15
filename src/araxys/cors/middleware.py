"""CORSMiddleware — origin matching, preflight handling, header injection.

Fail-closed by default: no configured origins means all cross-origin
requests are denied.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import CORSConfig


class CORSMiddleware(BaseHTTPMiddleware):
    """CORS policy enforcement middleware.

    Sits in the outermost shield position. Intercepts every request,
    checks the Origin header against the configured allowlist, and
    injects ``Access-Control-*`` headers into the response.

    Parameters
    ----------
    app:
        The ASGI application.
    cors_config:
        CORS policy configuration.
    """

    def __init__(self, app: Any, cors_config: CORSConfig) -> None:
        super().__init__(app)
        self._config = cors_config

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        origin = request.headers.get("origin")

        # No Origin header → same-origin request, pass through
        if origin is None:
            return await call_next(request)

        # Match origin against allowlist
        matched_origin = self._match_origin(origin)
        if matched_origin is None:
            return JSONResponse(
                status_code=400,
                content={"detail": "Origin not allowed"},
            )

        # Preflight request
        if request.method == "OPTIONS":
            return self._build_preflight_response(matched_origin)

        # Normal request
        response = await call_next(request)
        self._inject_cors_headers(response, matched_origin)
        return response

    def _match_origin(self, origin: str) -> str | None:
        """Check if *origin* is allowed.

        Returns the origin value to echo back in the ACAO header,
        or ``None`` if the origin is not allowed.
        """
        allow_origins = self._config.allow_origins
        if not allow_origins:
            return None
        if "*" in allow_origins:
            return "*"
        if origin in allow_origins:
            return origin
        return None

    def _build_preflight_response(self, matched_origin: str) -> Response:
        """Build a 200 response with preflight CORS headers."""
        headers: dict[str, str] = {
            "Access-Control-Allow-Origin": matched_origin,
            "Access-Control-Allow-Methods": ", ".join(self._config.allow_methods),
            "Access-Control-Allow-Headers": ", ".join(self._config.allow_headers),
            "Access-Control-Max-Age": str(self._config.max_age),
        }
        if self._config.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        return Response(status_code=200, headers=headers)

    def _inject_cors_headers(self, response: Response, matched_origin: str) -> None:
        """Inject CORS headers into an existing response."""
        response.headers["Access-Control-Allow-Origin"] = matched_origin
        response.headers["Vary"] = "Origin"
        if self._config.expose_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(
                self._config.expose_headers
            )
        if self._config.allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"
