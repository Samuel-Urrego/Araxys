"""Honeypot trap registration and handling.

Registers fake routes on the FastAPI router. When a bot hits one of
these routes, its IP is automatically banned across the entire system.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from araxys.core.config import HoneypotConfig
from araxys.core.types import AuditEntry, AuditEventType
from araxys.rate_limit.backends import RateLimitBackend

logger = structlog.get_logger("araxys.honeypot")


class HoneypotTrap:
    """Manages honeypot endpoints and IP banning.

    Parameters
    ----------
    backend:
        Shared rate-limit backend used to ban IPs.
    config:
        Honeypot configuration.
    on_audit:
        Optional callback to emit audit events.
    """

    def __init__(
        self,
        backend: RateLimitBackend,
        config: HoneypotConfig,
        on_audit: callable | None = None,
    ) -> None:
        self._backend = backend
        self._config = config
        self._on_audit = on_audit

    def register_routes(self, app: FastAPI) -> None:
        """Register all honeypot trap routes on the FastAPI app."""
        for path in self._config.paths:
            self._register_single_route(app, path)
        logger.info(
            "honeypot.routes_registered",
            count=len(self._config.paths),
            paths=self._config.paths,
        )

    def _register_single_route(self, app: FastAPI, path: str) -> None:
        """Register a single trap route that catches all HTTP methods."""

        @app.api_route(
            path,
            methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            include_in_schema=False,
        )
        async def _honeypot_handler(request: Request) -> JSONResponse:
            return await self._handle_trap(request, path)

    async def _handle_trap(self, request: Request, path: str) -> JSONResponse:
        """Handle a request to a honeypot endpoint.

        1. Ban the IP
        2. Emit an audit event
        3. Return a fake response to avoid alerting the bot
        """
        ip = self._get_client_ip(request)

        # Ban the IP
        await self._backend.ban(ip, self._config.ban_duration_seconds)
        logger.warning("honeypot.triggered", ip=ip, path=path)

        # Emit audit event
        if self._on_audit:
            entry = AuditEntry(
                event_type=AuditEventType.HONEYPOT_TRIGGERED,
                ip_address=ip,
                resource=path,
                action="honeypot_access",
                detail=f"Bot trapped on {path}",
            )
            await self._on_audit(entry)

        # Return a convincing fake response
        return JSONResponse(
            status_code=self._config.fake_response_code,
            content={"status": "ok"},
        )

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"
