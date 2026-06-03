"""Honeypot trap registration and handling.

Registers fake routes on the FastAPI router. When a bot hits one of
these routes, its IP is automatically banned across the entire system.
"""

from __future__ import annotations

import json
import typing
from datetime import UTC, datetime

import structlog
from fastapi import FastAPI, Request  # noqa: TC002
from starlette.responses import JSONResponse

from araxys.core.ip import get_client_ip
from araxys.core.types import (
    AuditEntry,
    AuditEventType,
    SecurityEvent,
    SecurityEventType,
)

if typing.TYPE_CHECKING:
    from araxys.core.config import HoneypotConfig
    from araxys.rate_limit.backends import RateLimitBackend

logger = structlog.get_logger("araxys.honeypot")

# Module-level event bus reference — set by shield.py on init.
_event_bus: typing.Any = None


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
    trusted_proxies:
        Optional list of IPs/CIDRs of trusted reverse proxies.
    """

    def __init__(
        self,
        backend: RateLimitBackend,
        config: HoneypotConfig,
        on_audit: typing.Callable | None = None,  # type: ignore
        trusted_proxies: list[str] | None = None,
    ) -> None:
        self._backend = backend
        self._config = config
        self._on_audit = on_audit
        self._trusted_proxies = trusted_proxies or []

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
        ip = get_client_ip(request, trusted_proxies=self._trusted_proxies)

        # Ban the IP
        await self._backend.ban(ip, self._config.ban_duration_seconds)
        logger.warning("honeypot.triggered", ip=ip, path=path)

        # Emit security event
        if _event_bus is not None:
            await _event_bus.emit(
                SecurityEvent(
                    event_type=SecurityEventType.HONEYPOT_TRIGGERED,
                    severity="warning",
                    message=f"Honeypot triggered: {ip} on {path}",
                    timestamp=datetime.now(UTC),
                    source_ip=ip,
                    metadata={
                        "path": path,
                        "method": request.method,
                    },
                )
            )

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

    # ── Passive Honeypot (hidden form fields) ──────────────────────────

    @staticmethod
    def render_hidden_field(field_name: str = "_email") -> str:
        """Return an HTML hidden form field that bots auto-fill.

        Place this inside your login/registration forms.  Legitimate
        users never see or fill this field (CSS-hidden), but bots
        scanning for ``type="email"`` or ``name="email"`` will populate
        it.  When the form is submitted, call ``check_hidden_field()``
        to detect the bot.

        Usage::

            <form method="post">
                {{ honeypot.render_hidden_field() | safe }}
                ...
            </form>
        """
        return (
            f'<div style="position:absolute;left:-9999px;" aria-hidden="true">'
            f'<input type="email" name="{field_name}" tabindex="-1" '
            f'autocomplete="off" value="" />'
            f"</div>"
        )

    @staticmethod
    async def check_hidden_field(
        request: Request,
        field_name: str = "_email",
    ) -> bool:
        """Return ``True`` if the hidden honeypot field was filled.

        Call this in your form handler.  A filled field means a bot
        submitted the form — ban the IP and reject the request.

        Usage::

            if await HoneypotTrap.check_hidden_field(request):
                raise HTTPException(403, "Bot detected")
        """
        try:
            body = await request.body()
        except Exception:
            return False

        # Check form-urlencoded
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs
            parsed = parse_qs(body.decode("utf-8", errors="replace"))
            return field_name in parsed and bool(parsed[field_name][0])

        # Check JSON
        if "application/json" in content_type:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return False
            if isinstance(data, dict):
                return field_name in data and bool(data[field_name])

        return False
