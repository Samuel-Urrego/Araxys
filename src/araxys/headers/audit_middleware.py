"""Security headers audit middleware — audits response security headers.

Wraps each response and checks its security headers against OWASP
recommendations. Findings are emitted as security events.
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from araxys.headers.auditor import audit_headers

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from araxys.headers.config import AuditConfig
    from araxys.webhooks.emitter import SecurityEventBus

logger = logging.getLogger("araxys.headers")

# Module-level event bus reference — set by AraxysShield during wiring.
_event_bus: SecurityEventBus | None = None


class AuditHeadersMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that audits response security headers.

    On each response, checks headers against OWASP recommendations and
    emits findings as security events for webhooks/metrics.

    Parameters
    ----------
    app:
        The inner ASGI application.
    config:
        Headers audit configuration.
    """

    def __init__(self, app: Any, config: AuditConfig) -> None:
        super().__init__(app)
        self._config = config
        self._sample_rate: float = config.sample_rate
        self._exclude_paths: tuple[str, ...] = tuple(config.exclude_paths)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)

        # Skip excluded paths
        path = request.url.path
        for excluded in self._exclude_paths:
            if path.startswith(excluded):
                return response

        # Sampling
        if self._sample_rate < 1.0:
            if random.random() > self._sample_rate:
                return response

        # Audit headers
        headers_dict = dict(response.headers)
        findings = audit_headers(headers_dict)

        # Emit events for non-pass findings
        has_issues = False
        for finding in findings:
            if finding.status in ("warn", "fail"):
                has_issues = True
                if self._config.emit_to_event_bus and _event_bus is not None:
                    from araxys.core.types import SecurityEvent, SecurityEventType

                    severity = (
                        "warning" if finding.status == "warn" else "critical"
                    )
                    try:
                        evt_type = (
                            SecurityEventType.HEADER_AUDIT_WARNING
                            if finding.status == "warn"
                            else SecurityEventType.HEADER_AUDIT_FAIL
                        )
                    except (AttributeError, ValueError):
                        evt_type = SecurityEventType.RATE_LIMIT_EXCEEDED  # fallback
                    event = SecurityEvent(
                        event_type=evt_type,
                        severity=severity,
                        message=(
                            f"{finding.header_name}: {finding.detail}"
                            if finding.detail
                            else f"{finding.header_name}: {finding.status}"
                        ),
                        metadata={
                            "header_name": finding.header_name,
                            "status": finding.status,
                            "found_value": finding.found_value,
                            "recommended_value": finding.recommended_value,
                        },
                    )
                    await _event_bus.emit(event)

        if has_issues:
            # Add X-Araxys-Headers-Audit header to the response
            response.headers["X-Araxys-Headers-Audit"] = "issues-found"

        return response
