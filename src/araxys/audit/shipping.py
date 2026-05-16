"""Log shipping for audit events.

Sends audit log entries to external endpoints (webhooks) via HTTP POST.
Shipping failures are non-blocking — errors are logged but never raised.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import structlog

if TYPE_CHECKING:
    from araxys.core.config import LogShippingConfig

logger = structlog.get_logger("araxys.audit.shipping")


class LogShipper:
    """Ships audit events to an external endpoint.

    Parameters
    ----------
    config:
        Log shipping configuration (endpoint, headers, TLS settings).
    client:
        Optional ``httpx.AsyncClient`` instance. If omitted, a new client
        is created.
    """

    def __init__(
        self,
        config: LogShippingConfig,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._client = client or httpx.AsyncClient()

    async def ship(self, data: dict[str, Any]) -> None:
        """Send *data* as a JSON POST to the configured endpoint.

        Parameters
        ----------
        data:
            The audit event payload to ship.
        """
        if self._config.type != "http":
            logger.warning("unsupported_shipping_type", type=self._config.type)
            return

        headers: dict[str, str] = {}
        if self._config.headers:
            headers.update(self._config.headers)
        headers.setdefault("Content-Type", "application/json")

        scheme = "https" if self._config.tls_enabled else "http"
        endpoint = self._config.endpoint.replace("https://", f"{scheme}://", 1)

        try:
            response = await self._client.post(
                endpoint,
                content=json.dumps(data, default=str),
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            logger.warning(
                "audit.shipping_failed",
                endpoint=endpoint,
                exc_info=True,
            )
