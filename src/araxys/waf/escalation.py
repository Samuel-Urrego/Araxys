"""WAF escalation subscriber — multi-strike auto-blocking via AWS WAF."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

import structlog

from araxys.core.config import WafEscalationConfig
from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from araxys.webhooks.emitter import SecurityEventBus

    from araxys.waf.aws_client import WafClient

logger = structlog.get_logger("araxys.waf.escalation")


class WafEscalationSubscriber:
    """Subscribes to :class:`SecurityEventBus` and escalates IPs that
    cross a multi-strike threshold to an AWS WAF IP set.

    Parameters
    ----------
    config:
        Escalation configuration.
    event_bus:
        The shared security event bus.
    waf_client:
        Optional :class:`WafClient` instance. When ``None``, escalation
        runs in dry-run mode regardless of config setting.
    """

    def __init__(
        self,
        config: WafEscalationConfig,
        event_bus: SecurityEventBus,
        waf_client: WafClient | None = None,
    ) -> None:
        self._config = config
        self._waf_client = waf_client
        self._semaphore = asyncio.Semaphore(1)

        # In-memory strike counter: {ip: [timestamp, ...]}
        self._strikes: dict[str, list[float]] = {}

        # Subscribe to the event bus
        event_bus.subscribe(self._on_event)

    # ------------------------------------------------------------------
    # Event handler
    # ------------------------------------------------------------------

    async def _on_event(self, event: SecurityEvent) -> None:
        """Called by the event bus for every security event.

        Filters by event type and source IP, then checks if the
        multi-strike threshold has been reached.
        """
        # Silently skip events without a source IP
        if not event.source_ip:
            return

        # Filter by allowed event types
        if event.event_type.value not in self._config.allowed_event_types:
            return

        ip = event.source_ip
        now = time.time()
        window = self._config.multi_strike_window_seconds

        if ip not in self._strikes:
            self._strikes[ip] = []

        # Evict stale timestamps
        self._strikes[ip] = [
            ts for ts in self._strikes[ip] if now - ts <= window
        ]

        # Record new strike
        self._strikes[ip].append(now)

        # Check threshold
        if len(self._strikes[ip]) >= self._config.multi_strike_count:
            await self._escalate(ip)

    # ------------------------------------------------------------------
    # Escalation
    # ------------------------------------------------------------------

    async def _escalate(self, ip: str) -> None:
        """Escalate *ip* to the AWS WAF IP set (or log in dry-run mode)."""

        if self._config.dry_run or self._waf_client is None:
            logger.info(
                "waf_escalation_dry_run",
                ip=ip,
                message="DRY RUN: would escalate IP to WAF IP set",
            )
            return

        async with self._semaphore:
            try:
                current = await self._waf_client.get_ip_set(
                    ip_set_id=self._config.ip_set_id or "",
                    ip_set_name=self._config.ip_set_name,
                )
                lock_token = (
                    current.get("IPSet", {}).get("LockToken", "")
                )
                current_addrs: list[str] = (
                    current.get("IPSet", {}).get("Addresses", [])
                )

                cidr = f"{ip}/32"
                if cidr in current_addrs:
                    logger.debug(
                        "waf_escalation_already_blocked",
                        ip=ip,
                    )
                    return

                new_addrs = [*current_addrs, cidr]
                await self._waf_client.update_ip_set(
                    ip_set_id=self._config.ip_set_id or "",
                    ip_set_name=self._config.ip_set_name,
                    ip_addresses=new_addrs,
                    lock_token=lock_token,
                )
                logger.info(
                    "waf_escalation_blocked",
                    ip=ip,
                    total=len(new_addrs),
                )
            except Exception:
                logger.exception(
                    "waf_escalation_failed",
                    ip=ip,
                )
