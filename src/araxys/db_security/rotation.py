"""Dynamic secrets rotation scheduler (v0.14).

Periodically checks for credential changes from the secret store
and rotates Redis/PostgreSQL connection pools when credentials change.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

import structlog

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from araxys.core.config import SecretsRotationConfig
    from araxys.db_security.manager import DatabaseSecurityManager
    from araxys.db_security.secrets import ConnectionStringResolver
    from araxys.webhooks.emitter import SecurityEventBus

logger = structlog.get_logger("araxys.db_security.rotation")

# ── Stats value types ──────────────────────────────────────────────────
# Mixed dict containing floats (timestamps), None, and ints (counters).
StatsDict = dict[str, dict[str, Any]]


class SecretsRotationScheduler:
    """Background scheduler for dynamic secrets rotation.

    Periodically checks secret store for credential changes and rotates
    the affected connection pools. Emits security events for observability.

    Parameters
    ----------
    manager:
        The :class:`DatabaseSecurityManager` that owns the connection pools.
    resolver:
        A :class:`ConnectionStringResolver` for looking up current secrets.
    config:
        Rotation configuration (interval, targets, fail mode, events).
    event_bus:
        Optional :class:`SecurityEventBus` for emitting rotation events.
    """

    def __init__(
        self,
        manager: DatabaseSecurityManager,
        resolver: ConnectionStringResolver,
        config: SecretsRotationConfig,
        event_bus: SecurityEventBus | None = None,
    ) -> None:
        self._manager = manager
        self._resolver = resolver
        self._config = config
        self._event_bus = event_bus
        self._task: asyncio.Task[None] | None = None

        # Per-target stats: track last_success, last_error, last_rotated
        self._stats: StatsDict = {}
        for target in config.targets:
            self._stats[target] = {
                "last_success": None,
                "last_error": None,
                "last_rotated": None,
                "rotations": 0,
                "failures": 0,
            }

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Create a background asyncio task for the rotation loop."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())
        logger.info(
            "rotation_scheduler.started",
            interval=self._config.interval_seconds,
        )

    def stop(self) -> None:
        """Cancel the background task and wait for graceful exit."""
        if self._task is None:
            return
        self._task.cancel()
        logger.info("rotation_scheduler.stopped")

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _run(self) -> None:
        """Main rotation loop — runs on config.interval_seconds.

        On first iteration, fires immediately (rotate on startup).
        Subsequent iterations wait for the configured interval.
        """
        first = True
        while True:
            if not first:
                try:
                    await self._sleep_with_cancel_check(self._config.interval_seconds)
                except asyncio.CancelledError:
                    logger.info("rotation_scheduler.cancelled")
                    return
            first = False

            await self.rotate_targets(self._config.targets)

    async def _sleep_with_cancel_check(self, seconds: float) -> None:
        """Sleep for *seconds* while periodically checking for cancellation.

        Uses 1-second polling intervals so that stop() does not block
        for the full sleep duration. Matches the ThreatIntelScheduler pattern.
        """
        elapsed = 0.0
        while elapsed < seconds:
            await asyncio.sleep(min(1.0, seconds - elapsed))
            elapsed += 1.0

    # ------------------------------------------------------------------
    # Public API — on-demand rotation
    # ------------------------------------------------------------------

    async def rotate_targets(self, targets: list[str]) -> None:
        """Rotate credentials for the given targets immediately.

        Parameters
        ----------
        targets:
            List of target names to rotate (e.g. ``["redis", "postgres"]``).
        """
        for target in targets:
            await self._rotate_one(target)

    async def _rotate_one(self, target: str) -> None:
        """Rotate a single target's credentials.

        Resolves the current secret, compares with the pool's active value,
        and rotates if there is a change. Emits events for observability.
        """
        start = time.monotonic()

        # Emit SECRET_ROTATING event
        await self._maybe_emit(
            SecurityEventType.SECRET_ROTATING,
            f"Starting rotation for '{target}'",
            {"target": target},
        )

        try:
            # Resolve new credential from the secret store
            new_value = await self._resolver.resolve(target)

            if new_value is None:
                # No new credential available — skip rotation
                logger.debug(
                    "rotation_scheduler.resolved_none",
                    target=target,
                    msg=f"No credential resolved for '{target}', skipping",
                )
                return

            # Rotate the pool via the manager
            await self._manager.rotate_target(target)

            # Update stats
            elapsed = time.monotonic() - start
            self._stats[target]["last_success"] = elapsed
            self._stats[target]["last_error"] = None
            self._stats[target]["last_rotated"] = time.monotonic()
            self._stats[target]["rotations"] = (
                self._stats[target]["rotations"] + 1
            )

            # Emit SECRET_ROTATED event
            await self._maybe_emit(
                SecurityEventType.SECRET_ROTATED,
                f"Successfully rotated '{target}' in {elapsed:.2f}s",
                {"target": target, "duration_s": round(elapsed, 3)},
            )

        except Exception as exc:
            elapsed = time.monotonic() - start
            self._stats[target]["last_error"] = elapsed
            self._stats[target]["last_success"] = None
            self._stats[target]["failures"] = (
                self._stats[target]["failures"] + 1
            )

            logger.error(
                "rotation_scheduler.rotation_failed",
                target=target,
                error=str(exc),
                duration_s=round(elapsed, 3),
            )

            # Emit SECRET_ROTATION_FAILED event
            await self._maybe_emit(
                SecurityEventType.SECRET_ROTATION_FAILED,
                f"Rotation failed for '{target}': {exc}",
                {"target": target, "error": str(exc), "duration_s": round(elapsed, 3)},
            )

            # fail_closed: escalate to stop the scheduler
            if self._config.fail_closed:
                logger.critical(
                    "rotation_scheduler.fail_closed",
                    target=target,
                    msg=(
                        "fail_closed=True — stopping scheduler after failure"
                        f" for '{target}'"
                    ),
                )
                if self._task is not None:
                    self._task.cancel()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, dict[str, float | None]]:
        """Return per-target rotation statistics.

        Returns a copy of the internal stats dict to prevent mutation.
        """
        return {k: dict(v) for k, v in self._stats.items()}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _maybe_emit(
        self,
        event_type: SecurityEventType,
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Emit a security event if event emission is enabled and bus is set."""
        if not self._config.emit_events or self._event_bus is None:
            return
        event = SecurityEvent(
            event_type=event_type,
            severity=self._severity_for(event_type),
            message=message,
            metadata=metadata or {},
        )
        await self._event_bus.emit(event)

    @staticmethod
    def _severity_for(event_type: SecurityEventType) -> str:
        """Map event type to severity level."""
        if event_type == SecurityEventType.SECRET_ROTATION_FAILED:
            return "warning"
        return "info"
