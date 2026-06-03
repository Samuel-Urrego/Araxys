"""ThreatIntelScheduler — background asyncio loop for threat intel feeds.

Coordinates feed fetching, IP deduplication, blocklist sync, TTL
eviction, and event emission.  Wired by :class:`AraxysShield` and
controlled via the ``threat-intel`` CLI.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import TYPE_CHECKING, Any

import structlog

from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.threat_intel.resolver import IPResolver

if TYPE_CHECKING:
    from araxys.core.config import ThreatIntelConfig
    from araxys.ip_access.backends import IPAccessBackend
    from araxys.threat_intel.feeds import FeedSource

logger = structlog.get_logger("araxys.threat_intel.scheduler")


def _ip_from_key(key: str) -> str:
    """Extract the IP address from a ``"ip:feed_name"`` TTL map key."""
    return key.rsplit(":", 1)[0]


class ThreatIntelScheduler:
    """Background scheduler for threat intelligence feed ingestion.

    Manages per-feed fetching on staggered timers, deduplication via
    :class:`IPResolver`, bulk blocklist insertion, TTL-based
    eviction, and ``THREAT_INTEL_LOADED`` event emission.

    Parameters
    ----------
    config:
        Master threat intel configuration.
    backend:
        IP access backend where blocked IPs are stored.
    feeds:
        List of feed fetcher instances.  Only feeds present in this
        list are fetched.
    event_bus:
        Optional :class:`SecurityEventBus` for emitting load events.
    """

    def __init__(
        self,
        config: ThreatIntelConfig,
        backend: IPAccessBackend,
        *,
        feeds: list[FeedSource] | None = None,
        event_bus: Any = None,
    ) -> None:
        self._config = config
        self._backend = backend
        self._feeds: list[FeedSource] = list(feeds) if feeds else []
        self._event_bus = event_bus

        self._resolver = IPResolver(config)

        # Lifecycle state
        self._running = False
        self._task: asyncio.Task[None] | None = None

        # Per-feed next-fetch timers (wall-clock based)
        self._feed_timers: dict[str, float] = {}

    # ── Public properties ────────────────────────────────────────────────

    @property
    def resolver(self) -> IPResolver:
        """The internal :class:`IPResolver` for inspection."""
        return self._resolver

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background scheduler loop.

        Sets ``_running = True`` and creates an :class:`asyncio.Task`
        for :meth:`_run`.  Idempotent — calling twice is a no-op.
        """
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Gracefully stop the scheduler.

        Cancels the background task, awaits its completion, and sets
        ``_running = False``.  Safe to call without a prior
        :meth:`start`.
        """
        self._running = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self._task = None

    # ── Background loop ──────────────────────────────────────────────────

    async def _run(self) -> None:
        """Main scheduler loop — fetches feeds on staggered timers.

        Each feed is fetched when its timer expires (wall-clock based).
        The loop sleeps in 1-second increments to remain responsive
        to cancellation.
        """
        while self._running:
            now = time.time()
            for feed in self._feeds:
                if not self._running:
                    return
                timer = self._feed_timers.get(feed.name, 0.0)
                if now >= timer:
                    try:
                        await self._refresh_one(feed.name)
                    except Exception:
                        logger.warning(
                            "threat_intel.feed_error",
                            feed=feed.name,
                            exc_info=True,
                        )
                    # Schedule next fetch after this feed's interval
                    feed_cfg = getattr(self._config, feed.name, None)
                    interval = (
                        feed_cfg.refresh_interval_seconds
                        if feed_cfg is not None and feed_cfg.enabled
                        else self._config.refresh_interval_seconds
                    )
                    self._feed_timers[feed.name] = now + interval

            await self._sleep_with_cancel_check(1.0)

    async def _sleep_with_cancel_check(self, seconds: float) -> None:
        """Sleep in small increments for responsive cancellation."""
        for _ in range(int(seconds)):
            if not self._running:
                return
            await asyncio.sleep(1.0)

    # ── Public API ───────────────────────────────────────────────────────

    async def refresh(self, feed_name: str | None = None) -> Any:
        """Trigger an on-demand refresh of one or all feeds.

        Parameters
        ----------
        feed_name:
            Feed to refresh.  ``None`` refreshes every feed.

        Returns
        -------
        dict | list[dict]
            Single :class:`dict` when *feed_name* is specified;
            ``list[dict]`` when refreshing all feeds.
        """
        if feed_name is not None:
            return await self._refresh_one(feed_name)

        results: list[dict[str, object]] = []
        for feed in self._feeds:
            result = await self._refresh_one(feed.name)
            results.append(result)
        return results

    def stats(self) -> dict[str, object]:
        """Return statistics about currently tracked IPs.

        Returns
        -------
        dict
            Keys: ``"total_ips"`` (int), ``"feeds"`` (dict of
            feed_name → ``{"ip_count": int, ...}``).
        """
        per_feed: dict[str, dict[str, object]] = {}
        for key in self._resolver._ttl_map:
            ip, fn = key.split(":", 1)
            if fn not in per_feed:
                per_feed[fn] = {
                    "ip_count": 0,
                    "last_fetch": None,
                }
            cnt = per_feed[fn].get("ip_count", 0)
            per_feed[fn]["ip_count"] = int(cnt) + 1  # type: ignore[operator]

        return {
            "total_ips": len(self._resolver._seen_ips),
            "feeds": per_feed,
        }

    async def purge(self) -> int:
        """Remove all threat-intel tracked IPs from the blocklist.

        Returns
        -------
        int
            Number of IP entries removed.
        """
        count = 0
        for key in list(self._resolver._ttl_map.keys()):
            ip = _ip_from_key(key)
            await self._backend.remove_from_blocklist(ip)
            del self._resolver._ttl_map[key]
            count += 1
        self._resolver._seen_ips.clear()
        return count

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _refresh_one(self, feed_name: str) -> dict[str, object]:
        """Fetch, deduplicate, sync, and evict for a single feed."""
        # Find the feed fetcher
        feed = next(
            (f for f in self._feeds if f.name == feed_name), None
        )
        if feed is None:
            return {
                "feed": feed_name,
                "error": f"Feed not found: {feed_name}",
            }

        # Get the feed config from ThreatIntelConfig
        feed_cfg = getattr(self._config, feed_name, None)

        # Fetch
        try:
            result = await feed.fetch(feed_cfg)
        except Exception as exc:
            logger.warning(
                "threat_intel.fetch_exception",
                feed=feed_name,
                exc_info=True,
            )
            return {
                "feed": feed_name,
                "error": str(exc),
            }

        # Log non-fatal fetch errors
        for err in result.errors:
            logger.warning(
                "threat_intel.fetch_warning",
                feed=feed_name,
                error=err,
            )

        # Determine TTL for this feed
        ttl = self._resolver._default_ttl
        if feed_cfg is not None and hasattr(feed_cfg, "ttl_seconds"):
            ttl = feed_cfg.ttl_seconds

        # Deduplicate
        new_ips = self._resolver.deduplicate(
            result.ips, feed_name, ttl_seconds=ttl,
        )

        # Sync new IPs to backend
        if new_ips:
            await self._resolver.sync_to_backend(self._backend, new_ips)

        # Evict expired entries
        evicted_ips = 0
        expired_keys = self._resolver.evict_expired()
        for key in expired_keys:
            ip = _ip_from_key(key)
            await self._backend.remove_from_blocklist(ip)
            evicted_ips += 1

        # Emit THREAT_INTEL_LOADED event
        if self._event_bus is not None:
            event = SecurityEvent(
                event_type=SecurityEventType.THREAT_INTEL_LOADED,
                severity="info",
                message=(
                    f"Feed {feed_name}: {len(new_ips)} new IPs, "
                    f"{len(result.ips)} total fetched, "
                    f"{evicted_ips} evicted"
                ),
                metadata={
                    "feed_name": feed_name,
                    "ips_fetched": len(result.ips),
                    "ips_added": len(new_ips),
                    "ips_evicted": evicted_ips,
                },
            )
            await self._event_bus.emit(event)

        return {
            "feed": feed_name,
            "ips_added": len(new_ips),
            "ips_evicted": evicted_ips,
        }
