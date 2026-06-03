"""IPResolver — deduplication, exclude-IP filtering, TTL tracking, eviction.

Handles the in-memory lifecycle of threat-intel IPs: deciding which
IPs are new, which should be blocked, when they expire, and syncing
them to the IP access backend.
"""

from __future__ import annotations

import ipaddress
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import ThreatIntelConfig
    from araxys.ip_access.backends import IPAccessBackend


class IPResolver:
    """In-memory IP deduplication and TTL tracking for threat intel feeds.

    Parameters
    ----------
    config:
        Master threat intel configuration (used for ``exclude_ips``).
    redis:
        Optional Redis client for ZSET-backed TTL tracking.
        When ``None``, TTL is tracked purely in-memory.
    default_ttl:
        Default TTL in seconds when no feed-specific TTL is available.
    """

    def __init__(
        self,
        config: ThreatIntelConfig,
        *,
        redis: object | None = None,
        default_ttl: int = 86400,
    ) -> None:
        self._config = config
        self._redis = redis
        self._default_ttl = default_ttl

        # _ttl_map: "ip:feed_name" → expiration timestamp (unix epoch)
        self._ttl_map: dict[str, float] = {}
        # _seen_ips: set of IP addresses currently tracked (no feed suffix)
        # Used for cross-feed dedup and middleware THREAT_INTEL_MATCH lookup
        self._seen_ips: set[str] = set()

    # ── Public property ──────────────────────────────────────────────────

    @property
    def tracked_ips(self) -> set[str]:
        """Set of IP addresses currently tracked by any feed."""
        return self._seen_ips.copy()

    # ── Deduplication ────────────────────────────────────────────────────

    def deduplicate(
        self,
        ips: list[str],
        feed_name: str,
        ttl_seconds: int | None = None,
    ) -> list[str]:
        """Filter *ips* to only those not already tracked.

        Records or extends the TTL for every IP (new or existing).
        IPs matching ``exclude_ips`` are silently skipped.

        Returns only the IPs that are new (not previously seen by
        *any* feed), so the caller only adds them to the blocklist
        once.

        Parameters
        ----------
        ips:
            Candidate IPs or CIDRs from a feed fetch.
        feed_name:
            Feed identifier for per-feed TTL tracking.
        ttl_seconds:
            Feed-specific TTL.  Falls back to :attr:`_default_ttl`.

        Returns
        -------
        list[str]
            IPs that are new (not yet tracked).
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = time.time()
        expiration = now + ttl

        new_ips: list[str] = []

        for ip_str in ips:
            # 1. Skip excluded IPs
            if self._is_excluded(ip_str):
                continue

            # 2. Always record/update TTL for this feed
            key = f"{ip_str}:{feed_name}"
            self._ttl_map[key] = expiration

            # 3. Add to seen set and result only if truly new
            if ip_str not in self._seen_ips:
                self._seen_ips.add(ip_str)
                new_ips.append(ip_str)

        return new_ips

    # ── Eviction ─────────────────────────────────────────────────────────

    def evict_expired(self) -> list[str]:
        """Return and remove all expired TTL map entries.

        Expired entries are those whose expiration timestamp is
        **less than or equal** to the current time.

        Returns
        -------
        list[str]
            Keys (``"ip:feed_name"``) of expired entries that were
            removed from :attr:`_ttl_map`.
        """
        now = time.time()
        expired_keys = [
            key for key, exp in self._ttl_map.items() if exp <= now
        ]

        for key in expired_keys:
            del self._ttl_map[key]
            # Check if the IP is still tracked by any feed
            ip = key.rsplit(":", 1)[0]
            if not any(k.startswith(ip + ":") for k in self._ttl_map):
                self._seen_ips.discard(ip)

        return expired_keys

    # ── Backend sync ─────────────────────────────────────────────────────

    async def sync_to_backend(
        self,
        backend: IPAccessBackend,
        ips: list[str],
    ) -> None:
        """Add *ips* to the IP access backend in batched fashion.

        Uses :meth:`add_bulk_to_blocklist` when the backend supports
        it (``RedisIPAccessBackend``), falling back to per-IP
        :meth:`add_to_blocklist`.  Lists larger than 1000 IPs are
        split into pipeline-friendly batches.
        """
        if not ips:
            return

        # Prefer bulk method for Redis backends
        if hasattr(backend, "add_bulk_to_blocklist"):
            BATCH_SIZE = 1000
            import asyncio

            # Ensure we're dealing with an async-compatible call
            bulk_fn = getattr(backend, "add_bulk_to_blocklist")
            if asyncio.iscoroutinefunction(bulk_fn):
                for i in range(0, len(ips), BATCH_SIZE):
                    batch = ips[i : i + BATCH_SIZE]
                    await bulk_fn(batch)  # type: ignore[misc]
                return

        # Fallback: per-IP add
        for ip_str in ips:
            await backend.add_to_blocklist(ip_str)

    # ── Exclude-IP helpers ───────────────────────────────────────────────

    def _is_excluded(self, ip_str: str) -> bool:
        """Return ``True`` if *ip_str* overlaps with any ``exclude_ips`` entry.

        Uses ``ipaddress.ip_network`` with ``strict=False`` so that
        bare IPs are treated as ``/32`` networks.  An overlap check
        means that a ``/24`` CIDR containing an excluded single IP is
        also excluded (safe-side false-positive mitigation).
        """
        if not self._config.exclude_ips:
            return False

        try:
            ip_net = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            return False

        for exclude_str in self._config.exclude_ips:
            try:
                exclude_net = ipaddress.ip_network(exclude_str, strict=False)
            except ValueError:
                continue
            if ip_net.overlaps(exclude_net):
                return True

        return False
