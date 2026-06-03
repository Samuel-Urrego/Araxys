"""IP Access Control backends — Protocol, InMemory, and Redis implementations.

Supports IPv4 and IPv6 CIDR matching via the ``ipaddress`` stdlib module.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import structlog

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger("araxys.ip_access.backends")


# ── CIDR Helper ──────────────────────────────────────────────────────────


def _ip_matches_cidr(ip: str, cidr: str) -> bool:
    """Check if an IP address matches a CIDR notation range.

    Works for both IPv4 and IPv6 addresses.
    """
    try:
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(cidr, strict=False)
        return addr in network
    except ValueError:
        logger.warning("invalid_ip_or_cidr", ip=ip, cidr=cidr)
        return False


# ── Protocol ─────────────────────────────────────────────────────────────


@runtime_checkable
class IPAccessBackend(Protocol):
    """Pluggable backend for IP access control rules.

    Implementations must handle CIDR notation matching for both
    IPv4 and IPv6.
    """

    async def is_allowed(self, ip: str) -> bool:
        """Return True if *ip* is in the allowlist."""
        ...

    async def is_blocked(self, ip: str) -> bool:
        """Return True if *ip* is in the blocklist."""
        ...

    async def add_to_allowlist(self, ip: str) -> None:
        """Add *ip* (or CIDR) to the allowlist."""
        ...

    async def add_to_blocklist(self, ip: str) -> None:
        """Add *ip* (or CIDR) to the blocklist."""
        ...

    async def remove_from_allowlist(self, ip: str) -> None:
        """Remove *ip* (or CIDR) from the allowlist."""
        ...

    async def remove_from_blocklist(self, ip: str) -> None:
        """Remove *ip* (or CIDR) from the blocklist."""
        ...


# ── InMemory Implementation ──────────────────────────────────────────────


class InMemoryIPAccessBackend:
    """In-memory IP access control backend using Python sets.

    Supports both exact IPs and CIDR notation. Mutable operations
    (add/remove) take effect immediately.
    """

    def __init__(
        self,
        allowlist: set[str] | None = None,
        blocklist: set[str] | None = None,
    ) -> None:
        self._allowlist: set[str] = allowlist or set()
        self._blocklist: set[str] = blocklist or set()

    async def is_allowed(self, ip: str) -> bool:
        return any(
            _ip_matches_cidr(ip, entry)
            for entry in self._allowlist
        )

    async def is_blocked(self, ip: str) -> bool:
        return any(
            _ip_matches_cidr(ip, entry)
            for entry in self._blocklist
        )

    async def add_to_allowlist(self, ip: str) -> None:
        self._allowlist.add(ip)

    async def add_to_blocklist(self, ip: str) -> None:
        self._blocklist.add(ip)

    async def remove_from_allowlist(self, ip: str) -> None:
        self._allowlist.discard(ip)

    async def remove_from_blocklist(self, ip: str) -> None:
        self._blocklist.discard(ip)


# ── Redis Implementation ─────────────────────────────────────────────────


class RedisIPAccessBackend:
    """Redis-backed IP access control backend.

    Uses Redis SETs with key pattern ``araxys:ip_access:{allowlist|blocklist}``.
    Each member is an IP or CIDR string.

    Parameters
    ----------
    redis:
        An async Redis client instance.
    """

    _ALLOWLIST_KEY = "araxys:ip_access:allowlist"
    _BLOCKLIST_KEY = "araxys:ip_access:blocklist"

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def _get_all_members(self, key: str) -> set[str]:
        members = await self._redis.smembers(key)  # type: ignore[misc]
        assert isinstance(members, set)
        return {m for m in members if m}

    async def is_allowed(self, ip: str) -> bool:
        allowlist = await self._get_all_members(self._ALLOWLIST_KEY)
        return any(_ip_matches_cidr(ip, entry) for entry in allowlist)

    async def is_blocked(self, ip: str) -> bool:
        blocklist = await self._get_all_members(self._BLOCKLIST_KEY)
        return any(_ip_matches_cidr(ip, entry) for entry in blocklist)

    async def add_to_allowlist(self, ip: str) -> None:
        await self._redis.sadd(self._ALLOWLIST_KEY, ip)  # type: ignore[misc]

    async def add_to_blocklist(self, ip: str) -> None:
        await self._redis.sadd(self._BLOCKLIST_KEY, ip)  # type: ignore[misc]

    async def remove_from_allowlist(self, ip: str) -> None:
        await self._redis.srem(self._ALLOWLIST_KEY, ip)  # type: ignore[misc]

    async def remove_from_blocklist(self, ip: str) -> None:
        await self._redis.srem(self._BLOCKLIST_KEY, ip)  # type: ignore[misc]

    async def add_bulk_to_blocklist(self, ips: list[str]) -> None:
        """Add multiple IPs to the blocklist using a Redis pipeline.

        IPs are batched in groups of 1000 to avoid blocking the event
        loop on large feed loads (e.g. 20K IPs from Blocklist.de).

        Parameters
        ----------
        ips:
            IP addresses or CIDR ranges to add to the blocklist.
        """
        if not ips:
            return

        BATCH_SIZE = 1000
        for i in range(0, len(ips), BATCH_SIZE):
            batch = ips[i : i + BATCH_SIZE]
            pipe = self._redis.pipeline()
            for ip in batch:
                pipe.sadd(self._BLOCKLIST_KEY, ip)
            await pipe.execute()
