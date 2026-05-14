"""Rate limit backend protocol and implementations.

Backends track request counts per key and manage temporary bans.
The ``InMemoryBackend`` is the default; ``RedisBackend`` is available
when the ``redis`` extra is installed.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimitBackend(Protocol):
    """Interface for rate-limit storage backends."""

    async def increment(self, key: str, window_seconds: int) -> int:
        """Increment the counter for *key* and return the current count.

        The counter must auto-expire after *window_seconds*.
        """
        ...

    async def get_count(self, key: str) -> int:
        """Return the current count for *key*, or 0 if not present."""
        ...

    async def ban(self, ip: str, duration_seconds: int) -> None:
        """Temporarily ban *ip* for *duration_seconds*."""
        ...

    async def is_banned(self, ip: str) -> bool:
        """Return ``True`` if *ip* is currently banned."""
        ...

    async def get_ban_expiry(self, ip: str) -> int:
        """Return the remaining seconds of the ban, or 0."""
        ...

    async def get_violation_count(self, ip: str) -> int:
        """Return the number of rate-limit violations for *ip*."""
        ...

    async def increment_violations(self, ip: str) -> int:
        """Increment and return the violation count for *ip*."""
        ...


class InMemoryBackend:
    """In-memory rate-limit backend for development and testing.

    NOT suitable for production multi-process deployments — counters are
    per-process and not shared across workers.
    """

    def __init__(self) -> None:
        # key -> (count, window_start)
        self._counters: dict[str, tuple[int, float]] = {}
        self._window_sizes: dict[str, int] = {}
        # ip -> ban_expires_at (unix timestamp)
        self._bans: dict[str, float] = {}
        # ip -> violation_count
        self._violations: defaultdict[str, int] = defaultdict(int)

    async def increment(self, key: str, window_seconds: int) -> int:
        now = time.monotonic()
        self._window_sizes[key] = window_seconds

        if key in self._counters:
            count, window_start = self._counters[key]
            if now - window_start >= window_seconds:
                # Window expired — reset
                self._counters[key] = (1, now)
                return 1
            new_count = count + 1
            self._counters[key] = (new_count, window_start)
            return new_count
        else:
            self._counters[key] = (1, now)
            return 1

    async def get_count(self, key: str) -> int:
        if key not in self._counters:
            return 0
        count, window_start = self._counters[key]
        window = self._window_sizes.get(key, 60)
        if time.monotonic() - window_start >= window:
            del self._counters[key]
            return 0
        return count

    async def ban(self, ip: str, duration_seconds: int) -> None:
        self._bans[ip] = time.monotonic() + duration_seconds

    async def is_banned(self, ip: str) -> bool:
        if ip not in self._bans:
            return False
        if time.monotonic() >= self._bans[ip]:
            del self._bans[ip]
            return False
        return True

    async def get_ban_expiry(self, ip: str) -> int:
        if ip not in self._bans:
            return 0
        remaining = self._bans[ip] - time.monotonic()
        if remaining <= 0:
            del self._bans[ip]
            return 0
        return int(remaining)

    async def get_violation_count(self, ip: str) -> int:
        return self._violations[ip]

    async def increment_violations(self, ip: str) -> int:
        self._violations[ip] += 1
        return self._violations[ip]


class RedisBackend:
    """Redis-backed rate-limit backend for production deployments.

    Requires the ``redis`` extra: ``pip install araxys[redis]``.
    """

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import from_url
        except ImportError as exc:
            raise ImportError(
                "RedisBackend requires the 'redis' package. "
                "Install it with: pip install araxys[redis]"
            ) from exc
        self._redis = from_url(redis_url, decode_responses=True)

    def _rate_key(self, key: str) -> str:
        return f"araxys:rate:{key}"

    def _ban_key(self, ip: str) -> str:
        return f"araxys:ban:{ip}"

    def _violation_key(self, ip: str) -> str:
        return f"araxys:violations:{ip}"

    async def increment(self, key: str, window_seconds: int) -> int:
        rkey = self._rate_key(key)
        pipe = self._redis.pipeline()
        pipe.incr(rkey)
        pipe.expire(rkey, window_seconds, nx=True)
        results = await pipe.execute()
        return int(results[0])

    async def get_count(self, key: str) -> int:
        val = await self._redis.get(self._rate_key(key))
        return int(val) if val else 0

    async def ban(self, ip: str, duration_seconds: int) -> None:
        await self._redis.setex(self._ban_key(ip), duration_seconds, "1")

    async def is_banned(self, ip: str) -> bool:
        return await self._redis.exists(self._ban_key(ip)) > 0

    async def get_ban_expiry(self, ip: str) -> int:
        ttl = await self._redis.ttl(self._ban_key(ip))
        return max(0, ttl)

    async def get_violation_count(self, ip: str) -> int:
        val = await self._redis.get(self._violation_key(ip))
        return int(val) if val else 0

    async def increment_violations(self, ip: str) -> int:
        rkey = self._violation_key(ip)
        pipe = self._redis.pipeline()
        pipe.incr(rkey)
        pipe.expire(rkey, 3600, nx=True)  # Violations expire after 1 hour
        results = await pipe.execute()
        return int(results[0])
