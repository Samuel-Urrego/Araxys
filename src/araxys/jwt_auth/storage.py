"""JWT token storage protocol and implementations.

Token storage is used for refresh token revocation tracking via JTI
(JWT ID) — when a refresh token is rotated, the old JTI is blacklisted.
"""


from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class TokenStorage(Protocol):
    """Interface for JWT refresh token state."""

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        """Add a JTI to the blacklist with a TTL matching the token expiry."""
        ...

    async def is_blacklisted(self, jti: str) -> bool:
        """Check if a JTI has been revoked."""
        ...


class InMemoryTokenStorage:
    """In-memory token storage for development and testing."""

    def __init__(self) -> None:
        # jti -> expires_at (monotonic)
        self._blacklist: dict[str, float] = {}

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        self._blacklist[jti] = time.monotonic() + ttl_seconds

    async def is_blacklisted(self, jti: str) -> bool:
        if jti not in self._blacklist:
            return False
        if time.monotonic() >= self._blacklist[jti]:
            del self._blacklist[jti]
            return False
        return True

    def _cleanup(self) -> None:
        """Remove expired entries (call periodically for long-running processes)."""
        now = time.monotonic()
        expired = [jti for jti, exp in self._blacklist.items() if now >= exp]
        for jti in expired:
            del self._blacklist[jti]


class RedisTokenStorage:
    """Redis-backed token storage for production.

    Requires the ``redis`` extra: ``pip install araxys[redis]``.
    """

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import from_url
        except ImportError as exc:
            raise ImportError(
                "RedisTokenStorage requires the 'redis' package. "
                "Install it with: pip install araxys[redis]"
            ) from exc
        self._redis = from_url(redis_url, decode_responses=True)

    def _key(self, jti: str) -> str:
        return f"araxys:jti_blacklist:{jti}"

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        await self._redis.setex(self._key(jti), ttl_seconds, "1")

    async def is_blacklisted(self, jti: str) -> bool:
        return await self._redis.exists(self._key(jti)) > 0  # type: ignore
