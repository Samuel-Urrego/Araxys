"""Challenge storage backends for WebAuthn.

Provides a ``ChallengeStore`` protocol and both in-memory and Redis
implementations for managing ephemeral WebAuthn challenges.

Challenges are short-lived (default TTL: 300 seconds) and MUST be
deleted after one successful verification.
"""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ChallengeStore(Protocol):
    """Protocol for storing and retrieving WebAuthn challenges.

    Challenges are ephemeral — they have a TTL and should be deleted
    after verification.
    """

    async def set(
        self, key: str, challenge: bytes, ttl_seconds: int = 300
    ) -> None:
        """Store a challenge with an optional TTL."""
        ...

    async def get(self, key: str) -> bytes | None:
        """Retrieve a challenge by key, or ``None`` if expired/unknown."""
        ...

    async def delete(self, key: str) -> None:
        """Delete a challenge by key."""
        ...


class InMemoryChallengeStore:
    """In-memory implementation of ``ChallengeStore``.

    .. warning::
        Not suitable for multi-worker deployments. Challenges are
        stored locally and lost on worker restart.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[bytes, float]] = {}

    async def set(
        self, key: str, challenge: bytes, ttl_seconds: int = 300
    ) -> None:
        if ttl_seconds <= 0:
            # Store with expiry=0 to mark as immediately expired
            self._store[key] = (challenge, 0.0)
        else:
            self._store[key] = (challenge, time.monotonic() + ttl_seconds)

    async def get(self, key: str) -> bytes | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        challenge, expiry = entry
        if expiry == 0.0 or time.monotonic() > expiry:
            self._store.pop(key, None)
            return None
        return challenge

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


class RedisChallengeStore:
    """Redis-backed implementation of ``ChallengeStore``.

    Challenges are stored with a TTL using ``SETEX`` and automatically
    removed by Redis on expiry.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    async def set(
        self, key: str, challenge: bytes, ttl_seconds: int = 300
    ) -> None:
        redis_key = f"webauthn:challenge:{key}"
        if ttl_seconds <= 0:
            await self._redis.set(redis_key, challenge)
            await self._redis.delete(redis_key)
        else:
            await self._redis.setex(redis_key, ttl_seconds, challenge)

    async def get(self, key: str) -> bytes | None:
        value = await self._redis.get(f"webauthn:challenge:{key}")
        return value  # type: ignore[no-any-return]

    async def delete(self, key: str) -> None:
        await self._redis.delete(f"webauthn:challenge:{key}")
