"""Brute force attempt tracking and lockout middleware.

Provides a pluggable ``BruteForceBackend`` protocol with InMemory and
Redis implementations, and a ``BruteForceMiddleware`` that intercepts
login requests to detect and block brute force attacks.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import BruteForceConfig

# Module-level event bus reference — set by shield.py on init.
_event_bus: Any = None


# ── Protocol ──────────────────────────────────────────────────────────────


@runtime_checkable
class BruteForceBackend(Protocol):
    """Pluggable backend for brute force attempt tracking and lockout.

    Implementations must track attempts per identifier and support
    time-based lockout with expiration.
    """

    async def record_attempt(self, identifier: str) -> int:
        """Record a failed attempt and return the current count."""
        ...

    async def is_locked(self, identifier: str) -> bool:
        """Return ``True`` if the identifier is currently locked out."""
        ...

    async def set_lockout(self, identifier: str, duration_seconds: int) -> None:
        """Lock the identifier for *duration_seconds*."""
        ...

    async def reset(self, identifier: str) -> None:
        """Clear both attempt count and lockout for the identifier."""
        ...

    async def get_attempts(self, identifier: str) -> int:
        """Return the current attempt count for the identifier."""
        ...


# ── InMemory Implementation ────────────────────────────────────────────────


class InMemoryBruteForceBackend:
    """In-memory brute force backend using dicts with TTL.

    Attempt counters are stored in a dict. Lockout state is tracked
    via ``time.monotonic`` timestamps. Expired lockouts are cleaned
    up lazily on ``is_locked`` calls.
    """

    def __init__(self) -> None:
        self._attempts: dict[str, int] = {}
        self._lockouts: dict[str, float] = {}

    async def record_attempt(self, identifier: str) -> int:
        count = self._attempts.get(identifier, 0) + 1
        self._attempts[identifier] = count
        return count

    async def is_locked(self, identifier: str) -> bool:
        expiry = self._lockouts.get(identifier)
        if expiry is None:
            return False
        if time.monotonic() >= expiry:
            del self._lockouts[identifier]
            return False
        return True

    async def set_lockout(self, identifier: str, duration_seconds: int) -> None:
        self._lockouts[identifier] = time.monotonic() + duration_seconds

    async def reset(self, identifier: str) -> None:
        self._attempts.pop(identifier, None)
        self._lockouts.pop(identifier, None)

    async def get_attempts(self, identifier: str) -> int:
        return self._attempts.get(identifier, 0)


# ── Redis Implementation ────────────────────────────────────────────────────


class RedisBruteForceBackend:
    """Redis-backed brute force backend.

    Uses ``INCR`` + ``EXPIRE`` for attempt tracking and a separate
    lockout key for lockout state.

    Key patterns:
        ``araxys:brute_force:{identifier}`` — attempt counter
        ``araxys:brute_force:lockout:{identifier}`` — lockout flag
    """

    _ATTEMPT_KEY_PREFIX = "araxys:brute_force:"
    _LOCKOUT_KEY_PREFIX = "araxys:brute_force:lockout:"

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    async def record_attempt(self, identifier: str) -> int:
        key = f"{self._ATTEMPT_KEY_PREFIX}{identifier}"
        count = int(await self._redis.incr(key))
        return count

    async def is_locked(self, identifier: str) -> bool:
        key = f"{self._LOCKOUT_KEY_PREFIX}{identifier}"
        exists = await self._redis.exists(key)
        return bool(exists)

    async def set_lockout(self, identifier: str, duration_seconds: int) -> None:
        key = f"{self._LOCKOUT_KEY_PREFIX}{identifier}"
        await self._redis.setex(key, duration_seconds, "1")

    async def reset(self, identifier: str) -> None:
        attempt_key = f"{self._ATTEMPT_KEY_PREFIX}{identifier}"
        lockout_key = f"{self._LOCKOUT_KEY_PREFIX}{identifier}"
        await self._redis.delete(attempt_key, lockout_key)

    async def get_attempts(self, identifier: str) -> int:
        key = f"{self._ATTEMPT_KEY_PREFIX}{identifier}"
        val = await self._redis.get(key)
        return int(val) if val else 0


# ── Middleware ──────────────────────────────────────────────────────────────


class BruteForceMiddleware(BaseHTTPMiddleware):
    """Brute force protection middleware.

    Tracks failed login attempts per identifier (default: ``username``).
    After *max_attempts* consecutive failures the identifier is locked
    for *lockout_duration_seconds*. A successful login (2xx response)
    resets the counter.

    The middleware extracts the identifier from the request body (JSON
    or form data) using the configured *identifier_field*.

    Parameters
    ----------
    app:
        The ASGI application.
    config:
        Brute force protection configuration.
    backend:
        Backend for attempt and lockout storage.
    """

    def __init__(
        self,
        app: Any,
        config: BruteForceConfig,
        backend: BruteForceBackend,
    ) -> None:
        super().__init__(app)
        self._config = config
        self._backend = backend

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        identifier = await self._extract_identifier(request)

        # Check lockout before processing
        if identifier is not None and await self._backend.is_locked(identifier):
            return JSONResponse(
                status_code=423,
                content={
                    "detail": "Account locked due to too many attempts",
                    "retry_after_seconds": self._config.lockout_duration_seconds,
                },
            )

        response = await call_next(request)

        # Post-response: track attempts and manage lockout
        if identifier is not None:
            if response.status_code == 401:
                attempts = await self._backend.record_attempt(identifier)
                if attempts >= self._config.max_attempts:
                    await self._backend.set_lockout(
                        identifier, self._config.lockout_duration_seconds
                    )
                    await self._emit_event(identifier)
            elif response.status_code < 300:
                await self._backend.reset(identifier)

        return response

    async def _extract_identifier(self, request: Request) -> str | None:
        """Extract the identifier from the request body.

        Tries JSON first, then form data. Returns ``None`` if the
        identifier field is not present or the body cannot be parsed.
        """
        field = self._config.identifier_field
        body_bytes = await request.body()
        if not body_bytes:
            return None

        # Try JSON
        try:
            data = json.loads(body_bytes)
            if isinstance(data, dict) and field in data:
                return str(data[field])
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Try form data
        try:
            content_type = request.headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:
                from urllib.parse import parse_qs

                parsed = parse_qs(body_bytes.decode("utf-8"))
                if field in parsed:
                    return parsed[field][0]
        except Exception:
            pass

        return None

    async def _emit_event(self, identifier: str) -> None:
        """Emit a BRUTE_FORCE_LOCKOUT security event."""
        if _event_bus is None:
            return
        event = SecurityEvent(
            event_type=SecurityEventType.BRUTE_FORCE_LOCKOUT,
            severity="warning",
            message=f"Brute force lockout: {identifier}",
            timestamp=datetime.now(UTC),
            metadata={
                "identifier": identifier,
                "max_attempts": self._config.max_attempts,
            },
        )
        await _event_bus.emit(event)
