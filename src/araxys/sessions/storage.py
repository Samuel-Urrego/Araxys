"""Session storage protocol and implementations.

Provides the ``SessionBackend`` Protocol for pluggable session storage,
plus ``InMemorySessionBackend`` for development/testing and
``RedisSessionBackend`` for production.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable


@dataclass
class SessionRecord:
    """A single active user session."""

    session_id: str
    user_id: str
    jti: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class SessionBackend(Protocol):
    """Interface for session storage backends."""

    async def create_session(
        self, user_id: str, jti: str, metadata: dict[str, Any] | None = None
    ) -> str:
        """Create a new session and return its session_id."""
        ...

    async def get_session(self, session_id: str) -> SessionRecord | None:
        """Retrieve a session by ID, or None if not found."""
        ...

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        """List all active sessions for a user."""
        ...

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a session. Returns True if found and revoked."""
        ...

    async def count_sessions(self, user_id: str) -> int:
        """Return the number of active sessions for a user."""
        ...

    async def revoke_oldest(self, user_id: str) -> str | None:
        """Revoke the oldest session for a user. Returns revoked session_id or None."""
        ...


class InMemorySessionBackend:
    """In-memory session storage for development and testing.

    Stores sessions in a dict keyed by session_id, and maintains
    a per-user index for efficient listing and counting.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    async def create_session(
        self, user_id: str, jti: str, metadata: dict[str, Any] | None = None
    ) -> str:
        session_id = str(uuid.uuid4())
        record = SessionRecord(
            session_id=session_id,
            user_id=user_id,
            jti=jti,
            created_at=datetime.now(UTC),
            metadata=metadata or {},
        )
        self._sessions[session_id] = record
        return session_id

    async def get_session(self, session_id: str) -> SessionRecord | None:
        return self._sessions.get(session_id)

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        return [
            s for s in self._sessions.values() if s.user_id == user_id
        ]

    async def revoke_session(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        del self._sessions[session_id]
        return True

    async def count_sessions(self, user_id: str) -> int:
        return sum(1 for s in self._sessions.values() if s.user_id == user_id)

    async def revoke_oldest(self, user_id: str) -> str | None:
        user_sessions = [
            s for s in self._sessions.values() if s.user_id == user_id
        ]
        if not user_sessions:
            return None
        oldest = min(user_sessions, key=lambda s: s.created_at)
        del self._sessions[oldest.session_id]
        return oldest.session_id


class RedisSessionBackend:
    """Redis-backed session storage for production.

    Uses Redis HASH per session (``araxys:sessions:{session_id}``) and
    a SET per user (``araxys:sessions:user:{user_id}``).

    Requires the ``redis`` extra: ``pip install araxys[redis]``.
    """

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import from_url
        except ImportError as exc:
            raise ImportError(
                "RedisSessionBackend requires the 'redis' package. "
                "Install it with: pip install araxys[redis]"
            ) from exc
        self._redis = from_url(redis_url, decode_responses=True)

    def _session_key(self, session_id: str) -> str:
        return f"araxys:sessions:{session_id}"

    def _user_key(self, user_id: str) -> str:
        return f"araxys:sessions:user:{user_id}"

    async def create_session(
        self, user_id: str, jti: str, metadata: dict[str, Any] | None = None
    ) -> str:
        session_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        pipe = self._redis.pipeline()
        pipe.hset(
            self._session_key(session_id),
            mapping={
                "session_id": session_id,
                "user_id": user_id,
                "jti": jti,
                "created_at": now,
                "metadata": str(metadata or {}),
            },
        )
        pipe.sadd(self._user_key(user_id), session_id)
        await pipe.execute()
        return session_id

    async def get_session(self, session_id: str) -> SessionRecord | None:
        data = await self._redis.hgetall(self._session_key(session_id))  # type: ignore[misc]
        if not data:
            return None
        return SessionRecord(
            session_id=data["session_id"],
            user_id=data["user_id"],
            jti=data["jti"],
            created_at=datetime.fromisoformat(data["created_at"]),
            metadata=json.loads(data["metadata"]) if data.get("metadata") else {},
        )

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        session_ids = await self._redis.smembers(self._user_key(user_id))  # type: ignore[misc]
        if not session_ids:
            return []
        records: list[SessionRecord] = []
        for sid in session_ids:
            record = await self.get_session(sid)
            if record is not None:
                records.append(record)
        return records

    async def revoke_session(self, session_id: str) -> bool:
        record = await self.get_session(session_id)
        if record is None:
            return False
        pipe = self._redis.pipeline()
        pipe.delete(self._session_key(session_id))
        pipe.srem(self._user_key(record.user_id), session_id)
        await pipe.execute()
        return True

    async def count_sessions(self, user_id: str) -> int:
        count = await self._redis.scard(self._user_key(user_id))  # type: ignore[misc]
        return count  # type: ignore[no-any-return]

    async def revoke_oldest(self, user_id: str) -> str | None:
        records = await self.list_sessions(user_id)
        if not records:
            return None
        oldest = min(records, key=lambda r: r.created_at)
        await self.revoke_session(oldest.session_id)
        return oldest.session_id



