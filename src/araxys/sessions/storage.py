"""Session storage protocol and implementations.

Provides the ``SessionBackend`` Protocol for pluggable session storage,
plus ``InMemorySessionBackend`` for development/testing and
``RedisSessionBackend`` for production.
"""

from __future__ import annotations

import ast
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from araxys.db_security.pool import ConnectionPool


class SessionNotFound(Exception):
    """Raised when a session is not found or has expired/idle timed out."""


def _is_session_idle(
    record: SessionRecord,
    idle_timeout_seconds: int | None,
) -> bool:
    """Check if a session has exceeded the idle timeout.

    Uses ``last_activity_at`` if set, otherwise falls back to ``created_at``.
    Returns False if ``idle_timeout_seconds`` is None or <= 0 (idle disabled).
    """
    if idle_timeout_seconds is None or idle_timeout_seconds <= 0:
        return False
    effective = record.last_activity_at or record.created_at
    elapsed = (datetime.now(UTC) - effective).total_seconds()
    return elapsed > idle_timeout_seconds


async def _emit_idle_event(
    event_bus: Any,
    session_id: str,
    record: SessionRecord,
) -> None:
    """Emit SESSION_IDLE_TIMEOUT event if event_bus is configured."""
    if event_bus is None:
        return
    effective = record.last_activity_at or record.created_at
    elapsed = int((datetime.now(UTC) - effective).total_seconds())
    event = SecurityEvent(
        event_type=SecurityEventType.SESSION_IDLE_TIMEOUT,
        severity="warning",
        message=f"Session {session_id} idle timeout",
        metadata={
            "token": session_id,
            "user_id": record.user_id,
            "idle_duration_seconds": elapsed,
        },
    )
    await event_bus.emit(event)


@dataclass
class SessionRecord:
    """A single active user session."""

    session_id: str
    user_id: str
    jti: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)
    expires_at: float | None = None
    last_activity_at: datetime | None = None


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

    async def refresh_session(self, session_id: str) -> bool:
        """Refresh a session's expiry. Returns True if session was found."""
        ...

    async def touch_session(self, session_id: str) -> None:
        """Update last_activity_at to now. Raises SessionNotFound if not found."""
        ...

    async def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns the number removed."""
        ...


class InMemorySessionBackend:
    """In-memory session storage for development and testing.

    Stores sessions in a dict keyed by session_id, and maintains
    a per-user index for efficient listing and counting.
    """

    def __init__(
        self,
        session_ttl_seconds: int = 3600,
        idle_timeout_seconds: int | None = None,
        event_bus: Any = None,
    ) -> None:
        self._sessions: dict[str, SessionRecord] = {}
        self._session_ttl_seconds = session_ttl_seconds
        self._idle_timeout_seconds = idle_timeout_seconds
        self._event_bus = event_bus

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
            expires_at=time.time() + self._session_ttl_seconds,
        )
        self._sessions[session_id] = record
        return session_id

    async def get_session(self, session_id: str) -> SessionRecord | None:
        record = self._sessions.get(session_id)
        if record is None:
            return None
        # Bug 2 fix: check TTL expiry
        if record.expires_at is not None and record.expires_at <= time.time():
            del self._sessions[session_id]
            return None
        # Idle timeout check
        if _is_session_idle(record, self._idle_timeout_seconds):
            await _emit_idle_event(self._event_bus, session_id, record)
            return None
        return record

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

    async def refresh_session(self, session_id: str) -> bool:
        if session_id not in self._sessions:
            return False
        self._sessions[session_id].expires_at = (
            time.time() + self._session_ttl_seconds
        )
        return True

    async def touch_session(self, session_id: str) -> None:
        record = self._sessions.get(session_id)
        if record is None:
            raise SessionNotFound(
                f"Session {session_id} not found"
            )
        # Idle check — cannot touch an idle session
        if _is_session_idle(record, self._idle_timeout_seconds):
            raise SessionNotFound(
                f"Session {session_id} is idle"
            )
        record.last_activity_at = datetime.now(UTC)

    async def cleanup_expired(self) -> int:
        now = time.time()
        to_remove: list[str] = []
        for sid, rec in self._sessions.items():
            if (
                rec.expires_at is not None and rec.expires_at < now
            ) or _is_session_idle(rec, self._idle_timeout_seconds):
                to_remove.append(sid)
        for sid in to_remove:
            del self._sessions[sid]
        return len(to_remove)


class RedisSessionBackend:
    """Redis-backed session storage for production.

    Uses Redis HASH per session (``araxys:sessions:{session_id}``) and
    a SET per user (``araxys:sessions:user:{user_id}``).

    Requires the ``redis`` extra: ``pip install araxys[redis]``.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        *,
        pool: ConnectionPool | None = None,
        session_ttl_seconds: int = 3600,
        idle_timeout_seconds: int | None = None,
        event_bus: Any = None,
    ) -> None:
        self._pool = pool
        self._session_ttl_seconds = session_ttl_seconds
        self._idle_timeout_seconds = idle_timeout_seconds
        self._event_bus = event_bus
        self._redis: Redis | None = None
        if pool is None and redis_url:
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
        ttl = self._session_ttl_seconds
        mapping = {
            "session_id": session_id,
            "user_id": user_id,
            "jti": jti,
            "created_at": now,
            "metadata": json.dumps(metadata or {}, default=str),
            "expires_at": str(time.time() + ttl),
        }
        if self._pool:
            conn = await self._pool.acquire()
            try:
                pipe = conn.pipeline()
                pipe.hset(self._session_key(session_id), mapping=mapping)
                pipe.expire(self._session_key(session_id), ttl)
                pipe.sadd(self._user_key(user_id), session_id)
                pipe.expire(self._user_key(user_id), ttl)
                await pipe.execute()
                return session_id
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        pipe = self._redis.pipeline()
        pipe.hset(self._session_key(session_id), mapping=mapping)
        pipe.expire(self._session_key(session_id), ttl)
        pipe.sadd(self._user_key(user_id), session_id)
        pipe.expire(self._user_key(user_id), ttl)
        await pipe.execute()
        return session_id

    async def get_session(self, session_id: str) -> SessionRecord | None:
        key = self._session_key(session_id)
        raw: dict[bytes, bytes] | dict[str, str]
        if self._pool:
            conn = await self._pool.acquire()
            try:
                raw = await conn.hgetall(key)  # type: ignore[misc]
            finally:
                await self._pool.release(conn)
        else:
            assert self._redis is not None
            raw = await self._redis.hgetall(key)  # type: ignore[misc]
        if not raw:
            return None
        # Normalize to str keys for consistent access (hgetall can return
        # bytes keys depending on the connection's decode_responses setting).
        data: dict[str, str] = cast("dict[str, str]", raw)
        raw_metadata = data.get("metadata")
        if raw_metadata:
            try:
                metadata: Any = json.loads(raw_metadata)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fallback for old str()-serialized format (single-quoted Python repr)
                metadata = ast.literal_eval(raw_metadata)
        else:
            metadata = {}
        raw_expires = data.get("expires_at")
        expires_at = float(raw_expires) if raw_expires else None
        raw_last_activity = data.get("last_activity_at")
        last_activity_at = (
            datetime.fromisoformat(raw_last_activity)
            if raw_last_activity
            else None
        )
        record = SessionRecord(
            session_id=data["session_id"],
            user_id=data["user_id"],
            jti=data["jti"],
            created_at=datetime.fromisoformat(data["created_at"]),
            metadata=metadata,
            expires_at=expires_at,
            last_activity_at=last_activity_at,
        )
        # Idle timeout check
        if _is_session_idle(record, self._idle_timeout_seconds):
            await _emit_idle_event(self._event_bus, session_id, record)
            return None
        return record

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        ukey = self._user_key(user_id)
        raw_ids: set[bytes] | set[str]
        if self._pool:
            conn = await self._pool.acquire()
            try:
                raw_ids = await conn.smembers(ukey)  # type: ignore[misc]
            finally:
                await self._pool.release(conn)
        else:
            assert self._redis is not None
            raw_ids = await self._redis.smembers(ukey)  # type: ignore[misc]
        if not raw_ids:
            return []
        # Normalize to str IDs (smembers can return bytes or str)
        norm: set[str] = cast("set[str]", raw_ids)
        records: list[SessionRecord] = []
        for sid in norm:
            record = await self.get_session(sid)
            if record is not None:
                records.append(record)
        return records

    async def revoke_session(self, session_id: str) -> bool:
        record = await self.get_session(session_id)
        if record is None:
            return False
        skey = self._session_key(session_id)
        ukey = self._user_key(record.user_id)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                pipe = conn.pipeline()
                pipe.delete(skey)
                pipe.srem(ukey, session_id)
                await pipe.execute()
                return True
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        pipe = self._redis.pipeline()
        pipe.delete(skey)
        pipe.srem(ukey, session_id)
        await pipe.execute()
        return True

    async def count_sessions(self, user_id: str) -> int:
        ukey = self._user_key(user_id)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                count = await conn.scard(ukey)  # type: ignore[misc]
                return count  # type: ignore[no-any-return]
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        count = await self._redis.scard(ukey)  # type: ignore[misc]
        return count  # type: ignore[no-any-return]

    async def revoke_oldest(self, user_id: str) -> str | None:
        records = await self.list_sessions(user_id)
        if not records:
            return None
        oldest = min(records, key=lambda r: r.created_at)
        await self.revoke_session(oldest.session_id)
        return oldest.session_id

    async def refresh_session(self, session_id: str) -> bool:
        record = await self.get_session(session_id)
        if record is None:
            return False
        skey = self._session_key(session_id)
        ukey = self._user_key(record.user_id)
        ttl = self._session_ttl_seconds
        if self._pool:
            conn = await self._pool.acquire()
            try:
                pipe = conn.pipeline()
                pipe.expire(skey, ttl)
                pipe.expire(ukey, ttl)
                await pipe.execute()
                return True
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        pipe = self._redis.pipeline()
        pipe.expire(skey, ttl)
        pipe.expire(ukey, ttl)
        await pipe.execute()
        return True

    async def touch_session(self, session_id: str) -> None:
        record = await self.get_session(session_id)
        if record is None:
            raise SessionNotFound(
                f"Session {session_id} not found"
            )
        now = datetime.now(UTC)
        skey = self._session_key(session_id)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                await conn.hset(  # type: ignore[misc]
                    skey,
                    mapping={"last_activity_at": now.isoformat()},
                )
                return
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        await self._redis.hset(  # type: ignore[misc]
            skey,
            mapping={"last_activity_at": now.isoformat()},
        )

    async def cleanup_expired(self) -> int:
        """Remove expired and idle sessions.

        Primary TTL mechanism is Redis EXPIRE. This scans user SET keys
        and removes members whose session HASH has expired or is idle.
        """
        removed = 0
        cursor = 0
        while True:
            if self._pool:
                conn = await self._pool.acquire()
                try:
                    cursor, keys = await conn.scan(
                        cursor, match="araxys:sessions:user:*", count=100
                    )
                finally:
                    await self._pool.release(conn)
            else:
                assert self._redis is not None
                cursor, keys = await self._redis.scan(
                    cursor, match="araxys:sessions:user:*", count=100
                )
            norm_keys: set[str] = cast("set[str]", keys)
            for ukey in norm_keys:
                members: set[str]
                if self._pool:
                    conn = await self._pool.acquire()
                    try:
                        members = cast("set[str]", await conn.smembers(ukey))  # type: ignore[misc]
                    finally:
                        await self._pool.release(conn)
                else:
                    assert self._redis is not None
                    members = cast("set[str]", await self._redis.smembers(ukey))  # type: ignore[misc]
                for member in members:
                    skey = self._session_key(member)
                    if self._pool:
                        conn = await self._pool.acquire()
                        try:
                            removed += await self._cleanup_one(
                                conn, member, ukey, skey,
                            )
                        finally:
                            await self._pool.release(conn)
                    else:
                        assert self._redis is not None
                        removed += await self._cleanup_one(
                            self._redis, member, ukey, skey,
                        )
            if cursor == 0:
                break
        return removed

    async def _cleanup_one(
        self, conn: Any, member: str, ukey: str, skey: str,
    ) -> int:
        """Check and remove a single session if expired or idle."""
        ttl = await conn.ttl(skey)
        if ttl < 0:
            # Session HASH already gone (TTL expired)
            await conn.srem(ukey, member)
            return 1
        # Check idle timeout
        if self._idle_timeout_seconds is not None and self._idle_timeout_seconds > 0:
            raw = await conn.hgetall(skey)
            if raw:
                data: dict[str, str] = cast("dict[str, str]", raw)
                raw_last = data.get("last_activity_at")
                raw_created = data.get("created_at")
                if raw_created:
                    try:
                        last_activity = (
                            datetime.fromisoformat(raw_last) if raw_last else None
                        )
                        created_at = datetime.fromisoformat(raw_created)
                        effective = last_activity or created_at
                        elapsed = (datetime.now(UTC) - effective).total_seconds()
                        if elapsed > self._idle_timeout_seconds:
                            await conn.delete(skey)
                            await conn.srem(ukey, member)
                            return 1
                    except (ValueError, TypeError):
                        pass
        return 0



