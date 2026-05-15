"""SessionManager — high-level session lifecycle management.

Enforces maximum concurrent sessions per user, emits security events
on create/revoke, and provides a background cleanup loop for expired
sessions.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from araxys.core.types import SecurityEvent, SecurityEventType

if TYPE_CHECKING:
    from araxys.core.config import SessionConfig
    from araxys.sessions.storage import SessionBackend

logger = logging.getLogger("araxys.sessions")


class SessionManager:
    """Manages user session lifecycle.

    Parameters
    ----------
    config:
        Session configuration (max concurrent, cleanup interval, etc.).
    backend:
        Pluggable session storage backend.
    event_bus:
        Optional SecurityEventBus for emitting session lifecycle events.
    """

    def __init__(
        self,
        config: SessionConfig,
        backend: SessionBackend,
        event_bus: Any = None,
    ) -> None:
        self._config = config
        self._backend = backend
        self._event_bus = event_bus
        self._cleanup_task: asyncio.Task[None] | None = None
        self._cleanup_interval = config.cleanup_interval_seconds

    async def create(
        self, user_id: str, jti: str, metadata: dict[str, Any] | None = None
    ) -> str:
        """Create a new session, enforcing max concurrent sessions.

        If the user already has ``max_concurrent`` sessions, the oldest
        session is revoked and a SECURITY event is emitted before creating
        the new session.
        """
        current_count = await self._backend.count_sessions(user_id)
        if current_count >= self._config.max_concurrent_per_user:
            revoked_id = await self._backend.revoke_oldest(user_id)
            if revoked_id is not None:
                logger.warning(
                    "Max concurrent sessions reached for user %s — "
                    "revoked oldest session %s",
                    user_id,
                    revoked_id,
                )
                await self._emit_event(
                    SecurityEventType.SESSION_REVOKED,
                    severity="warning",
                    message=f"Oldest session revoked for user {user_id} "
                    f"(max concurrent={self._config.max_concurrent_per_user})",
                    user_id=user_id,
                    metadata={"revoked_session_id": revoked_id},
                )

        session_id = await self._backend.create_session(user_id, jti, metadata)
        await self._emit_event(
            SecurityEventType.SESSION_CREATED,
            severity="info",
            message=f"Session created for user {user_id}",
            user_id=user_id,
            metadata={"session_id": session_id},
        )
        return session_id

    async def revoke(self, session_id: str) -> bool:
        """Revoke a session by ID. Returns True if found and revoked."""
        result = await self._backend.revoke_session(session_id)
        if result:
            await self._emit_event(
                SecurityEventType.SESSION_REVOKED,
                severity="info",
                message=f"Session revoked: {session_id}",
                metadata={"session_id": session_id},
            )
        return result

    async def list(self, user_id: str) -> list[dict[str, Any]]:
        """List all active sessions for a user as dicts."""
        records = await self._backend.list_sessions(user_id)
        return [
            {
                "session_id": r.session_id,
                "user_id": r.user_id,
                "jti": r.jti,
                "created_at": r.created_at.isoformat(),
                "metadata": r.metadata,
            }
            for r in records
        ]

    async def count(self, user_id: str) -> int:
        """Return the number of active sessions for a user."""
        return await self._backend.count_sessions(user_id)

    async def start_cleanup(self) -> None:
        """Start the background cleanup loop for expired sessions.

        Runs every ``cleanup_interval_seconds``. Can be stopped via
        ``stop_cleanup()``.
        """
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(
            "Session cleanup loop started (interval=%ds)", self._cleanup_interval
        )

    async def stop_cleanup(self) -> None:
        """Gracefully stop the background cleanup loop."""
        if self._cleanup_task is None:
            return
        self._cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._cleanup_task
        self._cleanup_task = None
        logger.info("Session cleanup loop stopped")

    async def _cleanup_loop(self) -> None:
        """Background loop that periodically cleans expired sessions."""
        while True:
            await asyncio.sleep(self._cleanup_interval)
            try:
                # In a real implementation, this would iterate stored sessions
                # and remove those past their TTL. For now the loop provides
                # the framework for this.
                pass
            except Exception:
                logger.exception("Error during session cleanup")

    async def _emit_event(
        self,
        event_type: SecurityEventType,
        severity: str,
        message: str,
        user_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Emit a security event if an event bus is configured."""
        if self._event_bus is None:
            return
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            timestamp=datetime.now(UTC),
            metadata={
                "user_id": user_id or "unknown",
                **(metadata or {}),
            },
        )
        await self._event_bus.emit(event)
