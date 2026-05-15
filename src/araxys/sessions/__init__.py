"""Session management — track, list, and revoke user sessions.

Provides session backends (InMemory + Redis) and a SessionManager
that enforces max concurrent sessions and emits security events.
"""

from araxys.sessions.manager import SessionManager
from araxys.sessions.storage import (
    InMemorySessionBackend,
    RedisSessionBackend,
    SessionBackend,
    SessionRecord,
)

__all__ = [
    "InMemorySessionBackend",
    "RedisSessionBackend",
    "SessionBackend",
    "SessionManager",
    "SessionRecord",
]
