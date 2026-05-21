"""Core types shared across all Araxys modules."""


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Scope(StrEnum):
    """Permission scopes for API keys and JWT tokens."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class AuditEventType(StrEnum):
    """Types of security events tracked by the audit system."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    RATE_LIMITED = "rate_limited"
    HONEYPOT_TRIGGERED = "honeypot_triggered"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_VERIFIED = "api_key_verified"
    API_KEY_REJECTED = "api_key_rejected"
    TOKEN_ROTATED = "token_rotated"
    TOKEN_REVOKED = "token_revoked"
    SANITIZATION_BLOCKED = "sanitization_blocked"
    IP_BANNED = "ip_banned"
    IP_UNBANNED = "ip_unbanned"
    QUERY_EXECUTED = "query_executed"


class SecurityEventType(StrEnum):
    """Types of security events emitted by Araxys modules.

    Shared across all v0.3 modules for webhooks, metrics, and audit.
    """

    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    HONEYPOT_TRIGGERED = "honeypot_triggered"
    IP_BLOCKED = "ip_blocked"
    IP_ALLOWED = "ip_allowed"
    CSRF_VALIDATION_FAILED = "csrf_validation_failed"
    BRUTE_FORCE_LOCKOUT = "brute_force_lockout"
    PASSWORD_VALIDATION_FAILED = "password_validation_failed"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    TOKEN_ROTATED = "token_rotated"
    SANITIZE_BLOCKED = "sanitize_blocked"
    AUDIT_TAMPER_DETECTED = "audit_tamper_detected"
    SESSION_IDLE_TIMEOUT = "session_idle_timeout"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Immutable security event emitted by Araxys modules.

    Consumed by the event bus for webhook delivery and metrics.
    """

    event_type: SecurityEventType
    severity: str  # "info" | "warning" | "critical"
    message: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_ip: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """Immutable record of a security event."""

    event_type: AuditEventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    ip_address: str | None = None
    user_id: str | None = None
    api_key_prefix: str | None = None
    resource: str | None = None
    action: str | None = None
    detail: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Request-scoped security context available to handlers."""

    ip_address: str
    is_authenticated: bool = False
    user_id: str | None = None
    scopes: tuple[Scope, ...] = ()
    api_key_prefix: str | None = None
    auth_method: str | None = None  # "jwt" | "api_key" | None
