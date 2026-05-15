"""Tests for core types, exceptions, and related infrastructure."""

from datetime import UTC, datetime

from araxys.core.exceptions import (
    AraxysError,
    BruteForceLockedError,
    CSRFValidationError,
    IPBlockedError,
    PasswordValidationError,
)
from araxys.core.types import SecurityEvent, SecurityEventType


class TestSecurityEventType:
    """SecurityEventType enum — must match spec exactly."""

    def test_all_values_present(self) -> None:
        values = {e.value for e in SecurityEventType}
        expected = {
            "rate_limit_exceeded",
            "honeypot_triggered",
            "ip_blocked",
            "ip_allowed",
            "csrf_validation_failed",
            "brute_force_lockout",
            "password_validation_failed",
            "session_created",
            "session_revoked",
            "token_rotated",
            "sanitize_blocked",
            "audit_tamper_detected",
        }
        assert values == expected

    def test_is_str_enum(self) -> None:
        assert SecurityEventType.RATE_LIMIT_EXCEEDED == "rate_limit_exceeded"
        assert SecurityEventType.IP_BLOCKED == "ip_blocked"
        assert SecurityEventType.CSRF_VALIDATION_FAILED == "csrf_validation_failed"


class TestSecurityEvent:
    """SecurityEvent dataclass — instantiation and field behavior."""

    def test_full_instantiation(self) -> None:
        ts = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
        event = SecurityEvent(
            event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
            severity="warning",
            timestamp=ts,
            source_ip="192.168.1.1",
            metadata={"attempts": 12},
            message="Rate limit exceeded for 192.168.1.1",
        )
        assert event.event_type == SecurityEventType.RATE_LIMIT_EXCEEDED
        assert event.severity == "warning"
        assert event.timestamp == ts
        assert event.source_ip == "192.168.1.1"
        assert event.metadata == {"attempts": 12}
        assert event.message == "Rate limit exceeded for 192.168.1.1"

    def test_minimal_instantiation(self) -> None:
        """Only required fields — defaults for the rest."""
        event = SecurityEvent(
            event_type=SecurityEventType.HONEYPOT_TRIGGERED,
            severity="critical",
            message="Honeypot triggered",
        )
        assert event.event_type == SecurityEventType.HONEYPOT_TRIGGERED
        assert event.severity == "critical"
        assert isinstance(event.timestamp, datetime)
        assert event.timestamp.tzinfo is not None  # timezone-aware
        assert event.source_ip is None
        assert event.metadata == {}

    def test_default_timestamp_is_utc(self) -> None:
        event = SecurityEvent(
            event_type=SecurityEventType.IP_BLOCKED,
            severity="info",
            message="test",
        )
        now = datetime.now(UTC)
        diff = abs((now - event.timestamp).total_seconds())
        assert diff < 2  # within 2 seconds — recent enough
        assert event.timestamp.tzinfo is UTC


class TestNewExceptions:
    """New exception classes added in v0.3."""

    def test_csrf_validation_error(self) -> None:
        exc = CSRFValidationError()
        assert isinstance(exc, AraxysError)
        assert "CSRF" in str(exc)

    def test_csrf_validation_error_custom_message(self) -> None:
        exc = CSRFValidationError(reason="Token mismatch")
        assert "Token mismatch" in str(exc)

    def test_brute_force_locked_error(self) -> None:
        exc = BruteForceLockedError(identifier="admin", retry_after=900)
        assert isinstance(exc, AraxysError)
        assert exc.identifier == "admin"
        assert exc.retry_after == 900
        assert "admin" in str(exc)
        assert "900" in str(exc)

    def test_password_validation_error(self) -> None:
        exc = PasswordValidationError(
            failures=["Too short", "Missing uppercase", "Missing digit"]
        )
        assert isinstance(exc, AraxysError)
        assert exc.failures == ["Too short", "Missing uppercase", "Missing digit"]
        assert "Too short" in str(exc)

    def test_password_validation_error_empty(self) -> None:
        exc = PasswordValidationError(failures=[])
        assert isinstance(exc, AraxysError)
        assert exc.failures == []

    def test_ip_blocked_error(self) -> None:
        exc = IPBlockedError(ip_address="10.0.0.5")
        assert isinstance(exc, AraxysError)
        assert exc.ip_address == "10.0.0.5"
        assert "10.0.0.5" in str(exc)

    def test_ip_blocked_error_default_message(self) -> None:
        exc = IPBlockedError(ip_address="192.168.1.1")
        assert "IP blocked" in str(exc)

    def test_exception_hierarchy(self) -> None:
        """All new exceptions inherit from AraxysError."""
        assert issubclass(CSRFValidationError, AraxysError)
        assert issubclass(BruteForceLockedError, AraxysError)
        assert issubclass(PasswordValidationError, AraxysError)
        assert issubclass(IPBlockedError, AraxysError)
