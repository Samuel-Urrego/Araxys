"""Tests for core types, exceptions, and related infrastructure."""

from datetime import UTC, datetime

from araxys.core.exceptions import (
    AraxysError,
    BruteForceLockedError,
    ConnectionError,
    CSRFValidationError,
    IPBlockedError,
    MalwareDetectionError,
    PasswordValidationError,
    TLSConfigurationError,
)
from araxys.core.types import AuditEventType, SecurityEvent, SecurityEventType


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
            "session_idle_timeout",
            "token_rotated",
            "sanitize_blocked",
            "audit_tamper_detected",
            # v0.9 — WebSocket events
            "ws.connect",
            "ws.disconnect",
            "ws.violation",
            "ws.auth_failed",
            "ws.channel_unauthorized",
            "ws.rate_exceeded",
            # v0.13 — XXE Protection
            "xxe_detected",
        }
        assert values == expected

    def test_is_str_enum(self) -> None:
        assert SecurityEventType.RATE_LIMIT_EXCEEDED.value == "rate_limit_exceeded"
        assert SecurityEventType.IP_BLOCKED.value == "ip_blocked"
        assert (
            SecurityEventType.CSRF_VALIDATION_FAILED.value == "csrf_validation_failed"
        )


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


class TestDatabaseSecurityExceptions:
    """ConnectionError and TLSConfigurationError (v0.5 db_security)."""

    def test_connection_error_is_araxys_error(self) -> None:
        exc = ConnectionError()
        assert isinstance(exc, AraxysError)

    def test_connection_error_default_message(self) -> None:
        exc = ConnectionError()
        assert "Database connection error" in str(exc)

    def test_connection_error_custom_message(self) -> None:
        exc = ConnectionError(message="Redis is unreachable")
        assert "Redis is unreachable" in str(exc)

    def test_tls_configuration_error_is_araxys_error(self) -> None:
        exc = TLSConfigurationError()
        assert isinstance(exc, AraxysError)

    def test_tls_configuration_error_default_message(self) -> None:
        exc = TLSConfigurationError()
        assert "TLS configuration error" in str(exc)

    def test_tls_configuration_error_custom_message(self) -> None:
        exc = TLSConfigurationError(message="Invalid min TLS version")
        assert "Invalid min TLS version" in str(exc)

    def test_configuration_error_is_araxys_error(self) -> None:
        from araxys.core.exceptions import ConfigurationError

        exc = ConfigurationError()
        assert isinstance(exc, AraxysError)

    def test_configuration_error_default_message(self) -> None:
        from araxys.core.exceptions import ConfigurationError

        exc = ConfigurationError()
        assert "Configuration error" in str(exc)

    def test_configuration_error_custom_message(self) -> None:
        from araxys.core.exceptions import ConfigurationError

        exc = ConfigurationError(message="sentinels and master_name required")
        assert "sentinels and master_name required" in str(exc)

    def test_configuration_error_hierarchy(self) -> None:
        from araxys.core.exceptions import ConfigurationError

        assert issubclass(ConfigurationError, AraxysError)

    def test_exception_hierarchy(self) -> None:
        assert issubclass(ConnectionError, AraxysError)
        assert issubclass(TLSConfigurationError, AraxysError)


class TestAuditEventType:
    """AuditEventType enum — verify QUERY_EXECUTED is present."""

    def test_query_executed_exists(self) -> None:
        assert hasattr(AuditEventType, "QUERY_EXECUTED")
        assert AuditEventType.QUERY_EXECUTED.value == "query_executed"

    def test_all_values_present(self) -> None:
        values = {e.value for e in AuditEventType}
        expected = {
            "login_success",
            "login_failed",
            "rate_limited",
            "honeypot_triggered",
            "api_key_created",
            "api_key_revoked",
            "api_key_verified",
            "api_key_rejected",
            "token_rotated",
            "token_revoked",
            "sanitization_blocked",
            "ip_banned",
            "ip_unbanned",
            "query_executed",
            # v0.9 — WebSocket events
            "ws.connect",
            "ws.disconnect",
            "ws.violation",
            "ws.auth_failed",
            # v0.13 — XXE Protection
            "xxe_detected",
        }
        assert values == expected


class TestMalwareDetectionError:
    """MalwareDetectionError exception — added in v0.8."""

    def test_all_fields(self) -> None:
        exc = MalwareDetectionError(
            detector_name="magic_bytes",
            filename="evil.jpg",
            threat_description="Magic bytes mismatch",
        )
        assert exc.detector_name == "magic_bytes"
        assert exc.filename == "evil.jpg"
        assert exc.threat_description == "Magic bytes mismatch"
        assert isinstance(exc.details, dict)

    def test_filename_none(self) -> None:
        exc = MalwareDetectionError(
            detector_name="zip_bomb",
            filename=None,
            threat_description="Archive bomb detected",
        )
        assert exc.filename is None

    def test_default_message(self) -> None:
        exc = MalwareDetectionError(
            detector_name="double_ext",
            filename="file.pdf.exe",
            threat_description="Double extension detected",
        )
        assert "Malware detected" in str(exc)
        assert "double_ext" in str(exc)

    def test_is_araxys_error(self) -> None:
        exc = MalwareDetectionError(
            detector_name="test",
            filename=None,
            threat_description="test threat",
        )
        assert isinstance(exc, AraxysError)

    def test_details_dict(self) -> None:
        exc = MalwareDetectionError(
            detector_name="test",
            filename="doc.exe",
            threat_description="test",
            details={"extra": "info"},
        )
        assert exc.details == {"extra": "info"}

    def test_exception_hierarchy(self) -> None:
        assert issubclass(MalwareDetectionError, AraxysError)
