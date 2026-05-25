"""Custom exceptions for all Araxys modules."""


from __future__ import annotations

from typing import Any


class AraxysError(Exception):
    """Base exception for all Araxys errors."""

    def __init__(self, message: str = "An Araxys security error occurred") -> None:
        self.message = message
        super().__init__(self.message)


class RateLimitExceeded(AraxysError):
    """Raised when a client exceeds the rate limit threshold."""

    def __init__(
        self,
        ip_address: str,
        retry_after: int,
        *,
        message: str | None = None,
    ) -> None:
        self.ip_address = ip_address
        self.retry_after = retry_after
        super().__init__(
            message
            or f"Rate limit exceeded for {ip_address}. Retry after {retry_after}s."
        )


class HoneypotTriggered(AraxysError):
    """Raised when a client accesses a honeypot endpoint."""

    def __init__(self, ip_address: str, path: str) -> None:
        self.ip_address = ip_address
        self.path = path
        super().__init__(f"Honeypot triggered by {ip_address} on {path}")


class InvalidAPIKey(AraxysError):
    """Raised when an API key is invalid, expired, or lacks required scopes."""

    def __init__(self, reason: str = "Invalid API key") -> None:
        self.reason = reason
        super().__init__(reason)


class TokenExpired(AraxysError):
    """Raised when a JWT token has expired."""

    def __init__(self, token_type: str = "access") -> None:
        self.token_type = token_type
        super().__init__(f"{token_type.capitalize()} token has expired")


class TokenInvalid(AraxysError):
    """Raised when a JWT token is malformed or has an invalid signature."""

    def __init__(self, reason: str = "Invalid token") -> None:
        self.reason = reason
        super().__init__(reason)


class TokenRevoked(AraxysError):
    """Raised when a revoked refresh token is used (potential token theft)."""

    def __init__(self) -> None:
        super().__init__("Token has been revoked — possible token theft detected")


class SanitizationError(AraxysError):
    """Raised when a payload contains malicious content."""

    def __init__(self, threat_type: str, value_preview: str = "") -> None:
        self.threat_type = threat_type
        self.value_preview = value_preview
        super().__init__(f"Malicious {threat_type} detected in payload")


class EncryptionError(AraxysError):
    """Raised when audit log encryption or decryption fails."""

    def __init__(self, operation: str = "encryption") -> None:
        self.operation = operation
        super().__init__(f"Audit log {operation} failed")


class CSRFValidationError(AraxysError):
    """Raised when CSRF token validation fails."""

    def __init__(self, reason: str = "CSRF validation failed") -> None:
        self.reason = reason
        super().__init__(reason)


class BruteForceLockedError(AraxysError):
    """Raised when a client is locked out due to too many failed attempts."""

    def __init__(
        self,
        identifier: str,
        retry_after: int,
        *,
        message: str | None = None,
    ) -> None:
        self.identifier = identifier
        self.retry_after = retry_after
        super().__init__(
            message
            or f"Account locked for {identifier}. Retry after {retry_after}s."
        )


class PasswordValidationError(AraxysError):
    """Raised when a password fails validation rules."""

    def __init__(self, failures: list[str]) -> None:
        self.failures = failures
        joined = "; ".join(failures) if failures else "Password validation failed"
        super().__init__(f"Password validation failed: {joined}")


class IPBlockedError(AraxysError):
    """Raised when a request is blocked by IP Access Control."""

    def __init__(
        self,
        ip_address: str,
        *,
        message: str | None = None,
    ) -> None:
        self.ip_address = ip_address
        super().__init__(message or f"IP blocked: {ip_address}")


class ConfigurationError(AraxysError):
    """Raised when a configuration value is invalid or incomplete."""

    def __init__(self, message: str = "Configuration error") -> None:
        super().__init__(message)


class ConnectionError(AraxysError):
    """Raised when a database connection cannot be established or pool is exhausted."""

    def __init__(self, message: str = "Database connection error") -> None:
        super().__init__(message)


class TLSConfigurationError(AraxysError):
    """Raised when TLS configuration is invalid or cannot be applied."""

    def __init__(self, message: str = "TLS configuration error") -> None:
        super().__init__(message)


class ValidationError(AraxysError):
    """Raised when validation of a query or input fails."""

    def __init__(self, message: str = "Validation error") -> None:
        super().__init__(message)


class PromptInjectionError(AraxysError):
    """Raised when a prompt injection attack is detected by a detector."""

    def __init__(
        self,
        detector_name: str,
        matched_pattern: str | None = None,
        threat_score: float = 0.0,
    ) -> None:
        self.detector_name = detector_name
        self.matched_pattern = matched_pattern
        self.threat_score = threat_score
        super().__init__(
            f"Prompt injection detected by {detector_name}"
            + (f": {matched_pattern}" if matched_pattern else "")
        )


class MalwareDetectionError(AraxysError):
    """Raised when a heuristic malware detector flags a file.

    Attributes
    ----------
    detector_name:
        Name of the detector that flagged the file.
    filename:
        The uploaded filename, if available.
    threat_description:
        Human-readable description of the threat.
    details:
        Optional structured details about the detection.
    """

    def __init__(
        self,
        detector_name: str,
        filename: str | None,
        threat_description: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.detector_name = detector_name
        self.filename = filename
        self.threat_description = threat_description
        self.details = details or {}
        super().__init__(
            f"Malware detected by {detector_name}"
            + (f" on {filename}" if filename else "")
            + f": {threat_description}"
        )


# Re-export WebAuthnError for public API convenience.
# Import is here (not at top) to avoid circular imports since
# webauthn.exceptions itself imports AraxysError from this module.
from araxys.webauthn.exceptions import (  # noqa: E402, F401
    WebAuthnError,
)
