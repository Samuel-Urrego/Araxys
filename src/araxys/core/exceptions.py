from __future__ import annotations

"""Custom exceptions for all Araxys modules."""


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
