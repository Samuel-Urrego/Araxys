"""Araxys — Plug & play security library for FastAPI.

Usage::

    from fastapi import FastAPI
    from araxys import AraxysShield, AraxysConfig

    app = FastAPI()
    shield = AraxysShield(
        app,
        AraxysConfig(secret_key="your-32-char-secret-key-here!!!!"),
    )
"""

from araxys.core.config import (
    AraxysConfig,
    AuditConfig,
    HoneypotConfig,
    JWTConfig,
    RateLimitConfig,
    SanitizeConfig,
    SecureHeadersConfig,
)
from araxys.core.exceptions import (
    AraxysError,
    EncryptionError,
    HoneypotTriggered,
    InvalidAPIKey,
    RateLimitExceeded,
    SanitizationError,
    TokenExpired,
    TokenInvalid,
    TokenRevoked,
)
from araxys.core.types import AuditEntry, AuditEventType, Scope, SecurityContext
from araxys.shield import AraxysShield

__all__ = [
    # Main entry point
    "AraxysShield",
    # Configuration
    "AraxysConfig",
    "AuditConfig",
    "HoneypotConfig",
    "JWTConfig",
    "RateLimitConfig",
    "SanitizeConfig",
    "SecureHeadersConfig",
    # Types
    "AuditEntry",
    "AuditEventType",
    "Scope",
    "SecurityContext",
    # Exceptions
    "AraxysError",
    "EncryptionError",
    "HoneypotTriggered",
    "InvalidAPIKey",
    "RateLimitExceeded",
    "SanitizationError",
    "TokenExpired",
    "TokenInvalid",
    "TokenRevoked",
]
