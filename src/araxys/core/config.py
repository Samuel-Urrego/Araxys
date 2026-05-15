from __future__ import annotations

"""Central configuration for all Araxys modules.

Uses Pydantic Settings for env var support:
    ARAXYS_SECRET_KEY=my-secret
    ARAXYS_REDIS_URL=redis://localhost:6379
"""


from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class RateLimitConfig(BaseModel):
    """Configuration for the dynamic rate limiting module."""

    enabled: bool = True
    window_seconds: int = Field(
        default=60, ge=1, description="Sliding window size in seconds"
    )
    max_requests: int = Field(default=100, ge=1, description="Max requests per window")
    ban_threshold: int = Field(
        default=5,
        ge=1,
        description="Number of limit violations before temporary ban",
    )
    ban_duration_seconds: int = Field(
        default=300,
        ge=1,
        description="Temporary ban duration in seconds",
    )
    escalation_multiplier: float = Field(
        default=2.0,
        ge=1.0,
        description="Multiplier applied to ban duration on repeated violations",
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["/docs", "/redoc", "/openapi.json", "/healthz"],
        description="Paths excluded from rate limiting",
    )


class HoneypotConfig(BaseModel):
    """Configuration for the honeypot trap endpoints."""

    enabled: bool = True
    paths: list[str] = Field(
        default_factory=lambda: [
            "/admin/config",
            "/wp-admin",
            "/wp-login.php",
            "/.env",
            "/.git/config",
            "/phpmyadmin",
            "/server-status",
        ],
        description="Fake paths that trigger an automatic IP ban",
    )
    ban_duration_seconds: int = Field(
        default=3600,
        ge=1,
        description="How long a honeypot-triggered IP stays banned",
    )
    fake_response_code: int = Field(
        default=200,
        description="HTTP status code returned to the bot (200 to not alert it)",
    )


class JWTConfig(BaseModel):
    """Configuration for JWT token management."""

    algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    access_token_ttl_minutes: int = Field(
        default=30,
        ge=1,
        description="Access token time-to-live in minutes",
    )
    refresh_token_ttl_days: int = Field(
        default=7,
        ge=1,
        description="Refresh token time-to-live in days",
    )
    issuer: str | None = Field(default=None, description="JWT 'iss' claim")
    audience: str | None = Field(default=None, description="JWT 'aud' claim")


class SecureHeadersConfig(BaseModel):
    """Configuration for security headers middleware."""

    enabled: bool = True
    hsts_max_age: int = Field(
        default=31_536_000, description="HSTS max-age in seconds (1 year)"
    )
    hsts_include_subdomains: bool = True
    frame_options: str = Field(default="DENY", description="X-Frame-Options value")
    content_type_nosniff: bool = True
    referrer_policy: str = Field(
        default="strict-origin-when-cross-origin",
        description="Referrer-Policy header value",
    )
    content_security_policy: str | None = Field(
        default=None,
        description="CSP header value (None = not set)",
    )
    permissions_policy: str | None = Field(
        default=None,
        description="Permissions-Policy header value",
    )


class SanitizeConfig(BaseModel):
    """Configuration for automatic payload sanitization."""

    enabled: bool = True
    block_sqli: bool = Field(default=True, description="Block SQL injection attempts")
    strip_xss: bool = Field(default=True, description="Strip XSS payloads")
    max_depth: int = Field(
        default=10,
        ge=1,
        description="Max recursion depth for nested payload scanning",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Paths excluded from sanitization (e.g. file upload endpoints)",
    )


class AuditConfig(BaseModel):
    """Configuration for encrypted audit logging."""

    enabled: bool = True
    encrypt: bool = Field(
        default=True, description="Encrypt log entries with AES-256-GCM"
    )
    log_file: str | None = Field(
        default=None,
        description="File path for audit log output (None = stdout only)",
    )


class AraxysConfig(BaseSettings):
    """Master configuration for the Araxys security shield.

    All settings can be overridden via environment variables with the
    ``ARAXYS_`` prefix, e.g. ``ARAXYS_SECRET_KEY``.
    """

    model_config = {"env_prefix": "ARAXYS_", "case_sensitive": False}

    secret_key: str = Field(
        ...,
        min_length=32,
        description="Master secret key — used for JWT signing and audit encryption",
    )
    redis_url: str | None = Field(
        default=None,
        description="Redis connection URL. If None, in-memory backends are used.",
    )

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    honeypot: HoneypotConfig = Field(default_factory=HoneypotConfig)
    jwt: JWTConfig = Field(default_factory=JWTConfig)
    secure_headers: SecureHeadersConfig = Field(default_factory=SecureHeadersConfig)
    sanitize: SanitizeConfig = Field(default_factory=SanitizeConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
