"""Central configuration for all Araxys modules.

Uses Pydantic Settings for env var support:
    ARAXYS_SECRET_KEY=my-secret
    ARAXYS_REDIS_URL=redis://localhost:6379
"""


from __future__ import annotations

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
    per_user: bool = Field(
        default=False,
        description="Enable per-user rate limiting (uses SecurityContext)",
    )
    per_api_key: bool = Field(
        default=False,
        description="Enable per-API-key rate limiting",
    )
    path_limits: dict[str, RateLimitConfig] = Field(
        default_factory=dict,
        description="Per-endpoint limits (key = path pattern like '/auth/login')",
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

    algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (HS256, RS256, ES256)",
    )
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
    private_key: str | None = Field(
        default=None,
        description="PEM string or file path for RS256/ES256 signing",
    )
    public_key: str | None = Field(
        default=None,
        description="PEM string or file path for RS256/ES256 verification",
    )
    jwks_enabled: bool = Field(
        default=False,
        description="Enable JWKS endpoint generation from public key",
    )


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
    coop: str = Field(
        default="same-origin",
        description="Cross-Origin-Opener-Policy header value",
    )
    coep: str | None = Field(
        default=None,
        description="Cross-Origin-Embedder-Policy header value (e.g. 'require-corp')",
    )
    corp: str = Field(
        default="same-origin",
        description="Cross-Origin-Resource-Policy header value",
    )
    hide_server: bool = Field(
        default=True,
        description="Strip Server header from responses",
    )
    csp_directives: dict[str, str] = Field(
        default_factory=dict,
        description="Raw CSP directives as directive-name -> value pairs",
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
    scan_query_params: bool = Field(
        default=False,
        description="Scan HTTP query parameters for injection patterns",
    )
    scan_headers: bool = Field(
        default=False,
        description="Scan HTTP headers for injection patterns",
    )
    check_nosql_injection: bool = Field(
        default=False,
        description="Check for NoSQL injection patterns ($where, $gt, etc.)",
    )
    check_command_injection: bool = Field(
        default=False,
        description="Check for OS command injection patterns",
    )
    check_path_traversal: bool = Field(
        default=False,
        description="Check for path traversal patterns (../, %00, etc.)",
    )


class LogShippingConfig(BaseModel):
    """Configuration for shipping audit logs to an external endpoint."""

    type: str = Field(
        default="http",
        description="Shipping protocol: 'http' or 'syslog'",
    )
    endpoint: str = Field(
        default="",
        description="Target endpoint URL (e.g. https://logs.example.com/ingest)",
    )
    headers: dict[str, str] | None = Field(
        default=None,
        description="HTTP headers to include in shipping requests",
    )
    tls_enabled: bool = Field(
        default=True,
        description="Enable TLS for the shipping connection",
    )


class CSPDirectiveConfig(BaseModel):
    """Per-directive configuration for building Content-Security-Policy headers."""

    default_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="default-src directive values",
    )
    script_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="script-src directive values",
    )
    style_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="style-src directive values",
    )
    img_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="img-src directive values",
    )
    connect_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="connect-src directive values",
    )
    font_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="font-src directive values",
    )
    object_src: list[str] = Field(
        default_factory=lambda: ["'none'"],
        description="object-src directive values",
    )
    frame_src: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="frame-src directive values",
    )
    report_uri: str | None = Field(
        default=None,
        description="report-uri for CSP violation reports",
    )
    upgrade_insecure_requests: bool = Field(
        default=False,
        description="Add upgrade-insecure-requests directive",
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
    log_rotation_bytes: int = Field(
        default=0,
        ge=0,
        description="Max bytes before log rotation (0 = disabled)",
    )
    log_backup_count: int = Field(
        default=5,
        ge=0,
        description="Number of backup files to keep",
    )
    async_write: bool = Field(
        default=False,
        description="Use aiofiles for non-blocking log writes",
    )
    pii_fields: list[str] = Field(
        default_factory=list,
        description="Field names to mask in audit logs (e.g. email, password)",
    )
    log_shipping: LogShippingConfig | None = Field(
        default=None,
        description="Optional log shipping configuration",
    )


class CORSConfig(BaseModel):
    """Configuration for CORS policy management."""

    allow_origins: list[str] = Field(
        default_factory=list,
        description="Allowed origins (empty = deny all = fail-closed)",
    )
    allow_methods: list[str] = Field(
        default_factory=lambda: ["GET"],
        description="Allowed HTTP methods",
    )
    allow_headers: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed request headers",
    )
    allow_credentials: bool = Field(
        default=False,
        description="Include Access-Control-Allow-Credentials",
    )
    expose_headers: list[str] = Field(
        default_factory=list,
        description="Headers exposed to the client",
    )
    max_age: int = Field(
        default=600,
        ge=0,
        description="Preflight cache duration in seconds",
    )


class IPControlConfig(BaseModel):
    """Configuration for IP Access Control."""

    enabled: bool = False
    mode: str = Field(
        default="block",
        description="Access mode: allow (default-deny), block (default-allow), hybrid",
    )
    allowlist: list[str] = Field(
        default_factory=list,
        description="IPs/CIDRs always allowed",
    )
    blocklist: list[str] = Field(
        default_factory=list,
        description="IPs/CIDRs always blocked",
    )
    redis_url: str | None = Field(
        default=None,
        description="Redis URL for dynamic rule storage (None = in-memory)",
    )


class BruteForceConfig(BaseModel):
    """Configuration for brute force protection."""

    enabled: bool = False
    max_attempts: int = Field(
        default=5,
        ge=1,
        description="Consecutive failures before lockout",
    )
    lockout_duration_seconds: int = Field(
        default=900,
        ge=1,
        description="Lockout duration in seconds (default 15 min)",
    )
    identifier_field: str = Field(
        default="username",
        description="Request field used as lockout identifier",
    )
    check_hibp: bool = Field(
        default=False,
        description="Check password against HaveIBeenPwned API",
    )


class CSRFConfig(BaseModel):
    """Configuration for CSRF double-submit cookie protection."""

    enabled: bool = False
    token_expiry_seconds: int = Field(
        default=3600,
        ge=1,
        description="CSRF token time-to-live in seconds (default 1 hour)",
    )
    cookie_name: str = Field(
        default="csrf_token",
        description="Name of the CSRF cookie",
    )
    header_name: str = Field(
        default="X-CSRF-Token",
        description="Name of the CSRF header",
    )
    secure_cookie: bool = Field(
        default=True,
        description="Set Secure flag on CSRF cookie",
    )


class SessionConfig(BaseModel):
    """Configuration for session management."""

    enabled: bool = False
    max_concurrent_per_user: int = Field(
        default=5,
        ge=1,
        description="Maximum concurrent sessions per user",
    )
    cleanup_interval_seconds: int = Field(
        default=60,
        ge=1,
        description="Interval between expired session cleanup runs",
    )
    redis_url: str | None = Field(
        default=None,
        description="Redis URL for session storage (None = in-memory)",
    )


class WebhookConfig(BaseModel):
    """Configuration for security event webhook delivery."""

    enabled: bool = False
    urls: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Map of event_type -> list of webhook URLs",
    )
    retry_max: int = Field(
        default=3,
        ge=0,
        description="Maximum retry attempts on delivery failure",
    )
    timeout_seconds: int = Field(
        default=5,
        ge=1,
        description="HTTP request timeout in seconds",
    )
    queue_size: int = Field(
        default=1000,
        ge=1,
        description="Maximum pending events in the async queue",
    )


class MetricsConfig(BaseModel):
    """Configuration for Prometheus metrics export."""

    enabled: bool = False
    path: str = Field(
        default="/metrics",
        description="Path for the Prometheus metrics endpoint",
    )


class TelemetryConfig(BaseModel):
    """Configuration for OpenTelemetry distributed tracing."""

    enabled: bool = False
    service_name: str = Field(
        default="araxys",
        description="Service name reported to OTLP exporter",
    )
    exporter_endpoint: str | None = Field(
        default=None,
        description="OTLP gRPC/HTTP exporter endpoint",
    )
    sample_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Trace sample rate (0.0 = never, 1.0 = always)",
    )


class AraxysConfig(BaseSettings):
    """Master configuration for the Araxys security shield.

    All settings can be overridden via environment variables with the
    ``ARAXYS_`` prefix, e.g. ``ARAXYS_SECRET_KEY``.
    """

    model_config = {
        "env_prefix": "ARAXYS_",
        "case_sensitive": False,
        "env_nested_delimiter": "__",
    }

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
    # v0.3 modules — optional, enabled via sub-config
    cors: CORSConfig = Field(default_factory=CORSConfig)
    ip_control: IPControlConfig | None = Field(default=None)
    brute_force: BruteForceConfig | None = Field(default=None)
    csrf: CSRFConfig | None = Field(default=None)
    session: SessionConfig | None = Field(default=None)
    webhooks: WebhookConfig | None = Field(default=None)
    metrics: MetricsConfig | None = Field(default=None)
    telemetry: TelemetryConfig | None = Field(default=None)
