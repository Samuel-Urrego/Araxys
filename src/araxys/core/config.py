"""Central configuration for all Araxys modules.

Uses Pydantic Settings for env var support:
    ARAXYS_SECRET_KEY=my-secret
    ARAXYS_REDIS_URL=redis://localhost:6379
"""


from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings

from araxys.core.exceptions import ConfigurationError
from araxys.websocket.config import WebSocketConfig  # noqa: TC001
from araxys.xxe.config import XXEConfig  # noqa: TC001


class RateLimitConfig(BaseModel):
    """Configuration for the dynamic rate limiting module."""

    enabled: bool = True
    algorithm: Literal["fixed", "sliding"] = Field(
        default="fixed",
        description=(
            "Rate limiting algorithm. 'fixed' uses simple window counters; "
            "'sliding' uses a weighted previous-window approximation that "
            "prevents 2x bursts at window boundaries."
        ),
    )
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
    max_ban_duration_seconds: int = Field(
        default=3600,
        ge=1,
        description="Maximum ban duration in seconds (caps exponential escalation)",
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
    leeway_seconds: int = Field(
        default=0,
        ge=0,
        description=(
            "Clock skew tolerance in seconds for exp/iat/nbf validation. "
            "A value of 5-30 prevents rejecting tokens due to minor clock "
            "differences between servers."
        ),
    )
    token_binding: bool = Field(
        default=False,
        description=(
            "When enabled, access tokens are bound to the client's IP and "
            "User-Agent.  A stolen token cannot be used from a different "
            "IP or browser.  Enabling this prevents token-theft account "
            "takeover but may cause issues behind rotating proxies."
        ),
    )


class PermissionsPolicyConfig(BaseModel):
    """Structured configuration for the ``Permissions-Policy`` header.

    Each directive accepts ``"*"`` (all origins), ``"self"`` (same origin),
    ``"none"`` (disabled), or a space-separated list of origins.
    ``None`` means the directive is not included in the header.
    """

    camera: str | None = Field(default=None, description="camera directive")
    microphone: str | None = Field(default=None, description="microphone directive")
    geolocation: str | None = Field(default=None, description="geolocation directive")
    interest_cohort: str | None = Field(
        default=None, description="interest-cohort (FLoC) directive"
    )
    usb: str | None = Field(default=None, description="usb directive")
    bluetooth: str | None = Field(default=None, description="bluetooth directive")
    payment: str | None = Field(default=None, description="payment directive")
    accelerometer: str | None = Field(
        default=None, description="accelerometer directive"
    )
    gyroscope: str | None = Field(default=None, description="gyroscope directive")
    magnetometer: str | None = Field(default=None, description="magnetometer directive")
    midi: str | None = Field(default=None, description="midi directive")
    autoplay: str | None = Field(default=None, description="autoplay directive")
    fullscreen: str | None = Field(default=None, description="fullscreen directive")
    picture_in_picture: str | None = Field(
        default=None, description="picture-in-picture directive"
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
    csp_directives: CSPDirectiveConfig | None = Field(
        default=None,
        description="Structured CSP directive config for building the CSP header",
    )
    permissions_policy_directives: PermissionsPolicyConfig | None = Field(
        default=None,
        description=(
            "Structured Permissions-Policy configuration. "
            "Takes precedence over the raw ``permissions_policy`` string."
        ),
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
    max_body_bytes: int = Field(
        default=10_485_760,
        ge=1,
        description="Maximum request body size in bytes (default 10 MB). "
        "Requests with larger bodies receive a 413 response.",
    )
    exclude_paths: list[str] = Field(
        default_factory=list,
        description="Paths excluded from sanitization (e.g. file upload endpoints)",
    )
    scan_query_params: bool = Field(
        default=True,
        description="Scan query parameter names and values for injection patterns",
    )
    scan_headers: bool = Field(
        default=True,
        description="Scan request header values for injection patterns",
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
    base_uri: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="base-uri directive — restricts <base> tag targets",
    )
    form_action: list[str] = Field(
        default_factory=lambda: ["'self'"],
        description="form-action directive — restricts form submission targets",
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
    chain_integrity: bool = Field(
        default=True,
        description=(
            "Enable hash-chain integrity verification.  Each entry is "
            "linked to the previous one via SHA-256, making tampering "
            "(deletion or modification) detectable via verify_integrity()."
        ),
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
        description="Preflight cache duration in seconds",
    )
    deny_null_origin: bool = Field(
        default=True,
        description=(
            "Reject requests with Origin: null.  Null origins come from "
            "file:// URLs, sandboxed iframes, and data: URIs — they cannot "
            "be trusted and should normally be denied."
        ),
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
    hibp_fail_closed: bool = Field(
        default=False,
        description=(
            "If True, HIBP API failures REJECT the password instead of "
            "allowing it. Safer but may block users if HIBP is down."
        ),
    )
    attempt_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        description=(
            "How long attempt counters live before expiring. "
            "Prevents stale counters from persisting indefinitely."
        ),
    )
    progressive_delay: bool = Field(
        default=False,
        description=(
            "Add increasing delays between failed attempts (1s, 2s, 4s...) "
            "before the hard lockout.  Slows down brute force without "
            "locking legitimate users."
        ),
    )


class MFAConfig(BaseModel):
    """Configuration for Multi-Factor Authentication (TOTP)."""

    enabled: bool = False
    issuer: str = Field(
        default="Araxys",
        description="Issuer name displayed in authenticator apps",
    )
    digits: Literal[6, 8] = Field(
        default=6,
        description="Number of digits in the TOTP code",
    )
    period_seconds: int = Field(
        default=30,
        ge=10,
        le=120,
        description="TOTP time step in seconds",
    )
    window: int = Field(
        default=1,
        ge=0,
        le=5,
        description="Adjacent time steps to accept (±1 = ~90s validity)",
    )
    recovery_code_count: int = Field(
        default=8,
        ge=1,
        le=20,
        description="Number of one-time recovery codes to generate",
    )
    recovery_code_bytes: int = Field(
        default=16,
        ge=8,
        description="Entropy per recovery code (bytes)",
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
    """Configuration for server-side session management."""

    enabled: bool = False
    max_concurrent_per_user: int = Field(
        default=5,
        ge=1,
        description="Maximum concurrent sessions per user",
    )
    session_ttl_seconds: int = Field(
        default=3600,
        ge=1,
        description="Session time-to-live in seconds (1 hour default)",
    )
    idle_timeout_seconds: int | None = Field(
        default=None,
        ge=60,
        description=(
            "Idle timeout — session expires if not touched for N seconds. "
            "None = disabled (only absolute TTL applies)."
        ),
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

    # --- Dead-Letter Queue ---
    dlq_enabled: bool = Field(
        default=False,
        description="Enable the dead-letter queue for failed webhook deliveries",
    )
    dlq_retry_interval_seconds: int = Field(
        default=60,
        ge=1,
        description="Interval between DLQ consumer poll cycles and retry spacing",
    )
    dlq_max_age_seconds: int = Field(
        default=86400,
        ge=1,
        description="Max age in seconds before a DLQ event is auto-purged",
    )
    dlq_max_retries: int = Field(
        default=5,
        ge=1,
        description="Max retry attempts from the DLQ before marking dead",
    )


class MetricsConfig(BaseModel):
    """Configuration for Prometheus metrics export."""

    enabled: bool = False
    path: str = Field(
        default="/metrics",
        description="Path for the Prometheus metrics endpoint",
    )
    auth_token: str | None = Field(
        default=None,
        description=(
            "Optional bearer token to protect the /metrics endpoint. "
            "When set, requests must include ?token=... or "
            "Authorization: Bearer ..."
        ),
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


class RedisPoolConfig(BaseModel):
    """Configuration for the shared Redis connection pool.

    The ``mode`` field acts as a discriminator:
    * ``\"standalone\"`` (default): a single Redis instance via ``url``.
    * ``\"sentinel\"``: Redis Sentinel — requires ``sentinels`` + ``master_name``.
    * ``\"cluster\"``: Redis Cluster — requires ``startup_nodes`` or ``url``.
    """

    mode: Literal["standalone", "sentinel", "cluster"] = Field(
        default="standalone",
        description="Pool mode: standalone, sentinel, or cluster",
    )
    url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL",
    )
    # Sentinel mode
    sentinels: list[tuple[str, int]] = Field(
        default_factory=list,
        description="List of (host, port) pairs for Sentinel nodes",
    )
    master_name: str = Field(
        default="",
        description="Sentinel master name (required in sentinel mode)",
    )
    # Cluster mode
    startup_nodes: list[tuple[str, int]] = Field(
        default_factory=list,
        description="List of (host, port) pairs for Cluster startup nodes",
    )
    read_from_replicas: bool = Field(
        default=False,
        description="Allow reading from cluster replicas",
    )
    max_size: int = Field(
        default=10,
        ge=1,
        description="Maximum pool size",
    )
    idle_timeout_seconds: int = Field(
        default=300,
        description="Idle connection timeout in seconds",
    )
    acquire_timeout_seconds: float = Field(
        default=5.0,
        description="Timeout for acquiring a connection",
    )
    leak_threshold: int = Field(
        default=10,
        description="Outstanding connections before leak warning",
    )
    health_check_interval_seconds: float = Field(
        default=30,
        description="Interval between health checks in seconds",
    )
    reconnect_retries: int = Field(
        default=3,
        ge=1,
        description="Consecutive PING failures before attempting reconnection",
    )

    @model_validator(mode="after")
    def _validate_mode(self) -> RedisPoolConfig:
        """Validate conditional field requirements per mode."""
        if self.mode == "sentinel":
            if not self.sentinels or not self.master_name:
                raise ConfigurationError(
                    "sentinels and master_name are required for sentinel mode",
                )
        elif self.mode == "cluster" and not self.startup_nodes and not self.url:
            raise ConfigurationError(
                "startup_nodes or url is required for cluster mode",
            )
        return self


class TLSConfig(BaseModel):
    """Configuration for TLS connections to Redis."""

    enabled: bool = Field(
        default=False,
        description="Enable TLS for Redis connections",
    )
    ca_cert_path: str | None = Field(
        default=None,
        description="Path to CA certificate file",
    )
    cert_pin_sha256: str | None = Field(
        default=None,
        description="SHA-256 pin of the server certificate",
    )
    min_tls_version: str = Field(
        default="TLSv1.2",
        description="Minimum TLS version allowed",
    )


class SecretsConfig(BaseModel):
    """Configuration for external secret resolution (Vault, AWS Secrets Manager)."""

    enabled: bool = Field(
        default=False,
        description="Enable secret resolution from external providers",
    )
    fail_closed: bool = Field(
        default=False,
        description=(
            "If True, a resolver failure (network error, auth failure) raises "
            "instead of silently falling back to the next resolver in the chain. "
            "Set to True in production to prevent silent credential downgrades."
        ),
    )
    vault_url: str | None = Field(
        default=None,
        description="HashiCorp Vault server URL",
    )
    vault_token: str | None = Field(
        default=None,
        description="HashiCorp Vault authentication token",
    )
    vault_mount_path: str = Field(
        default="araxys",
        description="Vault secret mount path",
    )
    aws_region: str | None = Field(
        default=None,
        description="AWS region for Secrets Manager",
    )
    aws_secret_prefix: str = Field(
        default="araxys/",
        description="Prefix for AWS secret names",
    )


class QueryAuditConfig(BaseModel):
    """Configuration for query auditing."""

    enabled: bool = Field(
        default=True,
        description="Enable query auditing",
    )
    slow_query_threshold_ms: int = Field(
        default=100,
        ge=1,
        description="Threshold in ms for slow query detection",
    )


class QueryValidationConfig(BaseModel):
    """Configuration for SQL parameterization enforcement.

    When mode is ``warn``, queries with inline literals are logged but
    allowed.  When mode is ``block``, unparameterized queries raise
    :exc:`araxys.core.exceptions.ValidationError`.
    """

    mode: Literal["warn", "block"] = Field(
        default="warn",
        description="Enforcement mode: warn (log) or block (raise)",
    )


class PgPoolConfig(BaseModel):
    """Configuration for the PostgreSQL async connection pool."""

    enabled: bool = Field(default=False, description="Enable PostgreSQL pool")
    dsn: str = Field(
        default="postgresql://localhost:5432/araxys",
        description="PostgreSQL connection string (DSN)",
    )
    min_size: int = Field(default=2, ge=1, description="Minimum pool size")
    max_size: int = Field(default=10, ge=1, description="Maximum pool size")
    acquire_timeout_seconds: float = Field(
        default=5.0, ge=0.5, description="Seconds to wait for a connection"
    )
    idle_timeout_seconds: float = Field(
        default=300.0, ge=1.0, description="Close idle connections after N seconds"
    )
    health_check_seconds: float = Field(
        default=30.0, ge=5.0, description="Seconds between liveness checks"
    )


class DatabaseSecurityConfig(BaseModel):
    """Configuration for the database security module.

    When None on AraxysConfig, the entire module is disabled and
    existing backends operate via from_url() as today.
    """

    enabled: bool = Field(default=False, description="Enable database security module")
    redis_pool: RedisPoolConfig = Field(default_factory=RedisPoolConfig)
    pg_pool: PgPoolConfig | None = Field(
        default=None,
        description="Optional PostgreSQL connection pool configuration",
    )
    tls: TLSConfig = Field(default_factory=TLSConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    query_audit: QueryAuditConfig = Field(default_factory=QueryAuditConfig)
    query_validation: QueryValidationConfig | None = Field(
        default_factory=QueryValidationConfig,
        description="Optional query parameterization validation config",
    )


class FileScanConfig(BaseModel):
    """Configuration for file-based prompt injection scanning.

    Controls which file formats are scanned and how metadata/hidden
    text detection behaves. Supports PDF, Office documents (DOCX,
    PPTX, XLSX), and images (JPEG, PNG, TIFF, WebP).
    """

    enabled_formats: list[str] = Field(
        default_factory=lambda: [
            "jpeg", "png", "tiff", "webp",
            "pdf", "docx", "pptx", "xlsx",
        ],
        description="File formats to scan for metadata and hidden text injection",
    )
    max_file_size: int = Field(
        default=10_485_760,
        ge=1,
        description="Maximum file size in bytes (default 10 MB)",
    )
    scan_metadata: bool = Field(
        default=True,
        description="Scan file metadata (EXIF, PDF Info, Office properties)",
    )
    scan_hidden_text: bool = Field(
        default=True,
        description="Detect hidden/invisible text in files",
    )


class PromptInjectionConfig(BaseModel):
    """Configuration for prompt injection detection.

    When ``None`` on :class:`AraxysConfig`, the entire prompt injection
    feature is disabled.
    """

    detect_direct_injection: bool = Field(
        default=True,
        description="Detect direct instruction injection attempts",
    )
    detect_jailbreak: bool = Field(
        default=True,
        description="Detect jailbreak attempts (DAN, bypass restrictions, etc.)",
    )
    detect_delimiter_escape: bool = Field(
        default=True,
        description=(
            "Detect delimiter escape — closing ``` and "
            "injecting new instructions"
        ),
    )
    detect_zero_width: bool = Field(
        default=True,
        description="Detect zero-width character injection (\\u200B, \\u200C, etc.)",
    )
    detect_homoglyph: bool = Field(
        default=True,
        description="Detect homoglyph attacks (Cyrillic letters replacing Latin)",
    )
    threshold: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum threat score to flag as threat (0.0 = any match blocks)",
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs", "/redoc", "/openapi.json", "/healthz",
        ],
        description="Paths excluded from prompt injection scanning",
    )
    exclude_content_types: list[str] = Field(
        default_factory=list,
        description="Content types excluded from scanning",
    )
    file_scanning: FileScanConfig = Field(
        default_factory=FileScanConfig,
        description="Configuration for file-based scanning (PDF, Office, images)",
    )


class WebAuthnConfig(BaseModel):
    """Configuration for the WebAuthn / Passkeys module."""

    enabled: bool = Field(
        default=False,
        description="Enable WebAuthn passkey verification",
    )
    rp_id: str = Field(
        default="localhost",
        description="Relying Party ID (domain), e.g. 'example.com'",
    )
    rp_name: str = Field(
        default="Araxys",
        description="Human-readable Relying Party name",
    )
    origin: str = Field(
        default="http://localhost:8000",
        description="Expected origin from clientDataJSON",
    )


class MalwareConfig(BaseModel):
    """Configuration for heuristic file-upload malware detection.

    When ``None`` on :class:`AraxysConfig`, the entire malware detection
    feature is disabled. Detectors use only stdlib — no external dependencies.
    """

    enabled: bool = Field(
        default=True,
        description="Enable malware detection (master switch)",
    )
    max_file_size: int = Field(
        default=10 * 1024 * 1024,
        ge=1,
        description="Maximum file size in bytes to scan (10 MB default)",
    )

    # ── Per-detector toggles ──────────────────────────────────────────────
    detect_magic_bytes: bool = Field(
        default=True,
        description="Detect magic bytes / extension mismatch",
    )
    detect_mime_mismatch: bool = Field(
        default=True,
        description="Detect Content-Type / content signature mismatch",
    )
    detect_archive_bomb_zip: bool = Field(
        default=True,
        description="Detect ZIP bombs (high ratio, deep nest, many files)",
    )
    detect_archive_bomb_tar: bool = Field(
        default=True,
        description="Detect TAR bombs (high ratio, many members)",
    )
    detect_office_macros: bool = Field(
        default=True,
        description="Detect OOXML files with embedded VBA macros",
    )
    detect_polyglot: bool = Field(
        default=False,
        description=(
            "Detect polyglot files (multiple formats). OFF by default "
            "due to high false-positive risk."
        ),
    )
    detect_double_extension: bool = Field(
        default=True,
        description="Detect dangerous double extensions (e.g. invoice.pdf.exe)",
    )
    detect_path_traversal: bool = Field(
        default=True,
        description="Detect path traversal in filenames",
    )
    detect_size_mismatch: bool = Field(
        default=True,
        description="Detect file size / declared header mismatch",
    )

    # ── Archive bomb limits ────────────────────────────────────────────────
    archive_max_ratio: float = Field(
        default=100.0,
        ge=1.0,
        description="Maximum compression ratio before flagging (100:1)",
    )
    archive_max_depth: int = Field(
        default=5,
        ge=1,
        description="Maximum nested archive depth",
    )
    archive_max_files: int = Field(
        default=1000,
        ge=1,
        description="Maximum file count inside an archive",
    )
    archive_max_size: int = Field(
        default=100 * 1024 * 1024,
        ge=1,
        description="Maximum uncompressed size in bytes for archives",
    )
    archive_max_members: int = Field(
        default=1000,
        ge=1,
        description="Maximum member count inside a TAR archive",
    )

    # ── Extension and exclusion lists ─────────────────────────────────────
    dangerous_extensions: list[str] = Field(
        default_factory=lambda: [
            "exe", "dll", "scr", "vbs", "js", "jse",
            "ps1", "bat", "cmd", "com", "msi",
        ],
        description="Extensions considered dangerous in double-extension check",
    )
    excluded_paths: list[str] = Field(
        default_factory=list,
        description="Paths excluded from malware scanning",
    )
    excluded_content_types: list[str] = Field(
        default_factory=list,
        description="Content types excluded from malware scanning",
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
    trusted_proxies: list[str] = Field(
        default_factory=list,
        description=(
            "IP addresses or CIDR ranges of trusted reverse proxies. "
            "X-Forwarded-For is only honoured when the direct client IP "
            "belongs to one of these ranges. Leave empty to NEVER trust "
            "X-Forwarded-For (secure default)."
        ),
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
    mfa: MFAConfig | None = Field(default=None)
    # v0.5 — Database Security (optional, disabled by default)
    db_security: DatabaseSecurityConfig | None = Field(default=None)
    # v0.6 — WebAuthn / Passkeys
    webauthn: WebAuthnConfig | None = Field(default=None)
    # v0.7 — Prompt Injection Detection
    prompt_injection: PromptInjectionConfig | None = Field(
        default=None,
        description="Prompt injection detection config (None = feature disabled)",
    )
    # v0.8 — Malware Detection
    malware: MalwareConfig | None = Field(
        default=None,
        description="Malware detection config (None = feature disabled)",
    )
    # v0.9 — WebSocket Security
    websocket: WebSocketConfig | None = Field(
        default=None,
        description="WebSocket security config (None = feature disabled)",
    )
    # v0.13 — XXE Protection
    xxe: XXEConfig | None = Field(
        default=None,
        description="XXE protection config (None = feature disabled)",
    )
