# 🛡️ Araxys: Agent Instructions & Context

This document provides high-density technical context for AI agents (LLMs) working with the Araxys security library. It prioritizes technical facts, type signatures, and known constraints over introductory prose.

## 🏗️ Architecture Summary

Araxys uses an **Orchestrator Pattern** (`AraxysShield`) to wire specialized middlewares to a FastAPI application.

**Middleware Order (from innermost to outermost — FastAPI registration order):**
1. `SanitizeMiddleware` (innermost — closest to app logic)
2. `PromptInjectionMiddleware` (v0.11 — read-only, scans text + files before sanitization blocks)
3. `MalwareMiddleware` (v0.12 — read-only, scans multipart uploads heuristically)
4. `HoneypotMiddleware` (IP-ban check + trap routes)
5. `IPAccessMiddleware` (v0.3 — allow/block/hybrid before lockout)
6. `BruteForceMiddleware` (v0.3 — lockout before rate limiting)
7. `RateLimitMiddleware` (sliding window, per-IP/user/key)
8. `TelemetryMiddleware` (v0.3 — opt-in, wraps everything below)
9. `SecureHeadersMiddleware` (HSTS, CSP, COOP/CORP, X-Frame-Options)
10. `CORSMiddleware` (v0.3 — outermost, fail-closed)

## 🔑 Key Abstractions

| Component | Module Path | Responsibility |
|-----------|-------------|----------------|
| `AraxysShield` | `araxys.shield` | Entry point; wiring, config orchestration, event bus, shutdown. |
| `CORSMiddleware` | `araxys.cors.middleware` | Per-origin CORS, fail-closed, preflight handling. |
| `IPAccessMiddleware` | `araxys.ip_access.middleware` | Allow/block/hybrid IP filtering with CIDR. |
| `CSRFHandler` | `araxys.csrf.tokens` | Double-submit cookie CSRF with constant-time validation. |
| `BruteForceMiddleware` | `araxys.brute_force.limiter` | Account lockout after N failures. |
| `PasswordPolicy` | `araxys.brute_force.password_policy` | Password complexity + HIBP check. |
| `SessionManager` | `araxys.sessions.manager` | Session tracking, max concurrent, idle timeout, cleanup. |
| `SecurityEventBus` | `araxys.webhooks.emitter` | Unified async pub/sub event bus (12 event types). |
| `WebhookDelivery` | `araxys.webhooks.delivery` | httpx POST + retry (1s/2s/4s) per event type. |
| `DLQConsumer` | `araxys.webhooks.dlq` | Dead-letter queue: list, inspect, replay, purge. Admin API. |
| `MetricsRegistry` | `araxys.metrics.collector` | 9 Prometheus counters + histogram, /metrics endpoint. |
| `AraxysTracer` | `araxys.telemetry.tracer` | OTEL span context manager with no-op fallback. |
| `APIKeyManager`| `araxys.api_keys.manager` | Key generation (256-bit entropy), SHA-256 hashing, scope-based verification. |
| `JWTManager` | `araxys.jwt_auth.tokens` | Token creation (HS256/RS256/ES256), decoding, JWKS (RFC 7517), token binding, family revocation, JTI blacklisting. |
| `MFAManager` | `araxys.mfa.manager` | TOTP (RFC 6238), QR URI, one-time recovery codes. Zero external deps. |
| `OAuth2Manager` | `araxys.oauth.manager` | Authorization Code + PKCE, state store, multi-provider (Google, GitHub, Microsoft). |
| `RBACManager` | `araxys.rbac.manager` | Hierarchical RBAC with `resource:action` permission strings and wildcards. |
| `WebAuthnManager` | `araxys.webauthn.manager` | FIDO2 registration + authentication, COSE key parsing (EC2, RSA), attestation. |
| `AdminAPI` | `araxys.admin.router` | Session management, IP bans, API keys, rate limit stats, DLQ inspection, health checks. |
| `PromptInjectionGuard` | `araxys.prompt_injection.dependencies` | FastAPI `Depends` factory — scans text payloads against 5 detectors + file metadata. |
| `PromptInjectionMiddleware` | `araxys.prompt_injection.middleware` | Read-only ASGI middleware for text + file scanning (query params, JSON, multipart). |
| `MalwareScanner` | `araxys.malware.scanner` | Config-driven heuristic scanner: 9 detectors, async via `run_in_executor`. |
| `MalwareGuard` | `araxys.malware.dependencies` | FastAPI `Depends` factory — scans uploaded files against malware detectors. |
| `MalwareMiddleware` | `araxys.malware.middleware` | Read-only ASGI middleware for multipart file upload scanning. |
| `DatabaseSecurityManager` | `araxys.db_security.manager` | Shared Redis/PG pool lifecycle, secret resolver chain, TLS cert pinning, query auditing. |
| `ConnectionPool` | `araxys.db_security.pool` | Protocol for Redis connection pools — InMemoryPool + RedisPool + RedisClusterPool + RedisSentinelPool. |
| `QueryValidator` | `araxys.db_security.query_validator` | sqlparse-based detection of inline SQL literals vs parameterized queries. |
| `QueryAuditor` | `araxys.db_security.audit` | Emits `AuditEntry(QUERY_EXECUTED)` with slow query detection (>100ms threshold). |
| `SqlInjectionAnalyzer` | `araxys.sanitize.sqlparser` | sqlparse-based SQLi detection (stacked queries, UNION SELECT, tautologies, time-based, comments). Falls back to regex patterns when sqlparse not installed. |
| `SanitizeScanner` | `araxys.sanitize.scanner` | Recursive scanning of dicts/lists/strings for SQLi, XSS, NoSQL, command injection, path traversal. |
| `HoneypotTrap` | `araxys.honeypot.traps` | Fake endpoints (`/wp-admin`, `/.env`) that auto-ban bots with fake 200 responses. |
| `AuditLogger` | `araxys.audit.logger` | AES-256-GCM encrypted logging, hash-chain integrity, PII masking, async I/O. |
| `Scope` | `araxys.core.types` | Permission scopes: `read`, `write`, `admin`. |
| `SecurityEventType` | `araxys.core.types` | Enum for all 12 security event types. |
| `ScanResult` | `araxys.core.types` | Dataclass returned by prompt injection scanners — `threat_score`, `is_threat`, `detectors_triggered`. |

## ⚠️ Critical Implementation Gotchas

> [!IMPORTANT]
> **Runtime Annotations**: Do NOT move `fastapi.Request`, `fastapi.Response`, `fastapi.BackgroundTasks`, or Pydantic models (like `Scope`) into `TYPE_CHECKING` blocks. Doing so breaks runtime dependency injection and Pydantic model rebuilding. Use `# noqa: TC001/TC002` to satisfy Ruff.

- **API Key Constraints**: 
    - `prefix`: Exactly 8 characters (enforced by `min_length/max_length` in `APIKeyRecord`).
    - `key_hash`: SHA-256 (64 hex characters).
- **Encryption**: `AraxysConfig.secret_key` must be a high-entropy string (>= 32 chars) as it's used for AES-256-GCM encryption in audit logs.
- **Async First**: All storage operations and manager methods are `async`.
- **CORS fail-closed**: `CORSConfig` defaults to `default_factory=CORSConfig` with empty `allow_origins`. Middleware is ALWAYS registered. Empty allowlist = 400 on all cross-origin requests.
- **CSRF dependency**: Uses `HTTPException` (not custom `CSRFValidationError`) inside FastAPI dependencies — required for proper 403 responses through FastAPI's DI system.
- **Prometheus Registry**: Each `MetricsRegistry` instance creates its own `CollectorRegistry` to avoid "Duplicated timeseries" errors when multiple Shield instances exist in the same process.
- **OTEL imports**: Use `try/except ImportError` with lazy import helpers for `opentelemetry` — the SDK is optional and must not cause import errors.
- **Redis stubs**: Redis async methods return `Awaitable[T] | T` union types. Use `# type: ignore[misc]` on `await` lines or `isinstance` narrowing for `smembers()`.
- **JWT Asymmetric Keys**: When `private_key` and `public_key` are set in `JWTConfig`, `JWTManager` auto-detects RS256/ES256. `secret_key` is only used for HS256. Both paths coexist — existing HS256 configs are unaffected.
- **Rate Limit Identity**: `extract_user_id()` reads JWT `sub` from `request.state`. `extract_api_key()` reads `X-API-Key` header. Per-user/per-key limits are checked IN ADDITION to IP limits — the effective remaining is `min()` of all active dimensions.
- **Audit PII Masking**: `mask_pii()` is recursive and non-mutating — it deep-copies before masking. PII masking is applied BEFORE encryption in `AuditLogger.log_event()`.
- **Audit Async Writer**: `LogWriter` uses `aiofiles` (optional). Falls back to synchronous writes when `aiofiles` is not installed. Rotation is size-based with `asyncio.Lock` for thread safety.
- **CSP Builder**: `build_csp_header()` is a pure function. COOP/CORP default to `"same-origin"` (secure-by-default). Only add headers when their config value is not `None`.
- **Sanitize Scanner**: `scan_query_params()` scans BOTH parameter names AND values (NoSQL operators often hide in names like `?username[$ne]=admin`). Detectors are pure functions `(value: str) -> str | None`.
- **DB Security Backward Compat**: `db_security=None` (default) means ALL 6 Redis backends use independent `from_url()` calls — zero behavior change. When `db_security.enabled=True`, the shared pool replaces all `from_url()` calls. The old `redis_url` config field is deprecated when db_security is enabled.
- **Cert Pinning**: `cert_pin_sha256` in `TLSConfig` is verified at `RedisPool.acquire()` time, not at SSL context creation. Uses asyncio writer's `get_extra_info('ssl_object')` to access the peer certificate.
- **Secrets Resolver Chain**: Resolvers are tried in order (EnvVar → Vault → AWS) and each is fail-soft (returns `None` on error, never raises). ChainedResolver returns first non-None or None if all fail.
- **Async Secret Resolvers (v0.6)**: `VaultResolver.resolve()` and `AWSSecretsResolver.resolve()` use `asyncio.to_thread()` to avoid blocking the event loop. Error propagation is preserved.
- **RedisPool Health Loop (v0.6)**: Background health-check task uses `loop.create_task()`. Gracefully cancelled on `close()` via `contextlib.suppress(asyncio.CancelledError)`. Health check interval is `float` (seconds).
- **SQL Parser Fallback (v0.6)**: `SqlInjectionAnalyzer` imports `sqlparse` lazily. When `sqlparse` is not installed, `detect_sqli()` falls back to the original `patterns.py` regex patterns. The `araxys[sqlparser]` extra installs `sqlparse>=0.5.0`.
- **JSON Body Full Scan (v0.6)**: After `sanitize_payload()` handles SQLi+XSS, `SanitizeMiddleware` now iterates leaf string values in JSON bodies and runs `scan_value()` for NoSQL, command injection, and path traversal detection. Respects `SanitizeConfig` flags.
- **Session TTL (v0.7)**: `SessionRecord.expires_at` is a `float | None` (Unix timestamp). `SessionConfig.session_ttl_seconds` defaults to 3600 (1 hour). `RedisSessionBackend.create_session()` pipelines `EXPIRE` on both the session HASH key and user SET key.
- **Session Cleanup (v0.7)**: `SessionManager._cleanup_loop()` runs every `cleanup_interval_seconds`, calls `backend.cleanup_expired()`. Exceptions are caught and logged — the loop never crashes. Call `start_cleanup()` / `stop_cleanup()` for lifecycle.
- **Body Size Limit (v0.7)**: `SanitizeConfig.max_body_bytes` defaults to 10 MB. Exceeded requests get 413 `{"detail": "Request body too large"}`. Header-less requests fall back to reading the body and checking length.
- **RedisPool Reconnection (v0.7)**: `_health_loop()` tracks consecutive PING failures; after `reconnect_retries` (default 3), calls `_reconnect()`. Guarded by `asyncio.Lock()`. `RedisPoolConfig.reconnect_retries` threads to `RedisPool`.
- **QueryValidator (v0.7)**: `QueryValidator.validate()` uses sqlparse to detect inline SQL literals. `QueryValidationConfig.mode` is `"warn"` (default — returns `passed=True` with reason) or `"block"` (raises `ValidationError`). `ConnectionPool` Protocol now requires `validate_query()`. Test fakes must implement it.
- **Prompt Injection File Scanning (v0.11)**: `files/` subpackage uses lazy imports (`PIL`, `pypdf`, `docx`, `openpyxl`) with graceful fallback — missing optional deps return empty metadata. `FileScanConfig.enabled_formats` controls which parsers are attempted. Detectors are pure functions `(value: str) -> ScanResult`. Zero-width chars and homoglyphs use Unicode normalization (NFKC).
- **Malware Detection (v0.12)**: All 9 detectors are pure functions `(bytes) -> bool | str | None`. `MalwareScanner.scan()` uses `asyncio.get_event_loop().run_in_executor()` to avoid blocking the event loop. `Archives/` subpackage handles ZIP, TAR, GZ, BZ2, and 7z detection for archive bombs. Magic bytes DB covers 70+ file signatures. Polyglot detection checks for multiple valid file headers in a single file.
- **PromptInjectionMiddleware / MalwareMiddleware**: Both are read-only — they read the request body via `request.body()` (cached by Starlette, no mutation). They check for `PromptInjectionError` / `MalwareDetectionError` and return 400 with JSON detail. Never consume the upload stream — use `UploadFile` API.
- **Middleware Order Matters**: Prompt injection runs AFTER sanitization but BEFORE malware (innermost chain: Sanitize → PromptInjection → Malware). Changing this order without understanding the read-only contract will break request body consumption.
- **`ScanResult` Type**: `threat_score: float` is a design seam for future LLM-based secondary validation. Current detectors set `is_threat=True` for definitive matches. `detectors_triggered` is a list of detector names for audit trails.
- **Python Version (v0.12)**: Minimum Python 3.11. Uses `datetime.timezone.utc` (not `datetime.UTC`) and `(str, Enum)` (not `StrEnum`) for compatibility. `from __future__ import annotations` is required in all module files.

## 🛠️ Common Usage Patterns

### 1. Initializing Shield
```python
from araxys import AraxysShield, AraxysConfig

# Quick start — in-memory backends (dev/testing)
shield = AraxysShield(app, AraxysConfig(secret_key="super-secret-key-at-least-32-chars!"))

# Production — shared Redis pool via db_security (recommended)
from araxys.db_security.config import DatabaseSecurityConfig
shield = AraxysShield(
    app,
    AraxysConfig(
        secret_key="...",
        db_security=DatabaseSecurityConfig(
            enabled=True,
            redis_url="redis://localhost:6379",
        ),
    ),
)
# When db_security is enabled, all modules share the same Redis pool.
# The top-level redis_url fallback still works for simple setups.
```

### 2. CORS Configuration
```python
from araxys import CORSConfig
config = AraxysConfig(
    secret_key="...",
    cors=CORSConfig(allow_origins=["https://app.example.com"], allow_methods=["GET", "POST"]),
)
```

### 3. CSRF Protection (per-route)
```python
from fastapi import Depends
from araxys import csrf_protected, CSRFConfig

@app.post("/submit", dependencies=[Depends(csrf_protected(CSRFConfig()))])
async def submit_form():
    return {"status": "ok"}
```

### 4. Password Policy Dependency
```python
from araxys import password_policy_dependency, PasswordPolicyConfig

@app.post("/register")
async def register(password: str = Depends(password_policy_dependency(PasswordPolicyConfig()))):
    return {"status": "ok"}
```

### 5. Protecting a Route with Scoped API Keys
```python
from fastapi import Depends
from araxys.api_keys.dependencies import require_api_key
from araxys.core.types import Scope

@app.get("/secure", dependencies=[Depends(require_api_key(scopes=[Scope.WRITE]))])
async def secure_endpoint():
    return {"status": "ok"}
```

### 6. Observability (OTEL + Prometheus)
```python
config = AraxysConfig(
    secret_key="...",
    telemetry={"enabled": True, "service_name": "my-api"},
    metrics={"enabled": True},
)
# Spans auto-created for every HTTP request.
# GET /metrics exposes Prometheus counters and histogram.
```

### 7. Webhook Delivery
```python
config = AraxysConfig(
    secret_key="...",
    webhooks={
        "enabled": True,
        "urls": {
            "rate_limit_exceeded": ["https://hooks.slack.com/..."],
            "honeypot_triggered": ["https://api.security.example.com/alerts"],
        },
    },
)
# Events delivered with 1s/2s/4s exponential retry, non-blocking.
```

### 8. Prompt Injection Protection
```python
config = AraxysConfig(
    secret_key="...",
    prompt_injection=PromptInjectionConfig(
        enabled=True,
        file_scanning=FileScanConfig(
            enabled_formats=["pdf", "docx", "jpeg", "png"],
        ),
    ),
)
# Text scanning: 5 detectors (direct injection, jailbreak, delimiters, zero-width, homoglyphs)
# File scanning: metadata + hidden text in PDFs, Office docs, and images
# Per-route: Depends(get_prompt_injection_guard(config.prompt_injection))
```

### 9. Malware File Upload Scanning
```python
config = AraxysConfig(
    secret_key="...",
    malware=MalwareConfig(
        enabled=True,
        max_file_size=50 * 1024 * 1024,  # 50 MB
        detectors=["magic_bytes", "archive_bomb", "polyglot", "macros", "mime_mismatch"],
    ),
)
# 9 heuristic detectors — zero external dependencies
# Middleware is read-only (doesn't consume the upload stream)
# Per-route: Depends(get_malware_guard(config.malware))
```

### 10. Graceful Shutdown
```python
# On app shutdown
await shield.shutdown()
# Stops event bus, session cleanup loop, and webhook delivery tasks.
```

## 💻 CLI Operations
The `araxys` CLI is the preferred way for agents to perform environment management.
- **Set Context**: `export ARAXYS_REDIS_URL="redis://..."`
- **Key Creation**: `araxys keys create --owner "name" --scopes "read,write"`
- **Key Revocation**: `araxys keys revoke <prefix>`

## 🧪 Testing Guidelines
- **Storage**: Use `fakeredis.aioredis.FakeRedis` for testing Redis-dependent modules.
- **Async**: Use `@pytest.mark.asyncio`.
- **Typing**: All test functions MUST have an explicit `-> None` return type hint to satisfy `strict = true` Mypy settings.
- **Fixtures**: Standard fixtures for `storage` and `manager` are available in `tests/conftest.py` (when implemented) or within module tests.
- **Prometheus mocks**: Use `FakeCounter`/`FakeHistogram` based on `prometheus_client` API for unit tests without real registry.
- **OTEL mocks**: Use `unittest.mock` to mock `opentelemetry` imports — never require the real SDK in tests.
- **HIBP tests**: Mock `httpx.AsyncClient` responses for `check_hibp()` — never hit the real API in tests.

## 📊 Test Coverage (v0.12)
- **1,326 tests** across 46 test files covering all 24 modules
- Unit: ~600 tests (backends, stateless logic, pure functions, detectors, scanners, sqlparser, pool, query_validator)
- Integration: ~400 tests (middleware via `httpx.AsyncClient` + `TestClient`)
- E2E: ~150 tests (full middleware chain, file upload scanning, prompt injection file detection)
- Key pure functions: `build_csp_header()`, `mask_pii()`, `detect_nosql_injection()`, `detect_command_injection()`, `detect_path_traversal()`, `extract_user_id()`, `extract_api_key()`, `match_path()`, `SqlInjectionAnalyzer.analyze()`, `QueryValidator.validate()`, `detect_magic_bytes_mismatch()`, `detect_archive_bomb()`, `detect_polyglot()`, `detect_direct_injection()`, `detect_jailbreak()`, `detect_hidden_text()`
- Ruff + mypy strict enforced in CI (124 source files, 0 errors)
