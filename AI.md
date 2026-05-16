# 🛡️ Araxys: Agent Instructions & Context

This document provides high-density technical context for AI agents (LLMs) working with the Araxys security library. It prioritizes technical facts, type signatures, and known constraints over introductory prose.

## 🏗️ Architecture Summary

Araxys uses an **Orchestrator Pattern** (`AraxysShield`) to wire specialized middlewares to a FastAPI application.

**Middleware Order (from outer to inner):**
1. `CORSMiddleware` (v0.3 — outermost, fail-closed)
2. `SecureHeadersMiddleware`
3. `TelemetryMiddleware` (v0.3 — opt-in, wraps everything below)
4. `RateLimitMiddleware`
5. `BruteForceMiddleware` (v0.3 — lockout before processing)
6. `IPAccessMiddleware` (v0.3 — before Honeypot)
7. `HoneypotMiddleware`
8. `SanitizeMiddleware` (innermost)
9. `JWTAuthMiddleware` / `APIKeyMiddleware` (typically route-level)

## 🔑 Key Abstractions

| Component | Module Path | Responsibility |
|-----------|-------------|----------------|
| `AraxysShield` | `araxys.shield` | Entry point; wiring, config orchestration, event bus, shutdown. |
| `CORSMiddleware` | `araxys.cors.middleware` | Per-origin CORS, fail-closed, preflight handling. |
| `IPAccessMiddleware` | `araxys.ip_access.middleware` | Allow/block/hybrid IP filtering with CIDR. |
| `CSRFHandler` | `araxys.csrf.tokens` | Double-submit cookie CSRF with constant-time validation. |
| `BruteForceMiddleware` | `araxys.brute_force.limiter` | Account lockout after N failures. |
| `PasswordPolicy` | `araxys.brute_force.password_policy` | Password complexity + HIBP check. |
| `SessionManager` | `araxys.sessions.manager` | Session tracking, max concurrent, cleanup. |
| `SecurityEventBus` | `araxys.webhooks.emitter` | Unified async pub/sub event bus (12 event types). |
| `WebhookDelivery` | `araxys.webhooks.delivery` | httpx POST + retry (1s/2s/4s) per event type. |
| `MetricsRegistry` | `araxys.metrics.collector` | 9 Prometheus counters + histogram, /metrics endpoint. |
| `AraxysTracer` | `araxys.telemetry.tracer` | OTEL span context manager with no-op fallback. |
| `APIKeyManager`| `araxys.api_keys.manager` | Key generation, SHA-256 hashing, and verification. |
| `JWTManager` | `araxys.jwt_auth.tokens` | Token creation (HS256/RS256/ES256), decoding, JWKS (RFC 7517), introspection (RFC 7662), blacklist checks. |
| `Storage` | `araxys.*.storage` | Protocols for Redis or InMemory persistence. |
| `Scope` | `araxys.core.types` | Enum for permission-based access control. |
| `SecurityEventType` | `araxys.core.types` | Enum for all 12 security event types. |

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

## 🛠️ Common Usage Patterns

### 1. Initializing Shield
```python
from araxys import AraxysShield, AraxysConfig
shield = AraxysShield(app, AraxysConfig(secret_key="...", redis_url="..."))
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

### 8. Graceful Shutdown
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

## 📊 Test Coverage (v0.4)
- **490 tests** across 14 test files
- Unit: ~330 tests (backends, stateless logic, pure functions, detectors)
- Integration: ~160 tests (middleware via `httpx.AsyncClient` + `TestClient`)
- Key pure functions: `build_csp_header()`, `mask_pii()`, `detect_nosql_injection()`, `detect_command_injection()`, `detect_path_traversal()`, `extract_user_id()`, `extract_api_key()`, `match_path()`
- Ruff + mypy strict enforced in CI (91 source files, 0 errors)
