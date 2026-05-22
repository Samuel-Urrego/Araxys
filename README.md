<p align="center">
  <img src="assets/araxyslogo.png" alt="Araxys Logo" width="400">
</p>

<p align="center">
  <strong>Plug & Play Security for FastAPI</strong><br>
  <em>CORS · CSRF · Rate Limiting · JWT · API Keys · MFA · OAuth2 · RBAC · WebAuthn · Sessions · Webhooks + DLQ · Honeypots · Audit · DB Security · Redis Sentinel/Cluster</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge&logo=pydantic&logoColor=white" alt="Pydantic">
  <img src="https://img.shields.io/badge/uv-package%20manager-DE5FE9?style=for-the-badge&logo=uv&logoColor=white" alt="uv">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/version-0.10.0-blue?style=for-the-badge" alt="Version">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-DC143C?style=flat-square" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/JWT-OAuth2%20compliant-000000?style=flat-square&logo=jsonwebtokens&logoColor=white" alt="JWT">
  <img src="https://img.shields.io/badge/Redis-optional-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis">
  <img src="https://img.shields.io/badge/OpenTelemetry-optional-8B5CF6?style=flat-square&logo=opentelemetry&logoColor=white" alt="OTEL">
  <img src="https://img.shields.io/badge/Prometheus-optional-E6522C?style=flat-square&logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/structlog-logging-4B8BBE?style=flat-square" alt="structlog">
  <img src="https://img.shields.io/badge/tests-1018%20passed-brightgreen?style=flat-square" alt="Tests">
</p>

---

## ⚡ What is Araxys?

**Araxys** is a comprehensive security library for [FastAPI](https://fastapi.tiangolo.com/) that provides enterprise-grade protection with a plug & play architecture. Add security to your API with **three lines of code** — no rewrites, no boilerplate.

> **v0.10.0** adds session idle timeout (last_activity_at + touch_session), Redis Sentinel/Cluster high availability, webhook dead-letter queue with admin API, WebAuthn/Passkeys (FIDO2 registration + authentication ceremonies), and a comprehensive security audit with 47 fixes across all modules. **v0.9.0** added MFA (TOTP), RBAC (resource:action), OAuth2/OIDC with PKCE, and PostgreSQL connection pooling. **v0.8.0** was a hardening sprint with 28 fixes across 7 sprints. **v0.7.0** added session lifecycle management (TTL expiry, Redis EXPIRE, refresh, cleanup loop) and QueryValidator with sqlparse-based SQLi detection. [1018 tests](https://github.com/Samuel-Urrego/Araxys/actions).

```python
from fastapi import FastAPI
from araxys import AraxysShield, AraxysConfig

app = FastAPI()
shield = AraxysShield(app, AraxysConfig(secret_key="your-32-char-secret-key-here!!!!"))
# That's it. Your API is now protected. 🛡️
```

---

## 🧩 Modules

| Module | Description | Status |
|--------|------------|--------|
| 🚦 **CORS** | Per-origin policy with fail-closed default | ✅ v0.3 |
| 🛑 **IP Access Control** | Allow/block/hybrid modes with CIDR support | ✅ v0.3 |
| 🍪 **CSRF Protection** | Double-submit cookie with constant-time validation | ✅ v0.3 |
| 🔒 **Brute Force** | Account lockout + password policy + HIBP check | ✅ v0.3 |
| 👥 **Session Management** | Max concurrent, idle timeout, TTL expiry, touch_session() | ✅ v0.10 |
| 🗄️ **DB Security** | Redis Sentinel/Cluster pools, PG pool, TLS/cert pinning, secret resolver chain | ✅ v0.10 |
| 🎟️ **JWT Auth** | RS256/ES256 + HS256, JWKS, token rotation, family revocation | ✅ Ready |
| 🔑 **API Keys** | Scoped keys with SHA-256 hashing & expiration | ✅ Ready |
| 🔐 **MFA / TOTP** | Time-based OTP (RFC 6238), recovery codes | ✅ v0.9 |
| 🔓 **OAuth2 / OIDC** | PKCE flow, state store, multi-provider support | ✅ v0.9 |
| 🏷️ **RBAC** | Resource:action permission model | ✅ v0.9 |
| 🔏 **WebAuthn / Passkeys** | FIDO2 registration + authentication, COSE key parsing, attestation | ✅ v0.10 |
| 📨 **Webhooks** | Event bus + retry (1s/2s/4s) + dead-letter queue with admin API | ✅ v0.10 |
| 🚦 **Rate Limiting** | Sliding window, per-user/IP/key, escalating bans with cap | ✅ Ready |
| 🍯 **Honeypots** | Fake endpoints that auto-ban bots | ✅ Ready |
| 🛡️ **Secure Headers** | CSP, COOP/COEP/CORP, HSTS, X-Frame-Options (OWASP) | ✅ Ready |
| 🧹 **Sanitization** | SQLi (sqlparse), NoSQL, command injection, XSS, path traversal, multipart | ✅ Ready |
| 📋 **Audit Logging** | AES-256-GCM encrypted, async I/O, hash-chain integrity, PII masking | ✅ Ready |
| 📡 **OpenTelemetry** | Graceful span tracing (opt-in, no-op fallback) | ✅ v0.3 |
| 📊 **Prometheus Metrics** | 9 counters + histogram + /metrics endpoint | ✅ v0.3 |
| 💻 **Admin API** | Session/IP ban/API key management, DLQ inspection + replay | ✅ v0.9 |

---

## 📦 Installation

```bash
# Core (in-memory backends)
pip install araxys

# With Redis support (recommended for production)
pip install araxys[redis]

# With OpenTelemetry tracing
pip install araxys[opentelemetry]

# With Prometheus metrics
pip install araxys[prometheus]

# With webhook delivery support
pip install araxys[webhooks]

# Everything
pip install araxys[all]

# Development
pip install araxys[dev]
```

> **Requires Python 3.13+**

---

> [!TIP]
> **AI Agent Support:** This repository includes an [AI.md](AI.md) file specifically designed to provide high-density context for AI coding assistants (Cursor, Windsurf, etc.), ensuring they follow project standards and understand the internal architecture.

---

## 🚀 Quick Start

### Full Protection (All Modules)

```python
from fastapi import FastAPI
from araxys import AraxysShield, AraxysConfig

app = FastAPI()

shield = AraxysShield(
    app,
    AraxysConfig(
        secret_key="super-secret-key-at-least-32-chars!",
        redis_url="redis://localhost:6379",  # Optional — omit for in-memory
        cors={"allow_origins": ["https://myapp.com"], "allow_methods": ["GET", "POST"]},
        ip_access={"enabled": True, "mode": "block", "blocklist": ["10.0.0.0/8"]},
        rate_limit={"window_seconds": 60, "max_requests": 100},
        honeypot={"paths": ["/admin/config", "/wp-admin", "/.env"]},
        brute_force={"enabled": True, "max_attempts": 5},
        csrf={"enabled": True},
        secure_headers={"enabled": True},
        sanitize={"enabled": True},
        audit={"encrypt": True, "log_file": "audit.log"},
        telemetry={"enabled": True, "service_name": "my-api"},
        metrics={"enabled": True},
    ),
)
```

### CORS Policy

```python
# Fail-closed by default — explicitly allow origins
config = AraxysConfig(
    secret_key="...",
    cors={"allow_origins": ["https://app.example.com"], "allow_methods": ["GET", "POST", "PUT"]},
)
# CORS middleware is always registered. Empty allow_origins = deny all.
```

### IP Access Control

```python
# Allow mode — only listed IPs get through
config = AraxysConfig(
    secret_key="...",
    ip_access={"enabled": True, "mode": "allow", "allowlist": ["10.0.1.0/24", "192.168.1.100"]},
)
```

### CSRF Protection

```python
from fastapi import Depends
from araxys import csrf_protected, CSRFConfig

# Per-route opt-in — only state-changing endpoints
@app.post("/submit", dependencies=[Depends(csrf_protected(CSRFConfig()))])
async def submit_form():
    return {"status": "ok"}
```

### Brute Force + Password Policy

```python
from fastapi import Depends
from araxys import password_policy_dependency, PasswordPolicyConfig

@app.post("/auth/register")
async def register(
    password: str = Depends(password_policy_dependency(PasswordPolicyConfig())),
):
    # Password already validated — min 8 chars, upper, lower, digit, special
    return {"status": "registered"}
```

### API Key Authentication

```python
from fastapi import Depends
from araxys import Scope
from araxys.api_keys.dependencies import require_api_key
from araxys.api_keys.models import APIKeyRecord

# Create a key
key = await shield.api_key_manager.create_key(
    owner="service-a",
    scopes=[Scope.READ, Scope.WRITE],
    ttl_days=90,
)
print(f"Save this key: {key.raw_key}")  # Shown only once!

### 💻 Command Line Interface (CLI)

Araxys includes a professional CLI for managing API keys and security assets directly from your terminal.

**Setup:**

```bash
# Install with CLI dependencies
pip install "araxys[cli]"

# Configure your storage
export ARAXYS_REDIS_URL="redis://localhost:6379"
```

**Usage:**

```bash
# Create a new key
araxys keys create --owner "service-a" --scopes "read,write" --ttl 90

# List active keys in a beautiful table
araxys keys list

# Revoke a key by its prefix
araxys keys revoke [prefix]
```

# Protect an endpoint
@app.get("/data")
async def get_data(
    key: APIKeyRecord = Depends(
        require_api_key(Scope.READ, manager=shield.api_key_manager)
    ),
):
    return {"data": "protected", "owner": key.owner}
```

### JWT with Token Rotation

```python
from fastapi import Depends
from araxys import Scope
from araxys.jwt_auth.dependencies import require_jwt
from araxys.jwt_auth.tokens import TokenPayload

# Login — issue tokens
@app.post("/auth/login")
async def login(username: str, password: str):
    # ... validate credentials ...
    pair = await shield.jwt_manager.create_token_pair(
        subject=user.id,
        scopes=[Scope.READ, Scope.WRITE],
    )
    return pair.model_dump()

# Refresh — rotate tokens (old refresh token is blacklisted)
@app.post("/auth/refresh")
async def refresh(refresh_token: str):
    new_pair = await shield.jwt_manager.rotate_tokens(refresh_token)
    return new_pair.model_dump()

# Protected endpoint
@app.get("/profile")
async def profile(
    user: TokenPayload = Depends(
        require_jwt(Scope.READ, jwt_manager=shield.jwt_manager)
    ),
):
    return {"user_id": user.sub, "scopes": user.scopes}
```

---

## 🏗️ Architecture

```
src/araxys/
├── core/               # Config, exceptions, shared types
│   ├── config.py       # Pydantic Settings (env var support)
│   ├── exceptions.py   # Custom exception hierarchy
│   └── types.py        # Scope, AuditEntry, SecurityEvent, SecurityEventType
├── cors/               # 🚦 CORS policy manager
│   └── middleware.py   # Per-origin, fail-closed, preflight
├── ip_access/          # 🛑 IP access control
│   ├── backends.py     # Protocol + InMemory + Redis
│   └── middleware.py   # Allow/block/hybrid modes, CIDR
├── csrf/               # 🍪 CSRF protection
│   ├── tokens.py       # Double-submit cookie, constant-time
│   └── dependencies.py # Per-route FastAPI dependency
├── brute_force/        # 🔒 Brute force + password policy
│   ├── backends.py     # InMemory + Redis attempt tracking
│   ├── limiter.py      # Lockout middleware
│   └── password_policy.py  # Complexity rules + HIBP
├── sessions/           # 👥 Session management
│   ├── storage.py      # Protocol + InMemory + Redis
│   └── manager.py      # Max concurrent, idle timeout, touch, revocation, cleanup
├── telemetry/          # 📡 OpenTelemetry integration
│   ├── tracer.py       # Graceful no-op fallback, span CM
│   └── middleware.py   # Auto-spanning HTTP middleware
├── webhooks/           # 📨 Security event webhooks
│   ├── emitter.py      # SecurityEventBus (async pub/sub)
│   ├── delivery.py     # httpx POST + retry (1s/2s/4s) + SSRF guard
│   ├── dlq.py          # Dead-letter queue backend + consumer
│   └── dlq_routes.py   # DLQ admin API (list/inspect/replay/purge)
├── webauthn/           # 🔏 WebAuthn / Passkeys (v0.10)
│   ├── manager.py      # Registration + authentication ceremonies
│   ├── cose.py         # COSE key parsing (EC2, RSA)
│   ├── attestation.py  # Attestation verification (none, packed)
│   ├── storage.py      # CredentialStore protocol + Redis/InMemory
│   ├── challenges.py   # ChallengeStore with TTL
│   ├── dependencies.py # FastAPI Depends injection
│   ├── models.py       # RelyingPartyConfig, CredentialRecord
│   └── exceptions.py   # WebAuthnError, COSEAlgorithmError
├── mfa/                # 🔐 MFA / TOTP (v0.9)
│   ├── manager.py      # TOTP gen + verify (RFC 6238)
│   ├── models.py       # MFA config
│   └── dependencies.py # FastAPI Depends
├── rbac/               # 🏷️ RBAC (v0.9)
│   ├── models.py       # Permission, Role models
│   └── manager.py      # Role assignment + permission check
├── oauth/              # 🔓 OAuth2 / OIDC (v0.9)
│   ├── flow.py         # PKCE authorization + token exchange
│   ├── router.py       # Login + callback routes
│   └── providers/      # Google, GitHub, etc.
├── admin/              # 💻 Admin API (v0.9)
│   └── router.py       # Sessions, IP bans, API keys, DLQ management
├── metrics/            # 📊 Prometheus metrics
│   ├── collector.py    # 9 counters + histogram registry
│   └── endpoint.py     # /metrics scrape endpoint
├── rate_limit/         # 🚦 Dynamic rate limiting
│   ├── backends.py     # Protocol + InMemory + Redis
│   ├── limiter.py      # Sliding window + escalation
│   └── middleware.py   # ASGI middleware
├── honeypot/           # 🍯 Trap endpoints
│   ├── trap.py         # Route registration + auto-ban
│   └── middleware.py   # IP ban enforcement
├── api_keys/           # 🔑 API Key management
│   ├── models.py       # Pydantic models
│   ├── manager.py      # CRUD + verification
│   ├── storage.py      # Protocol + InMemory + Redis
│   └── dependencies.py # FastAPI dependencies
├── cli.py              # 💻 Command Line Interface (Typer + Rich)
├── jwt_auth/           # 🎟️ JWT tokens
│   ├── tokens.py       # Create, decode, rotate
│   ├── storage.py      # JTI blacklisting
│   └── dependencies.py # FastAPI dependencies
├── headers/            # 🛡️ Security headers
│   └── middleware.py   # HSTS, CSP, COOP, CORP
├── sanitize/           # 🧹 Input sanitization
│   ├── patterns.py     # SQLi + XSS regex patterns
│   ├── filters.py      # Detection + stripping
│   └── middleware.py   # ASGI middleware
├── audit/              # 📋 Audit logging
│   ├── encryption.py   # AES-256-GCM + PBKDF2
│   ├── logger.py       # Structured logger
│   └── events.py       # Event types
├── db_security/        # 🗄️ Database security (v0.5)
│   ├── pool.py         # Connection pooling + health
│   ├── secrets.py      # Env→Vault→AWS resolver chain
│   ├── tls.py          # TLS config + cert pinning
│   ├── audit.py        # Query auditor + slow detection
│   ├── manager.py      # Lifecycle orchestrator
│   └── dependencies.py # FastAPI DI
└── shield.py           # ⚡ Main orchestrator + shutdown()
```

### Middleware Chain (outer → inner)

```
CORS → SecureHeaders → Telemetry → RateLimit → BruteForce → IP Access → Honeypot → Sanitize → Auth (JWT / APIKey / WebAuthn)
```

---

## 🔐 Security Features in Detail

### CORS Policy Manager (v0.3)

- **Per-origin allowlist** with exact match and wildcard `*` support
- **Fail-closed default**: empty allowlist denies all cross-origin requests
- **Preflight handling**: automatic OPTIONS 200 with correct headers
- Full header injection: `Access-Control-Allow-Origin`, `Allow-Methods`, `Allow-Headers`, `Allow-Credentials`, `Expose-Headers`, `Max-Age`

### IP Access Control (v0.3)

- Three modes: **allow** (default-deny), **block** (default-allow), **hybrid**
- **CIDR support** for IPv4 and IPv6
- **X-Forwarded-For** fallback for proxied requests
- Pluggable backends (InMemory + Redis)

### CSRF Protection (v0.3)

- **Double-submit cookie** pattern
- **Constant-time comparison** via `secrets.compare_digest`
- **Per-route opt-in** as a FastAPI dependency — no global middleware overhead
- Configurable token expiry and cookie security

### Brute Force Protection (v0.3)

- **Account lockout** after N failed attempts (423 Locked response)
- **Auto-reset** on successful login
- **Password policy** with 6 configurable rules (length, upper, lower, digit, special)
- **HIBP integration** via k-anonymity model (opt-in)

### Session Management (v0.3)

- **Max concurrent sessions** per user with auto-revoke of oldest
- **Session listing** and per-session revocation
- Background cleanup loop for expired sessions
- `SecurityEvent` emission on create/revoke

### OpenTelemetry (v0.3)

- **Opt-in** — zero overhead when disabled or OTEL SDK absent
- Graceful **no-op fallback** when `opentelemetry` package not installed
- `araxys_span()` async context manager for custom spans
- Auto-spanning HTTP middleware

### Security Event Webhooks (v0.3)

- **Unified event bus** with 12 event types
- **Per-event-type webhook URLs** with retry (exponential backoff: 1s/2s/4s)
- **Fire-and-forget** delivery — never blocks the request
- Internally consumed by Prometheus metrics

### Prometheus Metrics (v0.3)

- **9 counters**: rate_limit_exceeded, honeypot_triggered, sanitize_blocked, jwt_rotated, csrf_failed, brute_force_lockout, ip_blocked, session_revoked, security_events
- **1 histogram**: middleware_duration_seconds
- Standard `/metrics` endpoint (configurable path)
- Opt-in, no-op when `prometheus-client` not installed

### Rate Limiting

- **Sliding window** counter per IP + endpoint
- **Escalating bans**: repeated violations increase ban duration exponentially
- **X-RateLimit headers**: `Limit`, `Remaining`, `Window` injected in every response
- **Path exclusion**: Skip `/docs`, `/healthz`, etc.

### Honeypot Endpoints

- Registers **fake routes** like `/admin/config`, `/wp-admin`, `/.env`
- Returns **200 OK** with fake content (doesn't alert the bot)
- **Auto-bans the IP** across ALL endpoints
- Integrates with audit logging

### API Key Management

- **256-bit entropy** keys via `secrets.token_urlsafe`
- Stored as **SHA-256 hashes** (raw key is never persisted)
- **Scope-based authorization**: `read`, `write`, `admin`
- **Expiration support** with configurable TTL
- **Pluggable storage**: implement the `APIKeyStorage` protocol with your database

### JWT with Token Rotation

- **Access + Refresh** token pairs following OAuth2 best practices
- **JTI-based revocation**: each refresh token has a unique ID
- **Replay attack detection**: reusing a rotated refresh token triggers an alert
- **Configurable TTLs**: access (default 30min), refresh (default 7 days)
- **Scope embedding** in token claims

### Secure Headers

| Header | Default Value |
|--------|--------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `0` (disabled — modern best practice) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` (v0.3) |
| `Cross-Origin-Resource-Policy` | `same-origin` (v0.3) |
| `Content-Security-Policy` | Configurable (CSP builder in v0.3) |
| `Permissions-Policy` | Configurable |
| `Server` | Hidden by default (v0.3) |

### Payload Sanitization

- **16 SQL injection patterns**: UNION, DROP, blind injection, time-based, etc.
- **9 XSS patterns**: script tags, JS URIs, event handlers, iframes
- **Recursive scanning** with configurable depth limit
- SQLi → **block** (400 response) · XSS → **strip** (bleach)

### Encrypted Audit Logging

- **AES-256-GCM** authenticated encryption (confidentiality + integrity)
- **PBKDF2-HMAC-SHA256** key derivation (480,000 iterations — OWASP 2023)
- **Per-entry unique salt + nonce** (no two entries share the same key material)
- **Tamper detection**: GCM authentication tag catches any modification
- Structured output via **structlog**

---

## ⚙️ Configuration

All settings support **environment variables** with the `ARAXYS_` prefix:

```bash
export ARAXYS_SECRET_KEY="your-production-secret-key-here!"
export ARAXYS_REDIS_URL="redis://localhost:6379"
export ARAXYS_CORS__ALLOW_ORIGINS='["https://myapp.com"]'
export ARAXYS_IP_ACCESS__ENABLED="true"
export ARAXYS_METRICS__ENABLED="true"
```

Or configure programmatically:

```python
from araxys import AraxysConfig, RateLimitConfig, HoneypotConfig, CORSConfig

config = AraxysConfig(
    secret_key="...",
    cors=CORSConfig(allow_origins=["https://app.example.com"]),
    ip_access={"enabled": True, "mode": "hybrid"},
    rate_limit=RateLimitConfig(
        max_requests=200,
        window_seconds=120,
        ban_threshold=10,
        ban_duration_seconds=600,
        escalation_multiplier=3.0,
    ),
    honeypot=HoneypotConfig(
        paths=["/admin", "/wp-login.php", "/.git/config"],
        ban_duration_seconds=7200,
    ),
    brute_force={"enabled": True, "max_attempts": 5},
    csrf={"enabled": True},
    telemetry={"enabled": True, "service_name": "my-api"},
    metrics={"enabled": True},
    jwt={"access_token_ttl_minutes": 15, "refresh_token_ttl_days": 30},
    audit={"encrypt": True, "log_file": "/var/log/araxys/audit.log"},
)
```

---

## 🧪 Testing

```bash
# Run all tests
uv run pytest tests/ -v

# With coverage
uv run pytest tests/ --cov=araxys --cov-report=term-missing
```

**1018 tests** covering all 21 modules — CORS, IP access, CSRF, brute force, sessions, telemetry, webhooks, DLQ, WebAuthn, MFA, RBAC, OAuth2/OIDC, admin, metrics, rate limiting, honeypots, API keys, JWT, headers, sanitization, audit logging, and database security.

---

## 🏭 Production Recommendations

| Aspect | Recommendation |
|--------|---------------|
| **Backends** | Use Redis (`araxys[redis]`) for multi-worker deployments |
| **Secret Key** | Generate with `openssl rand -hex 32` — never hardcode |
| **API Key Storage** | Implement `APIKeyStorage` protocol with your database |
| **Audit Logs** | Enable encryption + write to a dedicated log file |
| **Rate Limits** | Tune `max_requests` and `ban_threshold` per endpoint |
| **CORS** | Explicitly list allowed origins — never use `*` in production |
| **Observability** | Enable OTEL + Prometheus for production monitoring |
| **HTTPS** | Always deploy behind TLS — HSTS and secure cookies expect it |

---

## 📁 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Pydantic-E92063?style=for-the-badge&logo=pydantic&logoColor=white" alt="Pydantic">
  <img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT">
  <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis">
  <img src="https://img.shields.io/badge/OpenTelemetry-8B5CF6?style=for-the-badge&logo=opentelemetry&logoColor=white" alt="OTEL">
  <img src="https://img.shields.io/badge/Prometheus-E6522C?style=for-the-badge&logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/structlog-4B8BBE?style=for-the-badge&logo=python&logoColor=white" alt="structlog">
  <img src="https://img.shields.io/badge/cryptography-AES256-DC143C?style=for-the-badge" alt="cryptography">
  <img src="https://img.shields.io/badge/pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white" alt="pytest">
  <img src="https://img.shields.io/badge/Ruff-D7FF64?style=for-the-badge&logo=ruff&logoColor=black" alt="Ruff">
  <img src="https://img.shields.io/badge/mypy-strict-blue?style=for-the-badge" alt="mypy">
  <img src="https://img.shields.io/badge/uv-DE5FE9?style=for-the-badge&logo=uv&logoColor=white" alt="uv">
</p>

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with 🛡️ by <a href="https://github.com/andresramirez">Samuel Esteban Urrego Valencia</a></strong><br>
  <em>"Security shouldn't be an afterthought — it should be a single import."</em>
</p>
