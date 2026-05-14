<p align="center">
  <img src="assets/araxyslogo.png" alt="Araxys Logo" width="400">
</p>

<p align="center">
  <strong>Plug & Play Security for FastAPI</strong><br>
  <em>Rate limiting · Honeypots · JWT · API Keys · Encrypted Audit Logging</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.13+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Pydantic-v2-E92063?style=for-the-badge&logo=pydantic&logoColor=white" alt="Pydantic">
  <img src="https://img.shields.io/badge/uv-package%20manager-DE5FE9?style=for-the-badge&logo=uv&logoColor=white" alt="uv">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/encryption-AES--256--GCM-DC143C?style=flat-square" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/JWT-OAuth2%20compliant-000000?style=flat-square&logo=jsonwebtokens&logoColor=white" alt="JWT">
  <img src="https://img.shields.io/badge/Redis-optional-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis">
  <img src="https://img.shields.io/badge/structlog-logging-4B8BBE?style=flat-square" alt="structlog">
  <img src="https://img.shields.io/badge/tests-63%20passed-brightgreen?style=flat-square" alt="Tests">
</p>

---

## ⚡ What is Araxys?

**Araxys** is a comprehensive security library for [FastAPI](https://fastapi.tiangolo.com/) that provides enterprise-grade protection with a plug & play architecture. Add security to your API with **three lines of code** — no rewrites, no boilerplate.

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
| 🚦 **Rate Limiting** | Dynamic sliding window with escalating bans | ✅ Ready |
| 🍯 **Honeypots** | Fake endpoints that auto-ban bots | ✅ Ready |
| 🔑 **API Keys** | Scoped keys with SHA-256 hashing & expiration | ✅ Ready |
| 🎟️ **JWT Auth** | Access + Refresh tokens with rotation & revocation | ✅ Ready |
| 🛡️ **Secure Headers** | HSTS, CSP, X-Frame-Options & more (OWASP) | ✅ Ready |
| 🧹 **Sanitization** | SQLi detection & XSS stripping | ✅ Ready |
| 📋 **Audit Logging** | AES-256-GCM encrypted structured logs | ✅ Ready |

---

## 📦 Installation

```bash
# Core (in-memory backends)
pip install araxys

# With Redis support (recommended for production)
pip install araxys[redis]

# Development
pip install araxys[dev]
```

> **Requires Python 3.13+**

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
        rate_limit={"window_seconds": 60, "max_requests": 100},
        honeypot={"paths": ["/admin/config", "/wp-admin", "/.env"]},
        secure_headers=True,
        sanitize=True,
        audit={"encrypt": True, "log_file": "audit.log"},
    ),
)
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
│   └── types.py        # Scope, AuditEntry, SecurityContext
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
│   ├── storage.py      # Protocol + InMemory
│   └── dependencies.py # FastAPI dependencies
├── jwt_auth/           # 🎟️ JWT tokens
│   ├── tokens.py       # Create, decode, rotate
│   ├── storage.py      # JTI blacklisting
│   └── dependencies.py # FastAPI dependencies
├── headers/            # 🛡️ Security headers
│   └── middleware.py   # HSTS, CSP, X-Frame-Options
├── sanitize/           # 🧹 Input sanitization
│   ├── patterns.py     # SQLi + XSS regex patterns
│   ├── filters.py      # Detection + stripping
│   └── middleware.py   # ASGI middleware
├── audit/              # 📋 Audit logging
│   ├── encryption.py   # AES-256-GCM + PBKDF2
│   ├── logger.py       # Structured logger
│   └── events.py       # Event types
└── shield.py           # ⚡ Main orchestrator
```

---

## 🔐 Security Features in Detail

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
| `Content-Security-Policy` | Configurable |
| `Permissions-Policy` | Configurable |

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
```

Or configure programmatically:

```python
from araxys import AraxysConfig, RateLimitConfig, HoneypotConfig

config = AraxysConfig(
    secret_key="...",
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

**63 tests** covering all 7 modules — rate limiting, honeypots, API keys, JWT, headers, sanitization, and audit logging.

---

## 🏭 Production Recommendations

| Aspect | Recommendation |
|--------|---------------|
| **Backends** | Use Redis (`araxys[redis]`) for multi-worker deployments |
| **Secret Key** | Generate with `openssl rand -hex 32` — never hardcode |
| **API Key Storage** | Implement `APIKeyStorage` protocol with your database |
| **Audit Logs** | Enable encryption + write to a dedicated log file |
| **Rate Limits** | Tune `max_requests` and `ban_threshold` per endpoint |
| **HTTPS** | Always deploy behind TLS — HSTS headers expect it |

---

## 📁 Tech Stack

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Pydantic-E92063?style=for-the-badge&logo=pydantic&logoColor=white" alt="Pydantic">
  <img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT">
  <img src="https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis">
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
