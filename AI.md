# 🛡️ Araxys: Agent Instructions & Context

This document provides high-density technical context for AI agents (LLMs) working with the Araxys security library. It prioritizes technical facts, type signatures, and known constraints over introductory prose.

## 🏗️ Architecture Summary

Araxys uses an **Orchestrator Pattern** (`AraxysShield`) to wire specialized middlewares to a FastAPI application.

**Middleware Order (from outer to inner):**
1. `SecureHeadersMiddleware`
2. `RateLimitMiddleware`
3. `HoneypotMiddleware`
4. `SanitizeMiddleware`
5. `JWTAuthMiddleware` / `APIKeyMiddleware` (typically route-level)

## 🔑 Key Abstractions

| Component | Module Path | Responsibility |
|-----------|-------------|----------------|
| `AraxysShield` | `araxys.shield` | Entry point; wiring and config orchestration. |
| `APIKeyManager`| `araxys.api_keys.manager` | Key generation, SHA-256 hashing, and verification. |
| `JWTManager` | `araxys.jwt_auth.tokens` | Token creation, decoding, and blacklist checks. |
| `Storage` | `araxys.*.storage` | Protocols for Redis or InMemory persistence. |
| `Scope` | `araxys.core.types` | Enum for permission-based access control. |

## ⚠️ Critical Implementation Gotchas

> [!IMPORTANT]
> **Runtime Annotations**: Do NOT move `fastapi.Request`, `fastapi.Response`, `fastapi.BackgroundTasks`, or Pydantic models (like `Scope`) into `TYPE_CHECKING` blocks. Doing so breaks runtime dependency injection and Pydantic model rebuilding. Use `# noqa: TC001/TC002` to satisfy Ruff.

- **API Key Constraints**: 
    - `prefix`: Exactly 8 characters (enforced by `min_length/max_length` in `APIKeyRecord`).
    - `key_hash`: SHA-256 (64 hex characters).
- **Encryption**: `AraxysConfig.secret_key` must be a high-entropy string (>= 32 chars) as it's used for AES-256-GCM encryption in audit logs.
- **Async First**: All storage operations and manager methods are `async`.

## 🛠️ Common Usage Patterns

### 1. Initializing Shield
```python
from araxys import AraxysShield, AraxysConfig
shield = AraxysShield(app, AraxysConfig(secret_key="...", redis_url="..."))
```

### 2. Protecting a Route with Scoped API Keys
```python
from fastapi import Depends
from araxys.api_keys.dependencies import require_api_key
from araxys.core.types import Scope

@app.get("/secure", dependencies=[Depends(require_api_key(scopes=[Scope.WRITE]))])
async def secure_endpoint():
    return {"status": "ok"}
```

## 💻 CLI Operations (AX)
The `araxys` CLI is the preferred way for agents to perform environment management.
- **Set Context**: `export ARAXYS_REDIS_URL="redis://..."`
- **Key Creation**: `araxys keys create --owner "name" --scopes "read,write"`
- **Key Revocation**: `araxys keys revoke <prefix>`

## 🧪 Testing Guidelines
- **Storage**: Use `fakeredis.aioredis.FakeRedis` for testing Redis-dependent modules.
- **Async**: Use `@pytest.mark.asyncio`.
- **Typing**: All test functions MUST have an explicit `-> None` return type hint to satisfy `strict = true` Mypy settings.
- **Fixtures**: Standard fixtures for `storage` and `manager` are available in `tests/conftest.py` (when implemented) or within module tests.
