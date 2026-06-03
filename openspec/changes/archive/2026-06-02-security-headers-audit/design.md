# Design: Security Headers Audit

## Technical Approach

Shared audit core (`auditor.py` — pure functions) consumed by two channels: an ASGI middleware for runtime monitoring and a CLI command for ad-hoc URL scanning. The audit engine evaluates headers against OWASP best-practice rules and returns structured `HeaderFinding` instances. Middleware emits findings via structlog and `SecurityEventBus`; CLI renders via Rich tables/JSON.

## Architecture Decisions

### Decision: Separate file for audit middleware

**Choice**: New file `audit_middleware.py`
**Alternatives**: Add `AuditHeadersMiddleware` to existing `middleware.py`
**Rationale**: `middleware.py` is the *setter* middleware; the new class is a *reader/auditor*. Separate files keep responsibilities distinct and follow the pattern where each middleware lives in its own module (`cors/middleware.py`, `sanitize/middleware.py`, etc.).

### Decision: Pure-function core auditor

**Choice**: Module `auditor.py` exports top-level functions — no class, no state
**Alternatives**: Class-based auditor with config injection
**Rationale**: Pure functions are trivially testable (no mocking), consumed identically by middleware and CLI, and all audit rules are stateless checks against header values.

### Decision: Middleware position

**Choice**: Between CORS and `SecureHeadersMiddleware` (outermost tier)
**Rationale**: Must see final response headers after all inner middleware and app have run. Registered after `_register_secure_headers()` but before `_register_cors()`, the execution order becomes: CORS → AuditHeaders → SecureHeaders → inner stack. The audit middleware wraps `call_next`, so it inspects headers after `SecureHeadersMiddleware` has set them.

### Decision: Config as None-default

**Choice**: `SecurityHeadersAuditConfig | None = None` on `AraxysConfig`
**Alternatives**: Always-on with `enabled` flag
**Rationale**: Follows the established `Optional[XConfig] | None` pattern for optional modules (MFA, WebAuthn, ThreatIntel). `None` ⇒ module absent; presence + `enabled=True` ⇒ active. Disabled by default per spec requirement.

## Data Flow

```
Request → CORS → AuditHeadersMiddleware → SecureHeaders → [inner stack] → App
                    ↑  wraps call_next to audit final response headers
                    ↓
          audit_headers(response.headers) → list[HeaderFinding]
          ├── structlog emit (always)
          └── SecurityEventBus.emit (if bus available)

CLI path:
httpx.get(url) → audit_headers(response.headers) → Rich Table / JSON stdout
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/headers/auditor.py` | Create | Pure audit functions: `audit_headers()`, per-header rule checkers |
| `src/araxys/headers/audit_middleware.py` | Create | `AuditHeadersMiddleware(BaseHTTPMiddleware)` with sampling |
| `src/araxys/headers/__init__.py` | Modify | Export `audit_headers`, `AuditHeadersMiddleware`, `HeaderFinding` |
| `src/araxys/core/config.py` | Modify | Add `SecurityHeadersAuditConfig` + field on `AraxysConfig` |
| `src/araxys/core/types.py` | Modify | Add `HEADER_AUDIT_WARNING`, `HEADER_AUDIT_FAIL` to `SecurityEventType` |
| `src/araxys/shield.py` | Modify | Add `_register_headers_audit()` between secure_headers and cors |
| `src/araxys/cli.py` | Modify | Add `audit-headers` Typer command |
| `tests/test_headers_audit.py` | Create | Unit tests for auditor rules, middleware integration tests |
| `tests/test_headers.py` | Modify | Add audit middleware integration scenarios |

## Interfaces / Contracts

```python
@dataclass
class HeaderFinding:
    header: str              # e.g. "Content-Security-Policy"
    status: str              # "pass" | "warn" | "fail"
    severity: str            # "CRITICAL" | "HIGH" | "WARNING" | "INFO"
    message: str
    current_value: str | None = None
    recommendation: str | None = None

def audit_headers(headers: dict[str, str]) -> list[HeaderFinding]:
    """Return findings for a single response's headers."""

class SecurityHeadersAuditConfig(BaseModel):
    enabled: bool = False
    sample_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    exclude_paths: list[str] = Field(default_factory=list)
    emit_to_event_bus: bool = True
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Every audit rule independently | Parametrized pytest: header+value → expected `HeaderFinding` |
| Unit | `audit_headers()` full pass | Table-driven: dict of headers → list of expected findings |
| Integration | Middleware emits on sampled requests | `TestClient` with middleware, verify structlog output |
| Integration | CLI fetches URL and outputs JSON | Invoke with httpx mock, assert stdout |
| E2E | Full middleware chain audit | Registered via `AraxysShield`, verify event bus receives findings |

## Migration / Rollout

No migration required. Module is disabled by default (`headers_audit=None`). Users opt in via `ARAXYS_HEADERS_AUDIT__ENABLED=true` or `headers_audit=SecurityHeadersAuditConfig(enabled=True)` in code.

## Open Questions

- [ ] Cookie audit: use stdlib `http.cookies.SimpleCookie` or manual regex for parsing `Set-Cookie`? **Recommendation**: stdlib for RFC 6265 compliance.
- [ ] Should `Permissions-Policy` audit flag `*` wildcards on sensitive features (camera, microphone) as warnings? **Recommendation**: yes — warn on `camera=*`, `microphone=*`.
