## Exploration: security-headers-audit

### Current State

Araxys v0.14 has a well-established `SecureHeadersMiddleware` (`src/araxys/headers/middleware.py`) that **sets** security headers on every response. It does NOT audit, analyze, or report on the final state of response headers. The current module structure under `src/araxys/headers/` is minimal:

```
src/araxys/headers/
├── __init__.py          # Exports SecureHeadersMiddleware, build_csp_header
├── middleware.py        # SecureHeadersMiddleware (153 lines)
└── csp.py              # CSP builder from CSPDirectiveConfig (69 lines)
```

**Headers currently set by `SecureHeadersMiddleware`** (when enabled):

| Header | Default Value | Config Field |
|--------|--------------|-------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `hsts_max_age`, `hsts_include_subdomains` |
| `X-Content-Type-Options` | `nosniff` | `content_type_nosniff` |
| `X-Frame-Options` | `DENY` | `frame_options` |
| `X-XSS-Protection` | `0` (disabled — modern best practice) | hardcoded |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `referrer_policy` |
| `Content-Security-Policy` | Not set by default | `content_security_policy` (raw) or `csp_directives` (structured) |
| `Permissions-Policy` | Not set by default | `permissions_policy` (raw) or `permissions_policy_directives` (structured) |
| `Cross-Origin-Opener-Policy` | `same-origin` | `coop` |
| `Cross-Origin-Embedder-Policy` | Not set by default | `coep` |
| `Cross-Origin-Resource-Policy` | `same-origin` | `corp` |
| `Server` | **Stripped** (hidden) | `hide_server` |

**What's missing from the audit perspective**:
- No analysis of whether the headers that ARE set have **secure values** (e.g., is CSP too permissive? does `frame_options` use `SAMEORIGIN` instead of `DENY`?)
- No detection of **missing** headers that OWASP recommends (CSP, Permissions-Policy)
- No cookie security analysis (Secure, HttpOnly, SameSite flags on `Set-Cookie`)
- No detection of **Header set by the app** that might conflict with or weaken Araxys-set headers
- No reporting mechanism for header posture

**Relevant existing patterns in the codebase**:

1. **Security event emission**: `SecurityEventBus` (`src/araxys/webhooks/emitter.py`) — async pub/sub via `asyncio.Queue`. Modules emit `SecurityEvent` dataclasses with `SecurityEventType` enum values. Already used by rate_limit, honeypot, brute_force, etc. A header audit could emit events like `HEADER_AUDIT_WARNING` or `HEADER_AUDIT_FAIL`.

2. **Audit logging**: `AuditLogger` (`src/araxys/audit/logger.py`) — encrypted log entries with `AuditEventType`. Could be extended for header audit events.

3. **Structlog**: Used throughout (e.g., `structlog.get_logger("araxys.shield")`). Header audit findings could be logged as structured log events.

4. **CLI pattern**: Typer + Rich for table-based output (`src/araxys/cli.py`). Subcommands like `keys`, `waf`, `threat-intel` use rich tables/panels for output.

5. **Middleware registration**: `shield.py` `_register_secure_headers()` checks `config.secure_headers.enabled` and calls `app.add_middleware()`. An audit middleware would follow the identical pattern.

6. **Config pattern**: Every module has a Pydantic `BaseModel` config class in `src/araxys/core/config.py`, nested under `AraxysConfig`. Optional modules use `None` as default (disabled).

**Middleware execution order** (from `shield.py`, outermost → innermost):
```
CORS → SecureHeaders → CSRF → Telemetry → RateLimit → BruteForce → IPAccess →
Honeypot → AccountProtection → Malware → PromptInjection → XXE → Sanitize
```

An audit middleware would need to run **outermost** (after CORS, or even after all middleware) to see the FINAL response headers, including any set by the application endpoints themselves.

### Affected Areas

| File/Module | Why Affected |
|-------------|-------------|
| `src/araxys/headers/auditor.py` | **NEW** — Core audit logic: pure functions that take headers + config and return findings |
| `src/araxys/headers/middleware.py` | **MODIFIED** — New `SecurityHeadersAuditMiddleware` class (or a new file `audit_middleware.py`) |
| `src/araxys/headers/__init__.py` | **MODIFIED** — Export new public symbols |
| `src/araxys/core/config.py` | **MODIFIED** — New `SecurityHeadersAuditConfig` BaseModel, added to `AraxysConfig` |
| `src/araxys/core/types.py` | **MODIFIED** — New `SecurityEventType` entries (`HEADER_AUDIT_WARNING`, `HEADER_AUDIT_FAIL`, `HEADER_AUDIT_PASS`) |
| `src/araxys/shield.py` | **MODIFIED** — New `_register_headers_audit()` method + registration call in `_register_middleware_order` |
| `src/araxys/cli.py` | **MODIFIED** (if CLI path chosen) — New `audit-headers` subcommand |
| `src/araxys/__init__.py` | **POSSIBLY MODIFIED** — Export new configs/middleware if public API |
| `tests/test_headers.py` | **MODIFIED** — Tests for audit logic and middleware |

**Potential file tree after implementation**:
```
src/araxys/headers/
├── __init__.py           # Exports: SecureHeadersMiddleware, AuditMiddleware, build_csp_header, audit_headers
├── middleware.py          # SecureHeadersMiddleware (existing, unchanged except possibly a mode flag)
├── audit_middleware.py    # NEW — AuditHeadersMiddleware
├── auditor.py             # NEW — Core audit functions (pure, testable)
└── csp.py                 # Existing CSP builder (unchanged)
```

### Approaches

#### Approach 1 — Middleware-Only Audit (passive analyzer)

**How it works**: A new `AuditHeadersMiddleware` (ASGI middleware, registered outermost) inspects the response after all other middleware and the app have run. On each response, it evaluates the final headers against OWASP best-practice rules and emits findings via the `SecurityEventBus` and/or structlog. Configurable severity thresholds and report destinations.

```python
class AuditHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if self._should_audit(request):
            findings = audit_response_headers(dict(response.headers), self._rules)
            for finding in findings:
                await self._event_bus.emit(SecurityEvent(
                    event_type=SecurityEventType.HEADER_AUDIT_WARNING,
                    severity=finding.severity,
                    message=finding.message,
                    metadata={"header": finding.header, "value": finding.value},
                ))
        return response
```

| Pros | Cons | Complexity |
|------|------|------------|
| Fully automatic — plug & play like all other Araxys modules | Only works for Araxys-wrapped apps | Low-Medium |
| No user action required after config | Cannot audit external/legacy apps | |
| Consistent with existing Araxys middleware pattern | Runtime overhead on every request (mitigated by sampling) | |
| Can emit to event bus, structlog, or audit logger | Must be outermost to see final headers — position-dependent | |
| Configurable sampling rate prevents overhead on every request | | |

#### Approach 2 — CLI-Only Command (external scanner)

**How it works**: A new `araxys audit-headers <url>` CLI command that uses `httpx` to fetch headers from a URL (any URL, not just Araxys apps), evaluates them, and produces a Rich-formatted report with pass/fail/warn for each header category. Can output JSON for CI/CD pipelines.

```bash
$ araxys audit-headers https://example.com --format json
{
  "url": "https://example.com",
  "score": 72,
  "findings": [
    {"header": "Content-Security-Policy", "status": "missing", "severity": "high"},
    {"header": "Strict-Transport-Security", "status": "pass"},
    ...
  ]
}
```

| Pros | Cons | Complexity |
|------|------|------------|
| Works on ANY URL (not just Araxys apps) | Not automatic — user must run it manually | Low |
| Useful for CI/CD security scanning | Inconsistent with Araxys "automatic protection" philosophy | |
| Zero runtime overhead on the app | No real-time monitoring or alerting | |
| Easy to integrate into pipelines (JSON output) | User might forget to run it | |

#### Approach 3 — Hybrid (Shared Core + Both Channels) [RECOMMENDED]

**How it works**: The audit logic lives in pure functions in a new `src/araxys/headers/auditor.py` module. These functions are consumed by:
1. **Middleware** (`AuditHeadersMiddleware`) — for automatic runtime monitoring of Araxys apps
2. **CLI command** (`araxys audit-headers <url>`) — for ad-hoc scanning of any URL
3. Both share the same core rules, scoring, and report structure.

```
Core (auditor.py)
├── analyze_csp(csp_value: str) → CSPReport
├── analyze_cookie(set_cookie_headers: list[str]) → CookieReport
├── analyze_security_headers(headers: dict[str, str]) → AuditReport
└── score_report(report: AuditReport) → int (0-100)

Middleware (audit_middleware.py)     CLI (cli.py: audit-headers)
├── wraps auditor.analyze_*         ├── fetches headers via httpx
├── emits SecurityEvent             ├── wraps auditor.analyze_*
├── logs via structlog              └── renders via Rich tables/JSON
└── configurable sampling rate
```

| Pros | Cons | Complexity |
|------|------|------------|
| Maximum flexibility — runtime monitoring + ad-hoc scanning | More code to write (but shared core keeps it DRY) | Medium |
| Core logic is pure functions — trivially testable | Two integration points to maintain | |
| Consistent with existing patterns (event bus, structlog, CLI) | Need to decide whether core is part of public API | |
| Users choose the mode that fits their workflow | | |
| Can be extended with new rules without changing either integration | | |

### Audit Rules — What to Check

The audit engine should evaluate these aspects (OWASP Secure Headers Project + Mozilla Observatory guidelines):

**Critical (score heavily if missing/weak):**
1. **CSP** — Missing? Contains `unsafe-inline` or `unsafe-eval`? Missing `object-src 'none'`? Has `report-uri` or `report-to`? Too permissive `default-src`?
2. **HSTS** — Missing? Max-age < 6 months (15,768,000)? Missing `includeSubDomains`? No `preload`?
3. **X-Frame-Options** — Missing? Uses `SAMEORIGIN` instead of `DENY`? (CSP `frame-ancestors` preferred)
4. **X-Content-Type-Options** — Missing or not `nosniff`?
5. **Referrer-Policy** — Missing? Too permissive (e.g., `unsafe-url`, `no-referrer-when-downgrade`)?
6. **Permissions-Policy** — Missing entirely? Has overly broad permissions?

**Important (medium score impact):**
7. **Cookies** — `Set-Cookie` headers missing `Secure` flag? Missing `HttpOnly`? `SameSite=None` without `Secure`? Missing `__Host-` prefix for session cookies?
8. **Server header** — Exposed version info?
9. **Cross-Origin headers** — COOP, COEP, CORP missing? Inconsistent cross-origin isolation?
10. **Cache-Control** — Sensitive pages not setting `no-store`?

**Informational (low score impact):**
11. **Clear-Site-Data** — Present on logout?
12. **X-Permitted-Cross-Domain-Policies** — Present?
13. **Expect-CT** — Deprecated but informative
14. **X-DNS-Prefetch-Control** — Present?

### Audit Report Format

The report should be structured for multiple output channels:

```python
@dataclass
class HeaderFinding:
    header: str
    status: Literal["pass", "warn", "fail"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    message: str
    current_value: str | None = None
    recommendation: str | None = None

@dataclass
class AuditReport:
    url: str
    score: int                       # 0-100
    timestamp: datetime
    findings: list[HeaderFinding]
    summary: dict[Severity, int]     # count per severity level
```

### Integration Points

**Middleware** (for Araxys apps):
- `AuditHeadersMiddleware` registered in `shield.py` outermost (after CORS)
- Emits findings via `SecurityEventBus` (new `SecurityEventType` values)
- Logs structured events via `structlog`
- Configurable: sample rate, severity threshold, excluded paths

**CLI command** (for any URL):
- New subcommand: `araxys audit-headers <url>`
- Supports `--format json|table|text`
- Supports `--output <file>` for reports
- Supports `--fail-on <severity>` for CI/CD exit codes

### Recommendation

**Approach 3 — Hybrid (Shared Core + Middleware + CLI)**.

The core audit module (`auditor.py`) provides pure functions that are the single source of truth. The middleware wraps it for automatic runtime monitoring (consistent with Araxys "plug & play" philosophy). The CLI command wraps it for ad-hoc scanning of any URL.

**Implementation priority**:
1. **Phase 1**: Core audit module (`auditor.py`) with pure functions + unit tests — no middleware or CLI dependencies
2. **Phase 2**: Audit middleware (`audit_middleware.py`) + `SecurityHeadersAuditConfig` + `shield.py` registration
3. **Phase 3**: CLI `audit-headers` command

Phases 1 and 2 together deliver the core value proposition: automatic security header posture monitoring for Araxys apps.

### Risks

1. **Outermost position requirement**: The audit middleware must see the FINAL response headers. If registered in the wrong position, it will miss headers set by outer middleware. Mitigation: document the position requirement clearly, validate at startup.

2. **Performance overhead**: Analyzing every response header adds CPU cost. For high-traffic apps, this could be significant. Mitigation: `sample_rate` config (e.g., audit 1% of requests), exclude certain paths, and keep the pure functions lightweight.

3. **False positives on non-browser endpoints**: Headers like CSP and HSTS are irrelevant for internal microservice-to-microservice communication. Mitigation: `exclude_paths` config, or auto-detect `Content-Type: application/json` and skip certain checks.

4. **Cookie inspection requires parsing**: `Set-Cookie` is a multi-value header with complex parsing rules (RFC 6265). Mitigation: use Python's `http.cookies` module for parsing, handle multiple `Set-Cookie` headers.

5. **Config surface growth**: Adding a new config model to `AraxysConfig` adds complexity. Mitigation: follow the existing pattern — `None` as default means feature is disabled, minimal config when enabled.

6. **No access to response body in middleware**: The audit middleware can see response headers but not the body. It cannot detect CSP violations in real-time (that would need `report-uri` endpoint integration, which is a separate feature). Mitigation: limit scope to header analysis only; document that CSP violation reporting is out of scope.

### Ready for Proposal

**Yes** — the audit domain is well-understood, the OWASP guidelines provide clear rules, the Araxys architecture patterns are mapped, and the hybrid approach fits naturally into the existing codebase. The implementation is feasible within a single SDD change.

**Key decisions the proposal should answer**:
1. Whether to create a separate `audit_middleware.py` file or add the audit middleware to the existing `middleware.py`
2. The exact set of audit rules for the initial implementation (recommend: start with the 10 critical + important rules, add more in follow-up)
3. Whether the cookie audit should be part of the headers audit or a separate cookie-specific module
4. The `sample_rate` default (recommend: 1.0 for audit mode, configurable for production)
