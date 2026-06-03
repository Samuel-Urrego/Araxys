# Tasks: Security Headers Audit

## Phase 1: Core Auditor

- [x] 1.1 Create `src/araxys/headers/auditor.py` — `AuditFinding` dataclass + `audit_headers(headers: dict[str, str]) -> list[AuditFinding]` pure function
  - CSP: present, no 'unsafe-inline', no 'unsafe-eval', has default-script-src
  - HSTS: max-age >= 31536000, includeSubDomains, preload
  - Cookies (Set-Cookie): Secure, HttpOnly, SameSite, __Host- prefix
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY or SAMEORIGIN
  - Cross-Origin-Opener-Policy: same-origin or require-corp
  - Cross-Origin-Embedder-Policy: require-corp
  - Referrer-Policy: strict-origin-when-cross-origin or stricter
  - Permissions-Policy: no dangerous features
  Each finding: header, severity (CRITICAL/WARNING/INFO), message, recommendation, current_value, expected

- [x] 1.2 Create `src/araxys/headers/audit_middleware.py` — `AuditHeadersMiddleware(BaseHTTPMiddleware)`:
  - Runs outermost to see final headers
  - Config: `enabled: bool = True`, `sample_rate: float = 1.0`, `exclude_paths: list[str]`
  - On each response: `audit_headers(dict(response.headers))`, log via structlog at warning level per finding
  - Follow existing SecureHeadersMiddleware pattern

- [x] 1.3 Add `AuditConfig` to `src/araxys/headers/config.py`

- [x] 1.4 Wire `_register_audit_headers()` in `src/araxys/shield.py` — register between cors and secure_headers (outermost)

- [x] 1.5 Add CLI `audit-headers <url>` command to `src/araxys/cli.py` — uses httpx, runs audit_headers, outputs Rich table

- [x] 1.6 Export from `src/araxys/headers/__init__.py`

## Phase 2: Configuration & Types

- [x] 2.1 Add `AuditConfig` field to `AraxysConfig` in `src/araxys/core/config.py`
- [x] 2.2 Add `HEADER_AUDIT_WARNING` and `HEADER_AUDIT_FAIL` to `SecurityEventType` in `src/araxys/core/types.py`

## Phase 3: Tests

- [x] 3.1 Create `tests/test_headers_audit.py` — 50 tests covering:
  - Unit tests for every audit rule (CSP, HSTS, Cookies, X-Content-Type-Options, X-Frame-Options, COOP, COEP, Referrer-Policy, Permissions-Policy)
  - Integration tests for full `audit_headers()` function
  - Middleware integration tests (TestClient with AuditHeadersMiddleware)
  - CLI command tests (httpx mock, JSON/table formats, fail-on severity, error handling)
  - AuditFinding dataclass construction tests

### Review Workload Forecast
- 400-line budget risk: Low
- Chained PRs recommended: No
- Decision needed before apply: No
