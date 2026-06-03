# Security Headers Audit Specification

## Purpose

Audit and report on HTTP security header posture against OWASP best practices. Shared core consumed by middleware (runtime monitoring for Araxys apps) and CLI (ad-hoc scanning of any URL). Module disabled by default.

## Requirements

### Requirement: CSP Audit

The system MUST evaluate the Content-Security-Policy header. It MUST detect `'unsafe-inline'`, `'unsafe-eval'`, and missing directives (`default-src`, `script-src`, `object-src`). It MUST warn with CRITICAL severity when CSP is absent entirely.

#### Scenario: CSP present and secure

- GIVEN `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'`
- WHEN the audit runs
- THEN finding severity is INFO and status is `pass`

#### Scenario: CSP contains unsafe-inline

- GIVEN `Content-Security-Policy: default-src 'self' 'unsafe-inline'`
- WHEN the audit runs
- THEN finding severity is HIGH with recommendation to remove `'unsafe-inline'`

#### Scenario: CSP missing

- GIVEN no `Content-Security-Policy` header
- WHEN the audit runs
- THEN finding severity is CRITICAL with recommendation to set a restrictive CSP

### Requirement: HSTS Audit

The system MUST evaluate the `Strict-Transport-Security` header. It MUST verify `max-age >= 31536000` (1 year), presence of `includeSubDomains`, and `preload`. It MUST warn with CRITICAL severity when HSTS is absent.

#### Scenario: HSTS fully configured

- GIVEN `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- WHEN the audit runs
- THEN finding status is `pass` with severity INFO

#### Scenario: HSTS max-age too short

- GIVEN `Strict-Transport-Security: max-age=86400`
- WHEN the audit runs
- THEN finding severity is HIGH with recommendation to increase max-age to at least one year

#### Scenario: HSTS missing

- GIVEN no `Strict-Transport-Security` header
- WHEN the audit runs
- THEN finding severity is CRITICAL

### Requirement: Cookie Security Audit

The system MUST inspect all `Set-Cookie` headers for `Secure`, `HttpOnly`, and `SameSite` attributes. It MUST detect `SameSite=None` without `Secure`. It SHOULD recommend `__Host-` prefix for session cookies.

#### Scenario: Cookie fully hardened

- GIVEN `Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict`
- WHEN the audit runs
- THEN finding status is `pass`

#### Scenario: Cookie missing Secure flag

- GIVEN `Set-Cookie: session=abc; HttpOnly`
- WHEN the audit runs
- THEN finding severity is HIGH with recommendation to add `Secure`

### Requirement: Cross-Origin Isolation Audit

The system MUST check `Cross-Origin-Opener-Policy` (require-corp or same-origin), `Cross-Origin-Embedder-Policy` (require-corp), and `Cross-Origin-Resource-Policy`. It MUST warn on missing or weak values.

#### Scenario: Full cross-origin isolation

- GIVEN COOP=same-origin, COEP=require-corp, CORP=same-origin
- WHEN the audit runs
- THEN findings status is `pass` for all three headers

#### Scenario: Cross-origin headers missing

- GIVEN no COOP, COEP, or CORP headers
- WHEN the audit runs
- THEN each missing header reports WARNING severity

### Requirement: OWASP Recommended Headers Audit

The system MUST check: `X-Content-Type-Options` (MUST be `nosniff`), `X-Frame-Options` (MUST be `DENY` or `SAMEORIGIN`), `Referrer-Policy` (MUST NOT be `unsafe-url` or `no-referrer-when-downgrade`), `Permissions-Policy`, and `X-DNS-Prefetch-Control`.

#### Scenario: All recommended headers present and correct

- GIVEN all OWASP recommended headers with secure values
- WHEN the audit runs
- THEN all findings show `pass` status

#### Scenario: X-Content-Type-Options missing

- GIVEN no `X-Content-Type-Options` header
- WHEN the audit runs
- THEN finding severity is HIGH with recommendation to set `nosniff`

### Requirement: Structured Audit Report

The system MUST return a structured report containing: URL, numeric score (0-100), timestamp, per-finding severity (CRITICAL/WARNING/INFO), status (pass/warn/fail), current value, and recommendation text. The report SHOULD include a severity count summary.

#### Scenario: Report generated for audited URL

- GIVEN headers from `https://example.com` with 2 pass and 1 fail finding
- WHEN the audit completes
- THEN the report includes score < 100, three findings with severities, and a summary map

### Requirement: Middleware Integration

The system SHOULD provide an ASGI middleware that audits each response after all other middleware. It SHOULD support `sample_rate` (0.0-1.0) to control overhead. It SHOULD emit findings via structlog and/or the `SecurityEventBus`. It MUST be disabled by default.

#### Scenario: Middleware audits response

- GIVEN middleware enabled with `sample_rate=1.0` and a response with weak headers
- WHEN the response passes through
- THEN findings are emitted via structlog with severity and recommendation

#### Scenario: Sampling reduces overhead

- GIVEN middleware with `sample_rate=0.1` and 100 requests
- WHEN all 100 requests complete
- THEN approximately 10 responses are audited

### Requirement: CLI Command

The system SHOULD support `araxys audit-headers <url>` that fetches headers via HTTP and runs the audit. It SHOULD support `--format json|table` and `--fail-on <severity>` for CI/CD exit codes.

#### Scenario: CLI audits a remote URL

- GIVEN a reachable HTTPS URL
- WHEN `araxys audit-headers https://example.com --format json` runs
- THEN a JSON report with score and findings is printed to stdout

#### Scenario: CLI fails on unreachable URL

- GIVEN an unreachable URL
- WHEN `araxys audit-headers https://nonexistent.local` runs
- THEN a connection error is reported with non-zero exit code
