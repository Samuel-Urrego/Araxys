## Exploration: aws-waf-bridge

### Current State

Araxys v0.13 is a mature security library with 30+ modules and 1490 passing tests. It uses a layered middleware architecture orchestrated by `AraxysShield`, with middleware registered in reverse order (innermost → outermost: Sanitize → XXE → PromptInjection → Malware → Honeypot → AccountProtection → IP Access → BruteForce → RateLimit → CSRF → Telemetry → SecureHeaders → CORS).

**No existing OpenAPI/WAF integration** — The project has zero OpenAPI introspection, zero WAF-related code, and no references to AWS WAF APIs. boto3 is already an optional dependency under the `aws_secrets` extra (used in `db_security/secrets.py` for Secrets Manager), but not for WAF operations.

**Event bus system** — A `SecurityEventBus` (async pub/sub via `asyncio.Queue`) exists with module-level `_event_bus` references set by `shield.py`. However, **not all security modules emit events**:

| Module | Emits SecurityEvent? | Event Type |
|--------|---------------------|------------|
| `rate_limit` | ❌ NO (logger only) | — |
| `sanitize` | ❌ NO (returns 400) | — |
| `honeypot` | ❌ NO (audit callback only) | — |
| `brute_force` | ✅ Yes | `BRUTE_FORCE_LOCKOUT` |
| `ip_access` | ✅ Yes | `IP_BLOCKED`, `IP_ALLOWED` |
| `csrf` | ✅ Yes | `CSRF_VALIDATION_FAILED` |
| `xxe` | ✅ Yes | `XXE_DETECTED` |
| `account_protection` | ✅ Yes | `ACCOUNT_ENUMERATION_DETECTED` |

**Detected threats by module:**
- **Rate limit**: IP+endpoint request counters, escalating bans (base × multiplier^violations), path-specific limits, per-user/per-key tracking
- **Brute force**: Failed-attempt tracking per identifier, lockout with progressive delay, HIBP password checking
- **IP access**: Allowlist/blocklist with CIDR matching, three modes (allow/block/hybrid)
- **Sanitize**: SQLi blocking (via `sqlparse`), XSS stripping, NoSQL injection detection, command injection detection, path traversal detection, URL-decoding (double-encoded payload detection)
- **Honeypot**: Auto-ban on fake endpoint access
- **CSRF**: Double-submit cookie pattern validation
- **XXE**: XML External Entity attack detection

**Detection & blocking flow** (per module):
1. Middleware receives request → extracts IP (respecting trusted proxies)
2. Checks backend (in-memory or Redis) for state
3. If attack detected: returns 4xx response (429, 400, 403, 423)
4. If event bus available: emits `SecurityEvent` for webhooks/metrics

---

### Affected Areas

#### Feature A — WAF Rules Generation

| File/Module | Why Affected |
|-------------|-------------|
| `src/araxys/core/config.py` | New `WafRuleConfig` or `AwsWafConfig` BaseModel subclass needed |
| `src/araxys/shield.py` | New `_register_waf` method for optional runtime WAF module registration |
| `src/araxys/cli.py` | New CLI command (`araxys waf generate`) for offline rule generation |
| `src/araxys/__init__.py` | Export new public API symbols |
| `pyproject.toml` | New optional dependency extra: `aws_waf = ["boto3>=1.34"]` |
| `tests/` | New `test_waf.py` test file |

#### Feature B — WAF Block Escalation

| File/Module | Why Affected |
|-------------|-------------|
| `src/araxys/core/types.py` | New `SecurityEventType` entries (`WAF_ESCALATED`, etc.) |
| `src/araxys/core/config.py` | New `WafEscalationConfig` BaseModel subclass |
| `src/araxys/webhooks/emitter.py` | New subscriber for WAF escalation (pattern already established) |
| `src/araxys/shield.py` | Wire WAF escalation subscriber to event bus |
| `src/araxys/rate_limit/limiter.py` | **Must be enhanced** to emit `SecurityEvent` via `_event_bus` (currently logger only) |
| `src/araxys/rate_limit/middleware.py` | Pass event emission through |
| `src/araxys/sanitize/middleware.py` | **Must be enhanced** to emit `SecurityEvent` on blocking |
| `src/araxys/honeypot/trap.py` | **Must be enhanced** to emit `SecurityEvent` via event bus |
| `src/araxys/metrics/collector.py` | Register new `SecurityEventType` entries for metrics |
| `pyproject.toml` | New optional dependency extra: `aws_waf` |

---

### Feature A — Approaches

#### Approach A1 — Standalone WAF rule generator module (Recommended)

Create `src/araxys/waf/` module with:
- `schema_reader.py`: Reads `app.openapi()` to extract paths, methods, content types, query params, body schemas
- `rule_generator.py`: Generates AWS WAF rule JSON from extracted schema
- `aws_client.py`: Optional boto3 client to apply rules to AWS WAF

```python
# Usage:
waf = WafRuleGenerator(app.openapi())
rules = waf.generate()
# rules is a dict: {"ip_sets": [...], "regex_sets": [...], "rule_groups": [...], "web_acl": {...}}
# Optional: apply via boto3
await waf.apply(rules, web_acl_arn="...")
```

| Pros | Cons | Complexity |
|------|------|------------|
| Clean separation from other modules | AWS-specific (not portable to CloudFlare/other WAFs) | Medium |
| Works offline — generate, review, then apply | Requires OpenAPI schema to be accurate | |
| Stateless — no runtime overhead | | |
| Can output CloudFormation/Terraform JSON | | |

#### Approach A2 — CLI-only rule generator

Add `araxys waf generate --output waf-rules.json` command that:
1. Accepts OpenAPI JSON file path or FastAPI app module
2. Outputs WAF rules as JSON

| Pros | Cons | Complexity |
|------|------|------------|
| Minimal code footprint | Manual step in deployment pipeline | Low |
| Zero import overhead (only loaded when CLI invoked) | Rules can drift from actual API state | |
| Can be used in CI/CD pipelines | | |

#### Approach A3 — Middleware-based learned profile

Middleware that observes traffic, builds a profile of expected request patterns, then generates rules.

| Pros | Cons | Complexity |
|------|------|------------|
| Adaptive to real traffic | Learning phase is a security risk window | High |
| No manual OpenAPI dependency | Complex — stateful, requires storage | |
| | AWS WAF API calls per-request would be prohibitively slow | |

**Recommendation for Feature A: Combine A1 + A2**
- Create a `src/araxys/waf/` module with `WafRuleGenerator` class (A1)
- Expose it via a CLI command `araxys waf generate` (A2)
- Module reads `app.openapi()`, generates rules, outputs JSON
- Optional `araxys waf apply` command to push rules to AWS WAF via boto3
- Keep runtime usage optional — no middleware impact by default

---

### Feature B — Approaches

#### Approach B1 — Event bus subscriber (Recommended)

Create a `WafEscalationSubscriber` that subscribes to `SecurityEventBus`. On security events, upserts the offending IP into AWS WAF IP sets.

```python
# Pattern follows existing WebhookDelivery subscriber:
class WafEscalationSubscriber:
    async def handle_event(self, event: SecurityEvent) -> None:
        if event.event_type in ESCALATABLE_EVENTS and event.source_ip:
            await self._upsert_ip_to_waf(event.source_ip, event)
```

| Pros | Cons | Complexity |
|------|------|------------|
| Non-blocking — fire-and-forget via event bus | Requires enhancing rate_limit/sanitize/honeypot to emit events | Medium-High |
| Clean separation, follows existing webhooks pattern | AWS WAF API calls add latency (mitigated by async) | |
| Single integration point — one subscriber handles all events | AWS WAF IP set has rate limits (mitigated by batching/throttling) | |
| Already tested pattern (WebhookDelivery + MetricsRegistry) | | |

#### Approach B2 — Direct middleware integration

Each middleware calls WAF API directly when blocking.

| Pros | Cons | Complexity |
|------|------|------------|
| Immediate escalation | **BLOCKING** — WAF API latency in middleware path is unacceptable | Medium |
| | Tight coupling to AWS in every module | |
| | Harder to test — every middleware test needs WAF mocking | |

#### Approach B3 — Audit log shipping trigger

Use audit log entries to trigger WAF updates.

| Pros | Cons | Complexity |
|------|------|------------|
| All security events flow through audit | Audit is batch/async — not real-time | Medium |
| | Requires audit log parsing | |
| | Duplicates event bus infrastructure | |

**Recommendation for Feature B: Approach B1**

Use the existing event bus subscriber pattern with these critical pre-requisites:

1. **Enhance event emission** in `rate_limit`, `sanitize`, and `honeypot` modules to emit `SecurityEvent` via `_event_bus`. Required new `SecurityEventType` values:
   - `RATE_LIMIT_EXCEEDED` (already exists!)
   - `SANITIZE_BLOCKED` (already exists!)
   - `HONEYPOT_TRIGGERED` (already exists!)

   **Key discovery**: These event types ALREADY exist in the enum but are NOT emitted by their respective modules. The infrastructure is ready — the modules just need the `_event_bus` wiring (same pattern as `brute_force/limiter.py` lines 27, 283-297).

2. Add `WAF_ESCALATED` event type for when IP is successfully escalated to WAF.

3. Create `WafEscalationSubscriber` as a pluggable subscriber (pattern: `SecurityEventBus.subscribe()`).

---

### Dependencies Needed

| Dependency | Required For | Already in pyproject.toml? |
|------------|-------------|---------------------------|
| `boto3 >= 1.34` | AWS WAF API calls (both features) | ✅ Yes — under `aws_secrets` extra |
| `boto3-stubs[wafv2]` (dev) | Type checking for WAF v2 API | ❌ No — add to dev deps |
| No new core dependencies | All runtime logic | ✅ Uses stdlib + existing deps |

**boto3 isolation strategy**: Both features follow the existing `db_security/secrets.py` pattern:
- Import boto3 lazily inside the class `__init__`
- Wrap sync boto3 calls with `asyncio.to_thread()`
- Provide clear error message when boto3 is missing: `"Install with: pip install araxys[aws_waf]"`
- Register `boto3` in `[tool.mypy.overrides]` as `ignore_missing_imports = true` (already done)

**New optional extra**:
```toml
aws_waf = ["boto3>=1.34"]
```

(Can share the `boto3>=1.34` dependency with `aws_secrets`. Same version, separate semantic extra.)

---

### Risks

1. **Feature A — Schema drift**: Generated WAF rules are only as good as the OpenAPI schema. If routes are added/modified without regenerating rules, the WAF may block legitimate traffic or allow unapproved paths. Mitigation: generate rules in CI/CD pipeline, fail on drift.

2. **Feature A — OpenAPI completeness**: FastAPI's auto-generated OpenAPI may not include all constraints (e.g., custom validators in Pydantic models may not be reflected in the JSON Schema). WAF rules will be permissive for undocumented fields. Mitigation: document this as a known limitation.

3. **Feature B — WAF API rate limits**: AWS WAF IP set updates have API rate limits (~1 request/sec per IP set). Burst escalations from a DDoS could hit limits. Mitigation: batch updates, throttle in the subscriber.

4. **Feature B — AWS WAF IP set size limits**: IP sets have a maximum of 10,000 IPs. Long-running services could exhaust this. Mitigation: implement TTL-based eviction, or use rate-based rules instead of IP blocks.

5. **Feature B — boto3 sync blocking**: Even with `asyncio.to_thread()`, boto3 calls block a thread from the executor pool. Under high event volume, this could exhaust the default pool. Mitigation: configure `ThreadPoolExecutor` max_workers, or use `aioboto3` as a future enhancement.

6. **Feature B — Module enhancement risk**: Adding `_event_bus` emission to `rate_limit`, `sanitize`, and `honeypot` is low-risk but touches 3 production modules. Each must follow the existing pattern exactly (module-level `_event_bus = None`, set by `shield.py`).

7. **Feature B — False positive escalation**: If Araxys incorrectly blocks a legitimate IP (false positive), that IP gets escalated to AWS WAF globally, affecting ALL services behind the same CloudFront/ALB. Mitigation: configurable minimum severity threshold, configurable event types to escalate.

---

### Ready for Proposal

**Yes** — both features are well-understood, the codebase is thoroughly mapped, and the approaches align with existing architecture patterns.

**Recommended proposal structure**:
1. **Phase 1**: Enhance `rate_limit`, `sanitize`, `honeypot` to emit SecurityEvents (pre-requisite for Feature B)
2. **Phase 2**: Implement Feature A — WAF rule generator module + CLI
3. **Phase 3**: Implement Feature B — WAF escalation subscriber
4. Each phase independently testable and shippable
