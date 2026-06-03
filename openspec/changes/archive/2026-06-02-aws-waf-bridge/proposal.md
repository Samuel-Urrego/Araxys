# Proposal: AWS WAF Bridge

## Intent

Add AWS WAF integration: generate rules from OpenAPI schema, escalate blocked IPs via SecurityEventBus. No WAF integration exists. boto3 is optional under `aws_secrets`.

## Scope

### In Scope
- `src/araxys/waf/` — `WafRuleGenerator` (OpenAPI→WAF JSON) + CLI `araxys waf generate`
- `WafEscalationSubscriber` — event bus subscriber upserting IPs into AWS WAF
- Wire `_event_bus` in rate_limit, sanitize, honeypot (enums exist, modules don't emit)
- New `aws_waf` pip extra: `boto3>=1.34`
- Config: `WafRuleConfig`, `WafEscalationConfig`

### Out of Scope
CloudFlare/GCP WAF, real-time profiling, aioboto3 migration, rule deletion workflows.

## Capabilities

### New Capabilities
- `waf-rule-generation`: Generate AWS WAF rules (IP sets, regex sets, rule groups, Web ACL) from FastAPI's `app.openapi()`. CLI + programmable class.
- `waf-escalation`: Escalate blocked IPs to AWS WAF via event bus subscriber. Listens to RATE_LIMIT_EXCEEDED, SANITIZE_BLOCKED, HONEYPOT_TRIGGERED.

### Modified Capabilities
None.

## Approach

**3-phase delivery, independently testable:**

1. **Event wiring** — Add `_event_bus.emit()` in rate_limit, sanitize, honeypot following `brute_force/limiter.py` pattern (module-level `_event_bus = None`, set by shield).
2. **Rule generator** — `src/araxys/waf/` with `schema_reader.py`, `rule_generator.py`, `aws_client.py`. Optional boto3 apply via `asyncio.to_thread()`.
3. **Escalation subscriber** — `WafEscalationSubscriber` following webhooks pattern. Handles AWS rate limits (1 req/s) and IP set cap (10K) via throttling and TTL.

boto3: lazy import, install hint (`pip install araxys[aws_waf]`).

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/araxys/waf/` | New | schema_reader, rule_generator, aws_client, escalation |
| `src/araxys/core/config.py` | Modified | WafRuleConfig, WafEscalationConfig |
| `src/araxys/core/types.py` | Modified | `WAF_ESCALATED` event type |
| `src/araxys/rate_limit/limiter.py` | Modified | Wire `_event_bus` |
| `src/araxys/sanitize/middleware.py` | Modified | Wire `_event_bus` |
| `src/araxys/honeypot/trap.py` | Modified | Wire `_event_bus` |
| `src/araxys/cli.py` | Modified | `araxys waf generate` command |
| `pyproject.toml` | Modified | `aws_waf` extra |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| OpenAPI drift → stale WAF rules | Medium | CI/CD regeneration |
| WAF API rate limits under burst | Low | Batch updates, subscriber throttle |
| IP set exhaustion (10K limit) | Low | TTL eviction, rate-based fallback |
| Thread pool exhaustion | Low | Configurable max_workers |
| False positive globally escalated | Medium | Severity threshold, event type allowlist |

## Rollback Plan

- Remove `aws_waf` from shield → subscriber disconnects
- Delete `src/araxys/waf/`, revert pyproject.toml
- Event wiring is additive fire-and-forget — no rollback needed

## Dependencies

- `boto3>=1.34` (reused from `aws_secrets`)
- `boto3-stubs[wafv2]` (dev only)

## Success Criteria

- [ ] `araxys waf generate` outputs valid AWS WAF JSON
- [ ] Blocked IPs appear in WAF IP set within 30s
- [ ] 1490 existing tests pass — no regressions
- [ ] boto3 absent → graceful error, no ImportError
