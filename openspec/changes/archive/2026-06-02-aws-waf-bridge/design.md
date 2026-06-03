# Design: AWS WAF Bridge

## Technical Approach

Three independently testable phases:
1. **Event wiring** — Add `_event_bus.emit()` in rate_limit, sanitize, honeypot following `brute_force/limiter.py` pattern (module-level `_event_bus = None`, set by `shield.py`, guarded by `if _event_bus`).
2. **Rule generator** — `src/araxys/waf/` with `schema_reader.py` (ingests `app.openapi()` or JSON file), `rule_generator.py` (produces AWS WAF JSON), `aws_client.py` (lazy boto3 via `asyncio.to_thread()`). CLI: `araxys waf generate`.
3. **Escalation subscriber** — `WafEscalationSubscriber` subscribes via `event_bus.subscribe(self._on_event)` like `WebhookDelivery`. In-memory strike counter per IP with sliding window. AWS calls throttled via `asyncio.Semaphore(1)`. Dry-run logs only.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|-------------|-----------|
| Config location | `core/config.py` (`WafRuleConfig`, `WafEscalationConfig`) | `waf/config.py` | All 30+ config models live in `core/config.py`. Consistency. |
| Multi-strike storage | In-memory `dict[str, list[float]]` with lazy cleanup | Redis counters | Ephemeral per-process counters suffice; escalation itself persists to AWS. No new dependency. |
| AWS throttling | `asyncio.Semaphore(1)` per IP set applies | Token bucket, external lib | Stdlib-only, meets 1 req/s constraint exactly. |
| CLI structure | New typer `waf_app` added to `cli.py`, `app.add_typer(waf_app, name="waf")` | Standalone script | Extends existing CLI pattern (`keys_app`). |
| boto3 import | Lazy at `aws_client.__init__` / escalation `__init__` | Top-level `try/except` | Follows `AWSSecretsResolver` — constructor `import boto3`, fail with install hint. |
| Event emission point (rate_limit) | In `RateLimitMiddleware.dispatch()`, before returning 429 | Inside `RateLimiter.check()` | Middleware owns the response path; IP available, keeps limiter pure. |
| Event emission point (sanitize) | In `SanitizeMiddleware.dispatch()`, before `_block_response()` return | In `_block_response()` helper | IP extraction via `get_client_ip(request)` needed; `_block_response` doesn't receive request. |
| Event emission point (honeypot) | In `HoneypotTrap._handle_trap()`, after ban | New middleware | IP already resolved; method already handles the trap logic. |

## Data Flow — Escalation

```
RateLimit ──→ SecurityEventBus ──→ WafEscalationSubscriber._on_event()
Sanitize  ──┤                         │
Honeypot  ──┤                   ┌─────┴─────┐
BruteForce──┘                   │ strike map │
                                │ {ip: [ts]} │
                                └─────┬─────┘
                              threshold met?
                           ┌────no────┴───yes───┐
                           │                     │
                          done            ┌──────┴──────┐
                                          │ dry_run?    │
                                     ┌─yes─┴────no──────┐
                                     │ log INFO only     │
                                     │                 semaphore
                                     │             asyncio.to_thread()
                                     │              boto3.update_ip_set()
                                     └──────────────────┘
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/waf/__init__.py` | Create | Export `WafRuleGenerator`, `WafEscalationSubscriber`, `WafRuleConfig`, `WafEscalationConfig` |
| `src/araxys/waf/schema_reader.py` | Create | `SchemaReader`: reads `app.openapi()` or file → paths, methods, content-types dict |
| `src/araxys/waf/rule_generator.py` | Create | `WafRuleGenerator`: converts schema dict → AWS WAF JSON (IP sets, regex pattern sets, rule groups, Web ACL) |
| `src/araxys/waf/aws_client.py` | Create | `WafClient`: lazy boto3, `update_ip_set()`, `get_ip_set()`, all via `asyncio.to_thread()` |
| `src/araxys/waf/escalation.py` | Create | `WafEscalationSubscriber`: multi-strike counter, dry-run toggle, TTL eviction, semaphore-throttled AWS calls |
| `src/araxys/core/config.py` | Modify | Add `WafRuleConfig`, `WafEscalationConfig`; add `aws_waf: WafRuleConfig \| None` + `waf_escalation: WafEscalationConfig \| None` to `AraxysConfig` |
| `src/araxys/core/types.py` | Modify | Add `WAF_ESCALATED = "waf_escalated"` to `SecurityEventType` |
| `src/araxys/shield.py` | Modify | Wire `_event_bus` to rate_limit, sanitize, honeypot modules. Init `WafEscalationSubscriber` when `config.waf_escalation.enabled`. |
| `src/araxys/rate_limit/middleware.py` | Modify | Add `_event_bus = None`; emit `RATE_LIMIT_EXCEEDED` before 429 return |
| `src/araxys/sanitize/middleware.py` | Modify | Add `_event_bus = None`; emit `SANITIZE_BLOCKED` on block, extract IP via `get_client_ip` |
| `src/araxys/honeypot/trap.py` | Modify | Add `_event_bus = None`; emit `HONEYPOT_TRIGGERED` in `_handle_trap` |
| `src/araxys/cli.py` | Modify | Add `waf` typer sub-app with `generate` and `apply` commands |
| `src/araxys/__init__.py` | Modify | Export `WafRuleConfig`, `WafEscalationConfig`, `WafRuleGenerator`, `WafEscalationSubscriber` |
| `pyproject.toml` | Modify | Add `aws_waf = ["boto3>=1.34"]` to `[project.optional-dependencies]` |

## Interfaces

```python
# core/config.py — new models
class WafRuleConfig(BaseModel):
    enabled: bool = False
    openapi_file: str | None = None
    output_file: str | None = None
    web_acl_name: str = "AraxysWaf"
    region: str = "us-east-1"

class WafEscalationConfig(BaseModel):
    enabled: bool = False
    dry_run: bool = False
    multi_strike_count: int = 3
    multi_strike_window_seconds: int = 60
    ttl_seconds: int = 86400
    allowed_event_types: list[str] = Field(
        default=["rate_limit_exceeded", "sanitize_blocked",
                 "brute_force_lockout", "honeypot_triggered"])
    ip_set_id: str | None = None
    ip_set_name: str = "AraxysBlockedIPs"

# Escalation subscriber constructor
class WafEscalationSubscriber:
    def __init__(self, config: WafEscalationConfig, event_bus: SecurityEventBus) -> None:
        event_bus.subscribe(self._on_event)
```

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| Unit | `schema_reader`: OpenAPI parsing | Parametrized pytest with sample schemas |
| Unit | `rule_generator`: WAF JSON output | Snapshot-style assertions on known inputs |
| Unit | `escalation`: strike counting, threshold, dry-run | Direct method calls, mock event bus |
| Unit | `aws_client`: boto3 absent → ImportError, semaphore | Mock boto3, assert to_thread |
| Integration | Event wiring emits when blocking | Fake event bus subscriber, assert events received |
| Integration | CLI `araxys waf generate` outputs valid JSON | Subprocess, validate JSON structure |
| E2E | Shield with aws_waf config → subscriber wired | Test shield init, mock AWS calls |

## Open Questions

- [ ] Per-event-type TTL (spec scenario) vs global TTL — per-type adds complexity. Start with global `ttl_seconds`, add per-type dict override later if requested.
- [ ] Redis-backed strike counter for multi-worker deployments — out of scope, but document tradeoff in escalation module docstring.
