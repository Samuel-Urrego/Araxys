# Tasks: AWS WAF Bridge

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~1000 (850 new + 176 modified) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: Foundation + schema reader (~120 lines) → PR 2: Rule gen + AWS client (~300 lines) → PR 3: Event wiring + escalation (~380 lines) |
| Delivery strategy | single-pr |
| Chain strategy | stacked-to-main |

Decision needed before apply: Yes (resolved — chained PRs via stacked-to-main)
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

## Phase 1: Foundation

- [x] 1.1 Add `aws_waf` extra to `pyproject.toml` (`[project.optional-dependencies]`)
- [x] 1.2 Add `WafRuleConfig` and `WafEscalationConfig` Pydantic models to `src/araxys/core/config.py`
- [x] 1.3 Add `aws_waf` and `waf_escalation` optional fields to `AraxysConfig` in `src/araxys/core/config.py`
- [x] 1.4 Add `WAF_ESCALATED = "waf_escalated"` to `SecurityEventType` in `src/araxys/core/types.py`
- [x] 1.5 Create `src/araxys/waf/__init__.py` with public exports
- [x] 1.6 Create `src/araxys/waf/schema_reader.py` — `SchemaReader` class, ingests `app.openapi()` or JSON file path

## Phase 2: Rule Generator

- [x] 2.1 Create `src/araxys/waf/rule_generator.py` — `WafRuleGenerator`, produces AWS WAF JSON (IP sets, regex pattern sets, rule groups, Web ACL)
- [x] 2.2 Create `src/araxys/waf/aws_client.py` — `WafClient` with lazy boto3, `update_ip_set()`/`get_ip_set()` via `asyncio.to_thread()`, semaphore-throttled
- [x] 2.3 Add `waf generate` CLI command to `src/araxys/cli.py` — typer sub-app, `--app-instance` or `--input`, `--output`, snapshot drift warning

## Phase 3: Event Wiring

- [x] 3.1 Wire `_event_bus` in `src/araxys/rate_limit/middleware.py` — add module-level `_event_bus = None`, emit `RATE_LIMIT_EXCEEDED` before 429 return in `dispatch()`
- [x] 3.2 Wire `_event_bus` in `src/araxys/sanitize/middleware.py` — add module-level `_event_bus = None`, emit `SANITIZE_BLOCKED` in `dispatch()` before `_block_response()`, extract IP via `get_client_ip`
- [x] 3.3 Wire `_event_bus` in `src/araxys/honeypot/trap.py` — add module-level `_event_bus = None`, emit `HONEYPOT_TRIGGERED` in `_handle_trap()` after ban

## Phase 4: Escalation Subscriber

- [x] 4.1 Create `src/araxys/waf/escalation.py` — `WafEscalationSubscriber` with in-memory multi-strike counter, dry-run toggle, TTL eviction, `asyncio.Semaphore(1)` throttle
- [x] 4.2 Wire subscriber in `src/araxys/shield.py` — init when `config.waf_escalation.enabled`, subscribe to `event_bus`, set module-level `_event_bus` refs for rate_limit/sanitize/honeypot
- [x] 4.3 Add `araxys waf apply` CLI command to `src/araxys/cli.py` — boto3 presence check, `--ip-set-id`, `asyncio.to_thread` apply
- [x] 4.4 Add `boto3-stubs[wafv2]` dev dependency to `pyproject.toml`

## Phase 5: Testing

- [x] 5.1 Unit tests for `waf/schema_reader.py` — parametrized OpenAPI parsing (live app + static file)
- [x] 5.2 Unit tests for `waf/rule_generator.py` — snapshot assertions on WAF JSON output for known inputs
- [x] 5.3 Unit tests for `waf/aws_client.py` — mock boto3, test ImportError path, semaphore behavior
- [x] 5.4 Unit tests for `waf/escalation.py` — strike threshold met/not met, dry-run, TTL eviction, event type filtering
- [x] 5.5 Integration tests for event emission — fake subscriber on event bus, assert rate_limit/sanitize/honeypot emit correct events
- [x] 5.6 CLI test — `araxys waf generate --output` produces valid JSON structure
- [x] 5.7 Regression — `uv run pytest` must pass all 1686 existing tests
