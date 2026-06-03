# Proposal: Threat Intelligence Feeds Module

## Intent

Araxys v0.13 has automatic WAF escalation but no proactive threat intelligence. Operators must manually curate blocklists. This module adds automatic ingestion of community threat intel feeds (Firehol L1/L2/L3, Spamhaus DROP/EDROP, Blocklist.de, AbuseIPDB, AlienVault OTX) into the existing IP Access blocklist infrastructure — no new dependencies, no protocol changes.

## Scope

### In Scope
- `src/araxys/threat_intel/` module with config, background scheduler, feed fetchers, and IP resolver
- 8 feed sources: 5 plaintext (Firehol x3, Spamhaus DROP, EDROP, Blocklist.de) + 2 API (AbuseIPDB, AlienVault OTX)
- Background asyncio scheduler wired via `AraxysShield`, with clean shutdown
- TTL tracking in Redis ZSET, eviction loop syncing to existing `IPAccessBackend.add_to_blocklist()` / `remove_from_blocklist()`
- `exclude_ips` allowlist for false positive mitigation
- CLI: `threat-intel refresh | feeds | stats | purge`
- Events: `THREAT_INTEL_LOADED` and `THREAT_INTEL_MATCH` via `SecurityEventBus`

### Out of Scope
- Custom feed definitions (user-supplied URLs) — deferred to v2
- Per-IP metadata in middleware dispatch path — TTL lookup is deferred to Redis ZSET
- Feed-specific rate-limit token buckets — AbuseIPDB free tier handled via per-feed refresh_interval

## Capabilities

### New Capabilities
- `threat-intel-feeds`: Proactive ingestion of community threat intelligence IPs into Araxys blocklist. Includes background scheduling, TTL-based eviction, multi-feed deduplication, and Shield lifecycle integration.

### Modified Capabilities
None — additive module only. Existing IP Access protocol, SecurityEventBus, and Shield wiring patterns are consumed, not changed.

## Approach

**Approach A — Standalone background scheduler** (matches exploration recommendation). The `ThreatIntelScheduler` runs as an `asyncio.create_task()` in the Shield lifecycle, fetches enabled feeds on their per-feed intervals via `httpx`, deduplicates IPs in-memory, bulk-loads them into `IPAccessBackend.add_to_blocklist()`, and evicts expired IPs from Redis ZSET `araxys:threat_intel:ips`. Follows the WAF escalation pattern: background task, event bus emissions, graceful shutdown.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/araxys/threat_intel/` | New | Entire module: config, scheduler, resolver, feed fetchers, CLI |
| `src/araxys/core/config.py` | Modified | Add `ThreatIntelConfig` + `threat_intel: ThreatIntelConfig \| None` field |
| `src/araxys/core/types.py` | Modified | Add `THREAT_INTEL_LOADED`, `THREAT_INTEL_MATCH` event types |
| `src/araxys/shield.py` | Modified | Wire `_register_threat_intel()` in `__init__`, cancel in `shutdown()` |
| `src/araxys/cli.py` | Modified | Add `threat_intel_app` Typer sub-command |
| `src/araxys/ip_access/backends.py` | Modified | Add `add_bulk_to_blocklist()` convenience method |
| `tests/` | New | `test_threat_intel_*.py` for feeds, scheduler, resolver, integration |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Feed outage causes scheduler crash | Low | `try/except` per feed, log warning, skip — matches WAF escalation pattern |
| 20K IPs from Blocklist.de blocks event loop | Low | Bulk-add via Redis pipeline (1K batches) |
| False positives block legitimate traffic | Medium | `exclude_ips` config field; module disabled by default (`enabled=false`) |

## Rollback Plan

Set `ARAXYS_THREAT_INTEL__ENABLED=false` or remove `threat_intel` config key. Module is fully additive — all IPs live in Redis ZSET key `araxys:threat_intel:ips` and standard blocklist SET; running `araxys threat-intel purge` clears all threat-intel-derived IPs. No code removal needed for rollback.

## Dependencies

None. `httpx>=0.27` already core. `respx>=0.23.1` already dev. All feeds consumed via plaintext HTTP or REST API — no new packages.

## Success Criteria

- [ ] All 8 feeds fetch and parse correctly from HTTP sources (mocked in tests, live in integration)
- [ ] Scheduler starts/stops cleanly via Shield lifecycle, no task leaks on shutdown
- [ ] IPs deduplicated across overlapping feeds, expired IPs evicted within one refresh cycle
- [ ] CLI commands `refresh`, `feeds`, `stats`, `purge` work against running app
- [ ] `THREAT_INTEL_LOADED` and `THREAT_INTEL_MATCH` events emitted and consumable by subscribers
- [ ] 90%+ test coverage on new module; zero regressions on existing 1686 tests
