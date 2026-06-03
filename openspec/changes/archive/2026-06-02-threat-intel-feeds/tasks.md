# Tasks: Threat Intelligence Feeds Module

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 900–1100 (11 new + 5 modified files + tests) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 → PR 2 → PR 3 |
| Delivery strategy | ask-on-risk |
| Chain strategy | stacked-to-main |

Decision needed before apply: Yes (resolved — chained PRs via stacked-to-main)
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Config models + feed fetchers | PR 1 | `core/config.py`, `threat_intel/config.py`, `feeds/`, feed unit tests; base: main |
| 2 | Resolver + scheduler + backend | PR 2 | `resolver.py`, `scheduler.py`, `backends.py`, unit tests; base: PR 1 |
| 3 | Shield wiring + CLI + integration | PR 3 | `shield.py`, `cli.py`, exports, integration/CLI tests; base: PR 2 |

## Phase 1: Foundation

- [x] 1.1 Add `ThreatIntelConfig`, `FeedConfig` Pydantic models to `src/araxys/core/config.py`; add `threat_intel: ThreatIntelConfig | None` field on `AraxysConfig`
- [x] 1.2 Add `THREAT_INTEL_LOADED`, `THREAT_INTEL_MATCH` enum members to `SecurityEventType` in `src/araxys/core/types.py`
- [x] 1.3 Create `src/araxys/threat_intel/__init__.py` with public exports
- [x] 1.4 Create `src/araxys/threat_intel/config.py` — `FeedConfig`, `FEED_DEFAULTS` dict with 8 feed presets (Firehol L1/L2/L3, Spamhaus DROP/EDROP, Blocklist.de, AbuseIPDB, AlienVault)

## Phase 2: Feed Fetchers

- [x] 2.1 Create `src/araxys/threat_intel/feeds/__init__.py` — `FeedResult` dataclass, `FeedSource` Protocol
- [x] 2.2 Create `src/araxys/threat_intel/feeds/plaintext.py` — `PlaintextFeedFetcher`: one IP/CIDR per line, strip `#` comments and blanks
- [x] 2.3 Create `src/araxys/threat_intel/feeds/abuseipdb.py` — `AbuseIPDBFeedFetcher`: REST API v2, JSON response → IPs above abuse threshold
- [x] 2.4 Create `src/araxys/threat_intel/feeds/alienvault.py` — `AlienVaultFeedFetcher`: OTX pulses API, JSON → indicator extraction

## Phase 3: Core Logic

- [x] 3.1 Create `src/araxys/threat_intel/resolver.py` — dedup IPs, filter `exclude_ips`, Redis ZSET TTL tracking (`araxys:threat_intel:ips`), eviction via `ZREMRANGEBYSCORE`
- [x] 3.2 Add `add_bulk_to_blocklist(ips: list[str])` to `RedisIPAccessBackend` in `src/araxys/ip_access/backends.py` — 1K-IP pipeline batching (`sadd` + `zadd`)
- [x] 3.3 Create `src/araxys/threat_intel/scheduler.py` — `ThreatIntelScheduler` class: `run()` background loop, `refresh()`, `stats()`, `purge()`, `shutdown()`; staggered per-feed timers, per-feed error isolation

## Phase 4: Wiring & CLI

- [x] 4.1 Wire `_register_threat_intel()` in `src/araxys/shield.py` — `asyncio.create_task(scheduler.run())` on init, cancel+await on `shutdown()`; gate on `threat_intel.enabled`
- [x] 4.2 Add `threat_intel_app` Typer sub-command to `src/araxys/cli.py` — `refresh`, `feeds`, `stats`, `purge`
- [x] 4.3 Export `ThreatIntelConfig`, `ThreatIntelScheduler` from `src/araxys/__init__.py`

## Phase 5: Testing

- [x] 5.1 Unit: `tests/test_threat_intel_feeds.py` — plaintext parsing, API JSON deserialization, HTTP error resilience (via `respx`)
- [x] 5.2 Unit: `tests/test_threat_intel_resolver.py` — dedup, `exclude_ips` filter, TTL score calc, expired IP selection
- [x] 5.3 Unit: `tests/test_threat_intel_scheduler.py` — staggered start, per-feed error isolation, shutdown cancels task
- [x] 5.4 Integration: `tests/test_threat_intel_integration.py` — full fetch→block→evict cycle with `fakeredis`
- [x] 5.5 CLI: `tests/test_threat_intel_cli.py` — `refresh --feed`, `feeds`, `stats`, `purge` via `typer.testing.CliRunner`
