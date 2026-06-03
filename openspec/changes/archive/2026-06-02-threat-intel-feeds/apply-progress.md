# Apply Progress: threat-intel-feeds

## PR 3 — Shield + CLI + Integration Tests

### TDD Cycle Evidence

| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 4.1 | `tests/test_threat_intel_integration.py` (TestShieldThreatIntelWiring) | Integration | ✅ 10/10 | ✅ Written | ✅ 5/5 passed | ✅ 5 cases (enabled, disabled, no-feeds, shutdown) | ✅ Clean |
| 4.2 | `tests/test_threat_intel_cli.py` | CLI | N/A (new) | ✅ Written | ✅ 11/11 passed | ✅ 11 cases (refresh, feeds, stats, purge, not-enabled) | ✅ Clean |
| 4.3 | `tests/test_threat_intel_config.py` (existing) | Unit | ✅ 46/46 | ✅ Written | ✅ All pass | ➖ Single (structural export) | ✅ Clean |
| 5.4 | `tests/test_threat_intel_integration.py` (TestThreatIntelFetchBlockEvictCycle) | Integration | N/A (new) | ✅ Written | ✅ 8/8 passed | ✅ 8 cases (full cycle, dedup, exclude, evict, purge, event, error, empty) | ✅ Clean |
| 5.5 | `tests/test_threat_intel_cli.py` | CLI | N/A (new) | ✅ Written | ✅ 11/11 passed | ✅ Covered in 4.2 | ✅ Clean |

### Test Summary
- **Total tests written in this batch**: 24 (13 integration + 11 CLI)
- **All threat intel tests passing**: 148/148
- **Full suite**: 1833/1834 (1 pre-existing flaky test in test_webhooks.py — unrelated)
- **Layers used**: Integration (13), CLI (11), Unit (3 — exports)
- **Approval tests**: None — no refactoring tasks
- **Pure functions created**: 1 (`_build_feeds_from_config`)

### Completed Tasks (cumulative — ALL)
- [x] 1.1 ThreatIntelConfig, FeedConfig models + AraxysConfig field
- [x] 1.2 THREAT_INTEL_LOADED, THREAT_INTEL_MATCH enum members
- [x] 1.3 threat_intel/__init__.py exports
- [x] 1.4 FeedConfig, FEED_DEFAULTS presets
- [x] 2.1 FeedResult, FeedSource Protocol
- [x] 2.2 PlaintextFeedFetcher
- [x] 2.3 AbuseIPDBFeedFetcher
- [x] 2.4 AlienVaultFeedFetcher
- [x] 3.1 IPResolver — dedup, exclude_ips, TTL tracking, eviction
- [x] 3.2 add_bulk_to_blocklist on RedisIPAccessBackend
- [x] 3.3 ThreatIntelScheduler — background loop, refresh/stats/purge
- [x] 4.1 Wire _register_threat_intel() in shield.py — init + shutdown
- [x] 4.2 Add threat_intel_app Typer sub-command to cli.py
- [x] 4.3 Export ThreatIntelConfig, ThreatIntelScheduler from araxys/__init__.py
- [x] 5.1 Unit: test_threat_intel_feeds.py
- [x] 5.2 Unit: test_threat_intel_resolver.py
- [x] 5.3 Unit: test_threat_intel_scheduler.py
- [x] 5.4 Integration: test_threat_intel_integration.py
- [x] 5.5 CLI: test_threat_intel_cli.py

### Remaining Tasks
None — ALL TASKS COMPLETE.

### Files Changed (this batch)

| File | Action | What Was Done |
|------|--------|---------------|
| `src/araxys/threat_intel/cli.py` | Created | CLI command functions (refresh, feeds, stats, purge) with _get_threat_intel_scheduler() helper |
| `src/araxys/cli.py` | Modified | Added threat_intel_app Typer sub-app, registered 4 commands, imported CLI functions |
| `src/araxys/shield.py` | Modified | Added _register_threat_intel() method with feed builder + backend creation; added shutdown hook for scheduler stop |
| `src/araxys/threat_intel/__init__.py` | Modified | Added ThreatIntelScheduler to public exports |
| `src/araxys/__init__.py` | Modified | Added ThreatIntelConfig, ThreatIntelScheduler, FeedConfig, FEED_DEFAULTS to package exports |
| `tests/test_threat_intel_cli.py` | Created | 11 CLI tests: refresh, feeds, stats, purge, not-enabled error cases |
| `tests/test_threat_intel_integration.py` | Created | 13 integration tests: fetch→block→evict cycle + shield wiring lifecycle |
| `openspec/changes/threat-intel-feeds/tasks.md` | Modified | Marked 4.1-4.3, 5.4, 5.5 complete — ALL tasks done |

### Deviations from Design
- **Feed builder in shield**: Instead of inline `PlaintextFeedFetcher("firehol_level1", config.threat_intel.firehol_level1, ...)` with constructor args, feed instances are created without passing FeedConfig to the constructor. The config lookup happens inside `_fetch_and_sync` via `_get_feed_config()`. This matches the scheduler's internal pattern where config is resolved by feed name.
- **CLI helper**: Added `_get_threat_intel_scheduler()` standalone helper in `cli.py` for reuse across commands. Equivalent functionality lives in `_build_feeds_from_config()` in shield.py and the CLI module.

### Issues Found
- **Pre-existing flaky test**: `test_webhooks.py::TestWebhookDelivery::test_delivers_to_matching_urls` — fails intermittently (also seen in PR 2). Not related to threat-intel changes.
- **Eviction test refinement**: The integration test for eviction needed adjustment because the `deduplicate()` method refreshes TTL for already-known IPs. The test now directly manipulates TTL timestamps and calls `evict_expired()` directly to avoid the refresh cycle.

### Workload / PR Boundary
- Mode: stacked PR slice (PR 3 of 3 — FINAL)
- Current work unit: Shield wiring + CLI + Integration tests
- Boundary: shield.py modifications, cli.py additions, package exports, integration/CLI tests
- Estimated review budget impact: ~450 changed lines (production + tests)

### Status
**22/22 tasks complete. ALL DONE. Ready for sdd-verify.**
