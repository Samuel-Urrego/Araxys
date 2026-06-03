## Exploration: Threat Intelligence Feeds

### Current State

Araxys v0.13 has mature IP blocking infrastructure with a pluggable backend pattern:

- **IP Access Backends** (`src/araxys/ip_access/backends.py`): `IPAccessBackend` Protocol with `add_to_blocklist()` / `remove_from_blocklist()` / `is_blocked()`. Two implementations: `InMemoryIPAccessBackend` (sets) and `RedisIPAccessBackend` (Redis SETs at `araxys:ip_access:blocklist`). Both support CIDR matching.

- **IP Access Middleware** (`src/araxys/ip_access/middleware.py`): Three modes (allow, block, hybrid). Checks `is_allowed()`/`is_blocked()`, returns 403 on deny. Emits `IP_BLOCKED` / `IP_ALLOWED` events via module-level `_event_bus` global.

- **WAF Escalation** (`src/araxys/waf/escalation.py`): Reference pattern — subscribes to `SecurityEventBus`, uses multi-strike sliding window, respects AWS API rate limits via `asyncio.Semaphore(1)`, supports dry-run. Already feeds blocked IPs into AWS WAF IP sets.

- **Event System** (`src/araxys/webhooks/emitter.py`): `SecurityEventBus` — `asyncio.Queue`-based pub/sub. `subscribe()` for registering async callbacks, `emit()` for publishing. Used by WAF escalation, webhooks, metrics.

- **Shield** (`src/araxys/shield.py`): Central wiring. Pattern: check config → create backend → create middleware/subscriber → wire event bus globals → register middleware → log `module_initialized`.

- **Config** (`src/araxys/core/config.py`): `AraxysConfig` is `BaseSettings` with `ARAXYS_` env prefix, `__` nested delimiter. New modules use `Field(default=None)` — disabled by default until user explicitly sets config.

- **CLI** (`src/araxys/cli.py`): Typer + Rich. Sub-typers for `keys` and `waf`. Pattern: `def command(...) -> None:` with `asyncio.run(_run())` inner functions.

- **Dependencies**: `httpx>=0.27` is a **core** dependency (not optional). `respx>=0.23.1` is in dev deps for HTTP mocking. No new packages needed for basic feeds.

### Affected Areas

| Path | Why |
|------|-----|
| `src/araxys/threat_intel/` | **New module** — all feed logic lives here |
| `src/araxys/core/config.py` | New `ThreatIntelConfig` and optional `threat_intel: ThreatIntelConfig \| None` field on `AraxysConfig` |
| `src/araxys/core/types.py` | New `SecurityEventType` values: `THREAT_INTEL_LOADED`, `THREAT_INTEL_MATCH` |
| `src/araxys/shield.py` | New `_register_threat_intel()` method in `AraxysShield.__init__` — wires scheduler and backends |
| `src/araxys/cli.py` | New `threat_intel_app` typer for `refresh`, `feeds`, `stats` commands |
| `src/araxys/ip_access/backends.py` | **Possibly** `add_bulk_to_blocklist()` convenience method — avoid N round trips for bulk loads |
| `pyproject.toml` | No new dependencies needed (httpx already core). Optional `[threat-intel]` extra if needed later. |
| `tests/` | New `tests/test_threat_intel_*.py` files |
| `README.md` | Documentation for `pip install araxys[threat-intel]` if optional extra is created |

### Approaches

#### Approach A: Standalone Module with Background Scheduler

New module `src/araxys/threat_intel/` with:
- `config.py` — `ThreatIntelConfig` with per-feed API keys, refresh intervals, enabled toggles
- `scheduler.py` — asyncio background task that wakes up on intervals and fetches each enabled feed
- `feeds/` — one file per feed source (abuseipdb, alienvault, firehol, spamhaus, blocklist_de)
- `resolver.py` — deduplicates IPs across feeds, applies TTL per feed, feeds into IP Access backend
- `cli.py` — CLI commands for manual refresh, listing, stats
- `__init__.py` — public API exports

Flow: Scheduler → Feed.fetch() → Resolver.deduplicate() → backend.add_to_blocklist() → emit THREAT_INTEL_LOADED event

```
Shield.init()
  └─ threat_intel_config.enabled?
       └─ Create ThreatIntelScheduler(backend=ip_access_backend, config=threat_intel_config, event_bus=event_bus)
       └─ asyncio.create_task(scheduler.run())  ← background, cancellable on shutdown
```

| | |
|---|---|
| **Pros** | Follows existing module pattern (WAF, webhooks). No middleware changes. Clean separation — threat intel is a feeder, not interceptor. Easy to disable (config `enabled=false`). Each feed is a self-contained unit fetchable via `httpx`. CLI fits naturally. |
| **Cons** | Requires passing `IPAccessBackend` into the scheduler constructor. Need `add_bulk_to_blocklist()` on backend to avoid N round trips per feed load (Firehol has 10K+ IPs). Background task lifecycle must be managed in `shutdown()`. |
| **Complexity** | Medium |

#### Approach B: Extend IP Access Backend with Threat Intel Awareness

Add threat intel as a first-class concept inside `IPAccessBackend`:
- New methods: `add_threat_intel_ip(ip, source, ttl)`, `is_threat_intel_ip(ip)`, `evict_stale()`
- New Redis keys: `araxys:threat_intel:{source}` per feed
- IP Access middleware checks `is_threat_intel_ip()` as part of its dispatch logic
- Feed fetchers are simple functions called by the scheduler

| | |
|---|---|
| **Pros** | Unified IP blocking — threat intel is just another blocklist source from the middleware's perspective. No separate background task to manage. |
| **Cons** | Bloats the IP Access backend protocol. Mixing static blocklist with dynamic TTL-expiring feeds is a different concern. Every `dispatch()` call pays the cost of checking threat intel (even if no feeds configured). Harder to test in isolation. |
| **Complexity** | High — protocol changes cascade to all backends, tests, and callers |

#### Approach C: Event-Driven — Feeds as Pure Event Producers

Feeds module emits events only — does NOT touch backends directly:
1. `ThreatIntelFetcher` fetches feeds, deduplicates, and emits `THREAT_INTEL_LOADED(event_type=..., ips=[...], source_feed=...)` on the event bus
2. A new `ThreatIntelSubscriber` subscribes to `THREAT_INTEL_LOADED` and calls `backend.add_to_blocklist()` for each IP
3. A second subscriber could feed IPs into WAF escalation directly
4. Scheduler triggers fetcher periodically

| | |
|---|---|
| **Pros** | Maximum decoupling — the fetcher knows nothing about backends. Subscriber can be swapped (WAF, IP access, Redis, whatever). Clean event-driven architecture. |
| **Cons** | Over-engineered for the current use case. Queuing thousands of IPs through the event bus is wasteful — each IP would be a separate event or one massive event with a list payload. Event bus has a 1000-item queue limit; a Firehol feed with 10K IPs would overflow. |
| **Complexity** | Low to build, High to make work at scale |

### Recommendation

**Approach A — Standalone Module with Background Scheduler**

Rationale:
1. **Matches existing patterns**: `src/araxys/waf/escalation.py` is already a subscriber that feeds IPs into AWS WAF. The threat intel module would be a producer that feeds IPs into the existing IP Access backend. Same relationship, reversed direction.
2. **No protocol changes**: The `IPAccessBackend` protocol already supports `add_to_blocklist()`. We only need a bulk convenience method to avoid N Redis round trips for feeds with thousands of IPs.
3. **Testable in isolation**: Each feed can be tested with `respx` mocks and an `InMemoryIPAccessBackend`. No middleware involved.
4. **Easy to disable**: `config.threat_intel = None` → entire module skipped. No middleware dispatch overhead.
5. **CLI is a natural fit**: `araxys threat-intel refresh`, `araxys threat-intel feeds`, `araxys threat-intel stats` fit the existing CLI pattern perfectly.
6. **Shutdown is clean**: Cancel the background task in `shield.shutdown()`, same pattern as `_session_manager.stop_cleanup()` and `event_bus.stop()`.

**Module structure:**

```
src/araxys/threat_intel/
├── __init__.py          # Exports: ThreatIntelConfig, ThreatIntelScheduler
├── config.py            # ThreatIntelConfig, FeedConfig (per-feed)
├── scheduler.py         # ThreatIntelScheduler — asyncio background loop
├── resolver.py          # deduplicate, evict stale, TTL tracking
└── feeds/
    ├── __init__.py      # FeedResult, FeedSource Protocol
    ├── abuseipdb.py     # AbuseIPDB API v2 (free tier: 1000 checks/day)
    ├── alienvault.py    # AlienVault OTX pulses (free, requires API key)
    ├── firehol.py       # Firehol Level 1/2/3 (plaintext, no API key)
    ├── spamhaus.py      # Spamhaus DROP/EDROP (plaintext, no API key)
    └── blocklist_de.py  # blocklist.de (plaintext, no API key)
```

### Feed Sources Detail

| Feed | Type | Auth | Update Freq | IP Count | Block Duration |
|------|------|------|-------------|----------|----------------|
| **Firehol Level 1** | Plaintext HTTP | None | ~5 min (real-time) | ~15K | 24h (feed TTL) |
| **Firehol Level 2** | Plaintext HTTP | None | ~5 min | ~1K | 24h |
| **Firehol Level 3** | Plaintext HTTP | None | ~5 min | ~1K | 24h |
| **Spamhaus DROP** | Plaintext HTTP | None | Daily | ~1K | 24h |
| **Spamhaus EDROP** | Plaintext HTTP | None | Weekly | ~500 | 7d |
| **Blocklist.de** | Plaintext HTTP | None | ~5 min | ~20K | 24h |
| **AbuseIPDB** | REST API | API key (free: 1K/day) | On fetch | Varies | Configurable |
| **AlienVault OTX** | REST API | API key (free) | On fetch | Varies | Configurable |

All plaintext feeds use the same format: one IP or CIDR per line, `#` comments. This means a single generic `PlaintextFeedFetcher` can handle Firehol, Spamhaus, and Blocklist.de with a URL config.

### Schedule Mechanism

**Recommended: Background asyncio task** (not external cron).

Rationale:
- The app already runs an event loop (FastAPI). An `asyncio.create_task()` is zero-cost.
- No external dependencies (cron, celery, APScheduler).
- Clean shutdown: cancel task in `shield.shutdown()`.
- Same pattern as `SessionManager.start_cleanup()`, DLQ consumer, and event bus consumer.

```python
class ThreatIntelScheduler:
    def __init__(self, config, backend, event_bus):
        self._config = config
        self._backend = backend
        self._event_bus = event_bus
        self._task: asyncio.Task | None = None
        self._running = False
        self._resolver = IPResolver(config)  # dedup + TTL

    def start(self):
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def _run(self):
        while self._running:
            for feed in self._config.enabled_feeds():
                await self._fetch_feed(feed)
            await asyncio.sleep(self._config.refresh_interval_seconds)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
```

**Tradeoffs of external cron:**
- Simpler to reason about (no background task lifecycle).
- But: no access to the in-process `IPAccessBackend` instance. A CLI command would need to create its own Redis connection, parse config manually — duplicates wiring logic. Race conditions if CLI runs while the app updates the same Redis keys.
- Works fine for plaintext feeds (just HTTP GET → parse), but awkward for API-key-based feeds where you want config managed by the app.

### Storage & Deduplication

Feeds write directly into `IPAccessBackend.add_to_blocklist()`. This means:
- **InMemory**: IPs go into a Python set. Process restart clears everything. Only appropriate for dev.
- **Redis**: IPs go into `araxys:ip_access:blocklist` Redis SET. Survives restarts. But: **TTL cannot be applied per-IP in a SET** — Redis SETs don't support member-level TTL.

**Solution**: Use a **Sorted Set** for threat intel storage with score-based eviction:

```
araxys:threat_intel:ips  → ZSET (member=IP, score=expiration_timestamp)
araxys:threat_intel:meta:{feed_name} → HASH (last_fetch, ip_count, etag)
```

On each refresh:
1. Fetch feed
2. Deduplicate against current known IPs
3. `ZADD` new IPs with `score = now + ttl_seconds`
4. `ZREMRANGEBYSCORE` to evict expired (score < now)
5. Emit `THREAT_INTEL_LOADED` with count delta

The IP Access backend's `is_blocked()` would need a slight enhancement to also check `ZSCORE ar axys:threat_intel:ips {ip}` — OR, simpler: during each refresh cycle, the scheduler does `backend.add_to_blocklist(ip)` for new IPs and `backend.remove_from_blocklist(ip)` for evicted IPs. This way the IP Access backend remains unchanged.

**Better approach**: Keep threat intel as a **feeder** that syncs into the existing blocklist SET. The scheduler owns TTL tracking in a separate ZSET and periodically reconciles:
```
EVICT_LOOP:
  expired = ZRANGEBYSCORE threat_intel:ips 0 NOW
  for each expired IP:
    remove_from_blocklist(ip)
    ZREM threat_intel:ips ip
```

This keeps IP Access middleware fast (single `SISMEMBER` check) and isolates threat intel TTL complexity in the scheduler module.

### Event System Integration

Threat intel should emit events via the existing `SecurityEventBus`:

**New `SecurityEventType` values needed:**
- `THREAT_INTEL_LOADED` — emitted after each feed refresh completes (metadata: feed_name, ips_loaded, ips_evicted)
- `THREAT_INTEL_MATCH` — emitted when the IP Access middleware blocks an IP that originated from a threat intel feed

The second event (`THREAT_INTEL_MATCH`) requires a small enhancement: the middleware needs to distinguish "blocked because of static blocklist" from "blocked because of threat intel feed". This could be stored as metadata on the IP in Redis, or more simply, the middleware checks the `araxys:threat_intel:ips` ZSET as a secondary lookup when blocking an IP.

### Config Structure

```python
class FeedConfig(BaseModel):
    """Configuration for a single threat intel feed."""
    enabled: bool = True
    refresh_interval_seconds: int = Field(default=3600, ge=60)
    ttl_seconds: int = Field(default=86400, ge=3600)
    api_key: str | None = Field(default=None)
    url: str | None = Field(default=None)  # Override default feed URL

class ThreatIntelConfig(BaseModel):
    """Configuration for the Threat Intelligence Feeds module."""
    enabled: bool = False
    refresh_interval_seconds: int = Field(default=3600, ge=60, le=86400)
    firehol_level1: FeedConfig | None = Field(default=None)
    firehol_level2: FeedConfig | None = Field(default=None)
    firehol_level3: FeedConfig | None = Field(default=None)
    spamhaus_drop: FeedConfig | None = Field(default=None)
    spamhaus_edrop: FeedConfig | None = Field(default=None)
    blocklist_de: FeedConfig | None = Field(default=None)
    abuseipdb: FeedConfig | None = Field(default=None)
    alienvault_otx: FeedConfig | None = Field(default=None)

# On AraxysConfig:
threat_intel: ThreatIntelConfig | None = Field(
    default=None,
    description="Threat intelligence feeds config (None = feature disabled)."
)
```

Each feed is `None` by default → disabled. Setting `FeedConfig()` with defaults enables it. This matches the `Field(default=None)` pattern used by all v0.3+ modules.

### CLI Commands

```bash
araxys threat-intel refresh       # Force-refresh all enabled feeds
araxys threat-intel refresh --feed firehol_level1  # Refresh one feed
araxys threat-intel feeds         # List enabled feeds with last fetch time, IP count
araxys threat-intel stats         # Show total blocked IPs from threat intel
araxys threat-intel purge         # Remove all threat-intel-derived IPs from blocklist
```

These follow the existing `keys` and `waf` sub-command patterns.

### Testing Strategy

No real API keys needed. All feeds are tested with mocked HTTP:

1. **Plaintext feeds** (Firehol, Spamhaus, Blocklist.de): Use fixture files with sample IP lists. Test parsing edge cases (comments, blank lines, IPv6, CIDR notation).

2. **API feeds** (AbuseIPDB, AlienVault OTX): Use `respx` to mock HTTP responses with fixture JSON payloads.

3. **Scheduler**: Test with `asyncio` and `unittest.mock` — verify fetch intervals, start/stop lifecycle, eviction loop.

4. **Resolver**: Test deduplication with overlapping feeds (same IP in Firehol + Blocklist.de).

5. **Integration**: Test that scheduler → backend → middleware chain works end-to-end with `InMemoryIPAccessBackend`.

```python
# Example fixture for Firehol Level 1
# tests/fixtures/firehol_level1_sample.txt
# Firehol Level 1 sample
1.2.3.4
5.6.7.0/24
# this is a comment
2001:db8::1
```

### Dependencies

- **Core**: `httpx>=0.27` — already a production dependency. All feeds use async HTTP.
- **Dev**: `respx>=0.23.1` — already in dev deps for HTTP mocking.
- **Optional**: None needed. If we want `ipaddress`-based CIDR expansion for feeds that return CIDR ranges, [`netaddr`](https://pypi.org/project/netaddr/) is nice but `ipaddress` stdlib can handle it.

No new dependencies required. This keeps the module zero-cost to install.

### Risks

1. **Redis key collision**: Threat intel ZSET (`araxys:threat_intel:ips`) shared with IP access SET — no collision risk since they're different Redis types, but key naming must be unambiguous.

2. **Feed outages**: If a feed is down, the scheduler should log a warning and skip, not crash. Current WAF escalation pattern already does this (`logger.exception` inside try/except).

3. **Rate limiting by feed providers**: AbuseIPDB free tier is 1000 checks/day. Firehol and Blocklist.de have no rate limits (they're CDN-backed plaintext). The scheduler must respect per-feed `refresh_interval_seconds`.

4. **Large feed bursts**: Blocklist.de has ~20K IPs. Redis `SADD` with 20K members is O(N) but very fast. `ZADD` with 20K members is also fast. However, the initial sync should be batched (pipeline 1000 IPs at a time) to avoid blocking the event loop.

5. **False positives**: Threat intel feeds are aggressive — they may block CDN IPs, shared hosting, or corporate NAT gateways. `exclude_ips` / `allowlist` field in `ThreatIntelConfig` is essential.

6. **Thread safety**: The scheduler runs as an async task in the same event loop. `InMemoryIPAccessBackend` sets are not locked, but async tasks don't preempt mid-`await`, so `add_to_blocklist()` is effectively atomic. Redis commands are naturally atomic.

### Complexity Estimate

- **Overall**: Medium (4-5 days of focused work)
- **Config models**: 2-3 hours
- **Feed fetchers**: 1 day (5-6 feeds × 2 hours each, including fixtures)
- **Scheduler + resolver**: 1 day
- **Shield integration**: 2-3 hours
- **CLI**: 3-4 hours
- **Tests**: 1.5 days
- **Documentation**: 2 hours

This is NOT a high-risk change. It's additive — no existing code is modified except config model additions and shield wiring. Rollback is a config toggle (`threat_intel.enabled = false`).

### Ready for Proposal

**Yes**. The exploration confirms:
1. The existing IP Access backend protocol supports `add_to_blocklist()` — threat intel can feed directly into it
2. No new dependencies needed (httpx is already core)
3. The WAF escalation module provides a proven subscriber/background-task pattern to follow
4. Config structure fits the existing `Field(default=None)` convention
5. Testing with respx and fixture files is straightforward
6. CLI pattern (Typer sub-commands) is well-established

No blockers. The next phase should be `sdd-propose` to define scope, approach, and rollback plan.
