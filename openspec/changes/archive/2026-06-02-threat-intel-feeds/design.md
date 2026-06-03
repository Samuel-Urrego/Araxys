# Design: Threat Intelligence Feeds Module

## Technical Approach

Background `asyncio.create_task()` scheduler wired via `shield.py`, following the DLQ consumer / session cleanup pattern. Fetches enabled feeds on per-feed intervals via `httpx`, deduplicates IPs in-memory, loads into `IPAccessBackend.add_to_blocklist()`, tracks TTL in Redis ZSET `araxys:threat_intel:ips` (or in-memory dict fallback). Eviction runs on each sync loop. Emits `THREAT_INTEL_LOADED` events via `SecurityEventBus`.

## Architecture Decisions

| Decision | Choice | Alternatives | Rationale |
|----------|--------|-------------|-----------|
| Config location | `ThreatIntelConfig` in `core/config.py`; `FeedConfig` + defaults in `threat_intel/config.py` | All in module; all in core | Matches v0.13 pattern (`WafEscalationConfig` in core). Feed-specific sub-models keep module self-contained for feed constants |
| Storage strategy | Redis ZSET `araxys:threat_intel:ips` with score=expiration_ts | Hash with per-IP TTL; separate SET per feed | ZSET gives O(log N) range-query eviction. Single key simplifies purge. Matches existing `RedisIPAccessBackend` SET pattern |
| Feed parser reuse | Single `PlaintextFeedFetcher` class, 6 instances configured by `FeedConfig` | Per-source classes | All 6 plaintext feeds share identical format (IP-per-line, `#` comments). Separate class only for AbuseIPDB/OTX API |
| Bulk loading | 1K-IP batches via Redis pipeline (`sadd` + `zadd`) on `RedisIPAccessBackend` | Single `sadd` per IP | Blocklist.de ≈20K IPs. Pipeline batching avoids event-loop blocking; follows proposal mitigation |
| `THREAT_INTEL_MATCH` emission | Check Redis ZSET `ZSCORE` on block; emit if found | Separate SET of origin IPs; metadata in blocklist SET | Reuses existing ZSET — no extra storage. O(1) lookup. Deferred to middleware's `_deny()` path |

## Data Flow

```
Feed URL ──httpx──▶ FeedFetcher ──[IPs]──▶ ThreatIntelScheduler
                                                │
                                        ┌───────┴───────┐
                                        ▼               ▼
                                 Resolver.dedup()  Resolver.evict()
                                        │               │
                                        ▼               ▼
                           IPAccessBackend        Redis ZSET
                           .add_to_blocklist()   ZREMRANGEBYSCORE
                                        │
                                        ▼
                                 SecurityEventBus
                                 → THREAT_INTEL_LOADED
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/threat_intel/__init__.py` | Create | Public exports |
| `src/araxys/threat_intel/config.py` | Create | `ThreatIntelConfig`, `FeedConfig`, `FEED_DEFAULTS` dict |
| `src/araxys/threat_intel/scheduler.py` | Create | `ThreatIntelScheduler` — asyncio loop, fetch/evict cycle |
| `src/araxys/threat_intel/resolver.py` | Create | IP dedup, exclude_ips filter, TTL tracking, eviction |
| `src/araxys/threat_intel/feeds/__init__.py` | Create | `FeedResult`, `FeedSource` Protocol |
| `src/araxys/threat_intel/feeds/plaintext.py` | Create | `PlaintextFeedFetcher` — Firehol/Spamhaus/Blocklist.de |
| `src/araxys/threat_intel/feeds/abuseipdb.py` | Create | `AbuseIPDBFeedFetcher` — REST API v2 |
| `src/araxys/threat_intel/feeds/alienvault.py` | Create | `AlienVaultFeedFetcher` — OTX pulses API |
| `src/araxys/core/config.py` | Modify | Add `ThreatIntelConfig` model + `threat_intel` field on `AraxysConfig` |
| `src/araxys/core/types.py` | Modify | Add `THREAT_INTEL_LOADED`, `THREAT_INTEL_MATCH` to `SecurityEventType` |
| `src/araxys/shield.py` | Modify | `_register_threat_intel()` in `__init__`, cancel in `shutdown()` |
| `src/araxys/cli.py` | Modify | Add `threat_intel_app` Typer sub-command (refresh/feeds/stats/purge) |
| `src/araxys/ip_access/backends.py` | Modify | Add `add_bulk_to_blocklist(ips: list[str])` to `RedisIPAccessBackend` |
| `src/araxys/__init__.py` | Modify | Export `ThreatIntelConfig`, `ThreatIntelScheduler` |

## Interfaces / Contracts

```python
# FeedSource Protocol
class FeedSource(Protocol):
    name: str
    async def fetch(self, config: FeedConfig) -> FeedResult: ...

@dataclass
class FeedResult:
    feed_name: str
    ips: list[str]
    fetched_at: datetime
    errors: list[str]

# ThreatIntelScheduler
class ThreatIntelScheduler:
    def __init__(self, config: ThreatIntelConfig, backend: IPAccessBackend,
                 redis: Redis | None, event_bus: SecurityEventBus | None): ...
    async def run(self) -> None: ...   # background loop
    async def refresh(self, feed_name: str | None = None) -> dict: ...  # on-demand
    async def stats(self) -> dict: ...
    async def purge(self) -> int: ...
    async def shutdown(self) -> None: ...
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit — feeds | Plaintext parser (comments, blanks, CIDR), AbuseIPDB JSON parsing, OTX pulses parsing | `pytest` + `httpx.MockTransport` (respx) per feed |
| Unit — resolver | Dedup, exclude_ips filtering, TTL score calculation, eviction selection | Pure logic, no I/O |
| Unit — scheduler | Staggered start, per-feed error isolation, `try/except` per feed | Mock `httpx`, `IPAccessBackend` |
| Integration | Full fetch→block→evict cycle, shutdown cancels task | Real `RedisIPAccessBackend` with `fakeredis` |
| CLI | refresh --feed, feeds table, stats output, purge count | `typer.testing.CliRunner` |

## Migration / Rollout

No migration required. Module is fully additive and disabled by default (`threat_intel.enabled = False`). Rollback: set `ARAXYS_THREAT_INTEL__ENABLED=false` or omit config key. Run `araxys threat-intel purge` to clean blocklist.

## Open Questions

- None — all design decisions resolved.
