# Design: Dynamic Secrets Rotation

## Technical Approach

Reuse the `ThreatIntelScheduler` pattern (background `asyncio.Task` with `start()`/`stop()` lifecycle) to periodically re-resolve credentials via the existing `ChainedResolver` chain. On credential change, hot-swap pool clients via `reload_url()` (Redis pools, atomic swap with lock guard) or `reload_dsn()` (PGPool, close+recreate with min_size pre-warming). Emit events on success/failure via `SecurityEventBus`. Wire lifecycle into Shield (`__init__` → start, `shutdown()` → stop).

## Architecture Decisions

| Decision | Options | Tradeoffs | Decision |
|---|---|---|---|
| `reload_url()` location | A) `ConnectionPool` Protocol method | A: forces `InMemoryPool` no-op; uniform contract | **A**: Protocol method with `InMemoryPool` no-op |
| | B) Pool-type-specific mixin | B: avoids no-op but loses static dispatch | |
| Redis client swap guard | A) Reuse existing `_reconnect_lock` | A: zero new fields, proven pattern | **A**: Reuse lock; `_reconnect()` and `reload_url()` serialize naturally |
| | B) New dedicated `_swap_lock` | B: semantic clarity but redundant | |
| PGPool DSN reload | A) Full close+create+pre-warm | A: <100ms drain, documented limitation | **A**: Close+recreate; `asyncpg.Pool` has no hot-swap API |
| | B) Partial connection migration | B: complex, leak-prone, undocumented asyncpg internals | |
| Scheduler→pool mapping | A) `DatabaseSecurityManager.rotate_target()` | A: manager owns mapping, scheduler delegates | **A**: Manager knows which pool maps to which target |
| | B) Scheduler holds pool references directly | B: scheduler knows too much about pool internals | |

## Data Flow

```
SecretsRotationScheduler._run()
  │
  ├─ _sleep_with_cancel_check(interval)
  │
  └─ for target in targets:
       │
       ├─ emit SECRET_ROTATING
       ├─ resolver.resolve(target) ──→ ChainedResolver (EnvVar→Vault→AWS)
       ├─ if value changed:
       │    └─ manager.rotate_target(target)
       │         ├─ target is "database" → pg_pool.reload_dsn(new_dsn)
       │         │    ├─ PING new DSN  ── fail → SecretRotationError
       │         │    ├─ close old pool
       │         │    ├─ create new pool (min_size pre-warm)
       │         │    └─ swap reference
       │         └─ else → pool.reload_url(new_url)
       │              ├─ PING new URL    ── fail → SecretRotationError
       │              ├─ acquire _reconnect_lock
       │              ├─ create new client
       │              ├─ swap self._redis reference
       │              └─ close old client
       └─ emit SECRET_ROTATED | SECRET_ROTATION_FAILED
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/db_security/rotation.py` | **Create** | `SecretsRotationScheduler` — background asyncio task, per-target rotation loop, stats tracking |
| `src/araxys/db_security/pool.py` | Modify | Add `reload_url(url)` to `ConnectionPool` Protocol; implement on `RedisPool`, `RedisSentinelPool`, `RedisClusterPool`, `InMemoryPool` |
| `src/araxys/db_security/pg_pool.py` | Modify | Add `reload_dsn(dsn)` — PING-then-close+create with pre-warming |
| `src/araxys/db_security/manager.py` | Modify | Add `rotate_target(target)` method, expose resolver/pools to scheduler, scheduler lifecycle |
| `src/araxys/core/config.py` | Modify | Add `SecretsRotationConfig` model (enabled, interval_seconds, targets, rotate_on_startup, fail_closed) |
| `src/araxys/core/types.py` | Modify | Add `SECRET_ROTATING`, `SECRET_ROTATED`, `SECRET_ROTATION_FAILED` to `SecurityEventType` |
| `src/araxys/core/exceptions.py` | Modify | Add `SecretRotationError(AraxysError)` |
| `src/araxys/shield.py` | Modify | Create+start scheduler on init when enabled; stop on shutdown |
| `src/araxys/admin/router.py` | Modify | Add `POST /admin/secrets/rotate`, `GET /admin/secrets/status` |
| `src/araxys/cli.py` | Modify | Add `secrets rotate [--target]`, `secrets status` typer commands |

## Interfaces / Contracts

```python
# ConnectionPool Protocol addition
class ConnectionPool(Protocol):
    async def reload_url(self, url: str) -> None: ...

# PGPool
class PGPool:
    async def reload_dsn(self, dsn: str) -> None: ...

# SecretsRotationConfig
class SecretsRotationConfig(BaseModel):
    enabled: bool = False
    interval_seconds: int = 3600
    targets: list[str] = Field(default_factory=list)
    rotate_on_startup: bool = True
    fail_closed: bool = False

# Scheduler public API
class SecretsRotationScheduler:
    def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def rotate_targets(self, targets: list[str] | None = None) -> dict: ...
    def stats(self) -> dict: ...
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `reload_url()` on each pool variant | PING mock, verify old client closed, new client swapped, lock held, no-op on same URL |
| Unit | `reload_dsn()` on PGPool | asyncpg mock, verify pool close+create cycle, drain < 100ms |
| Unit | `SecretsRotationConfig` validation | Pydantic model tests — defaults, targets validation |
| Unit | `SecretRotationError` | Exception hierarchy test |
| Integration | `SecretsRotationScheduler` loop | Mock resolver, verify interval timing, event emission, fail_closed behavior |
| Integration | Shield lifecycle | Verify scheduler starts on init (enabled=True), stops on shutdown |
| Integration | Admin endpoints | Test auth guard, manual rotate, status response |
| E2E | CLI commands | `araxys secrets rotate --target redis_cache`, verify resolver call + pool reload |

## Migration / Rollout

No migration required. Defaults to `enabled=False` — opt-in, zero impact. `reload_url()`/`reload_dsn()` are additive; existing acquire/reconnect paths untouched. To fully revert: remove scheduler reference from Shield.

## Open Questions

- [ ] Target-to-pool mapping convention: should `database` → PGPool be hardcoded, or should config support explicit `pool_type` per target?
- [ ] Health-check `_reconnect()` and rotation `reload_url()` share the same lock — should health-check-driven reconnect skip PING for already-rotated URLs?
