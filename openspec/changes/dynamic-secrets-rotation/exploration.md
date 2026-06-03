# Exploration: Dynamic Secrets Rotation (v0.14)

## Current State

### Secret Resolver Chain
The codebase has a mature **secret resolver chain** (`src/araxys/db_security/secrets.py`) that implements the `ConnectionStringResolver` Protocol with `async resolve(name: str) -> str | None`:

1. **EnvVarResolver** — reads from `ARAXYS_DB__{NAME}` env vars
2. **VaultResolver** — reads from HashiCorp Vault KV v2 at `{mount_path}/data/{name}`, uses `hvac` (optional dep `araxys[vault]`)
3. **AWSSecretsResolver** — reads from AWS Secrets Manager at `{secret_prefix}{name}`, uses `boto3` (optional dep `araxys[aws_secrets]`)

A `ChainedResolver` composes them with first-non-None-wins semantics. All resolvers are **fail-soft by default** (return `None` on error), with an optional `fail_closed` flag.

### How Secrets Are Consumed Today
`DatabaseSecurityManager.__init__()` builds the resolver chain from `SecretsConfig` and creates Redis/PostgreSQL pools **once** at construction time. The pool URL/DNS is **set at init and never re-resolved**:

```python
# manager.py — pool URL is static after init
self._pool = RedisPool(url=config.redis_pool.url, ...)
self._pg_pool = PGPool(dsn=config.pg_pool.dsn, ...)
```

**The resolver chain exists but is never called after init.** It sits as `self._resolver` on the manager, unused for pooling. This is the gap rotation must fill.

### Database Pool Architecture
- **RedisPool** (`pool.py`): Wraps `redis.asyncio.Redis`. Has health checks (background PING), leak detection, idle timeout, reconnection. Creates client via `Redis.from_url(url)`.
- **RedisSentinelPool**: Same pattern with `Sentinel` client.
- **RedisClusterPool**: Same with `RedisCluster` client.
- **PGPool** (`pg_pool.py`): Wraps `asyncpg.create_pool()`. Has health checks, `start()`/`shutdown()`. DSN passed at init.

All pools already have a **reconnection mechanism** (`_reconnect()`) but it reconnects to the **same URL** — not a rotated credential.

### Existing Rotation Mechanisms
**None.** The only "rotation" in the codebase is:
- JWT token rotation (`TOKEN_ROTATED` events)
- API key rotation in admin router (`POST /admin/api-keys/{prefix}/rotate`)
Neither touches database credentials.

### Scheduling Patterns
No `apscheduler` dependency. The pattern is **background `asyncio.Task` loops**:
- `ThreatIntelScheduler` (best reference): `start()` → `asyncio.create_task(self._run())`, `stop()` → cancel + gather, per-feed sub-tasks, staggered start, `_running` flag, `_sleep_with_cancel_check()`
- Pool health loops: `asyncio.create_task(self._health_loop())` in `__init__`, cancelled on `close()`
- Session cleanup: same pattern

### Event Bus
`SecurityEventBus` (`webhooks/emitter.py`) — async pub/sub with `asyncio.Queue`. `emit(event)` drops if queue is full. Subscribers are async callables invoked in sequence; failures are isolated.

Existing `SecurityEventType` values relevant to rotation: `TOKEN_ROTATED`. Need new ones.

### CLI Patterns
- Typer + Rich (table output, colored status)
- Threat intel CLI (`threat_intel/cli.py`) is the closest model: commands for refresh, stats, purge
- Admin router (`admin/router.py`): FastAPI router with `_require_admin()` guard, provides REST API for inspection

---

## Affected Areas

| File/Module | Why Affected |
|---|---|
| `src/araxys/db_security/secrets.py` | Resolver chain — extend with `write()` method for Vault/AWS to push new passwords |
| `src/araxys/db_security/manager.py` | Manager — new rotation coordinator, scheduler lifecycle, pool reload |
| `src/araxys/db_security/pool.py` | Redis pools — new `reload_url()` method for hot credential swap without full reconnect |
| `src/araxys/db_security/pg_pool.py` | PG pool — new `reload_dsn()` method for hot credential swap |
| `src/araxys/core/config.py` | Config — new `SecretsRotationConfig` model (rotation_enabled, interval, targets) |
| `src/araxys/core/types.py` | Types — new `SecurityEventType` values: `SECRET_ROTATED`, `SECRET_ROTATION_FAILED`, `SECRET_ROTATING` |
| `src/araxys/core/exceptions.py` | Exceptions — new `SecretRotationError` |
| `src/araxys/shield.py` | Shield — wire rotation scheduler lifecycle (start on init, stop on shutdown) |
| `src/araxys/admin/router.py` | Admin — new endpoints: `POST /admin/secrets/rotate`, `GET /admin/secrets/status` |
| `src/araxys/cli.py` | CLI — new `araxys secrets rotate` and `araxys secrets status` commands |
| `tests/test_secrets.py` | Tests — rotation-specific resolver tests |
| `tests/test_db_security.py` | Tests — manager/pool reload tests |
| `tests/test_pool.py` | Tests — pool reload URL tests |
| `tests/test_pg_pool.py` | Tests — PG pool reload DSN tests |
| `pyproject.toml` | Dependencies — no new deps needed (hvac and boto3 already optional) |

---

## Approaches

### Approach 1: Graceful Pool Reload with Background Scheduler (Recommended)

**Description**: A `SecretsRotationScheduler` runs as a background `asyncio.Task` (following `ThreatIntelScheduler` pattern). On each interval:
1. Re-resolve credentials via the resolver chain
2. If credentials changed, call `pool.reload_url(new_url)` / `pg_pool.reload_dsn(new_dsn)` to perform an atomic hot-swap
3. Emit `SECRET_ROTATED` event on success, `SECRET_ROTATION_FAILED` on error

Pools gain a `reload_url()` method that creates a new underlying client, PINGs it, swaps the reference atomically, then closes the old client. No `acquire()` calls are dropped — the swap window is sub-millisecond.

**Config**:
```python
class SecretsRotationConfig(BaseModel):
    enabled: bool = False
    interval_seconds: int = 3600  # rotate every hour
    targets: list[Literal["redis", "postgres"]] = ["redis"]
    rotate_on_startup: bool = True
    fail_closed: bool = False  # if True, failed rotation raises instead of retrying
```

**Pros**:
- Follows existing scheduler pattern exactly (ThreatIntelScheduler)
- Zero new dependencies
- Pool hot-swap preserves in-flight connections
- Resolver chain already exists — just needs to be called periodically
- CLI/admin with rotation commands reuses existing CLI/admin patterns
- Full event emission for observability

**Cons**:
- `reload_url()` must be implemented carefully per pool type (standalone, sentinel, cluster)
- `asyncpg.Pool` hot DSN swap is non-trivial — may need pool.close() + pool.start()
- Need to thread-safely swap the underlying Redis client

**Effort**: Medium

---

### Approach 2: External Coordinator + Managed Rotation (Two-Pass)

**Description**: The `DatabaseSecurityManager` gains a `rotate()` method called externally (by a cron job, Kubernetes CronJob, or admin endpoint). No background scheduler — rotation is triggered explicitly.

**Config**: No interval config — just `rotation_enabled: bool`.

**Pros**:
- Simpler: no background task to manage
- Works well with Kubernetes CronJob or external orchestrator
- Explicit control — rotate only when you know new creds are available

**Cons**:
- No automatic rotation — ops burden for scheduling
- Must integrate with external cron/scheduler
- Risk: if cron fails, stale credentials go undetected
- Breaks the "batteries included" philosophy of Araxys

**Effort**: Low

---

### Approach 3: Vault/AWS Lease-Based Rotation with Renewal

**Description**: VaultResolver and AWSSecretsResolver gain lease/renewal awareness. Vault dynamic secrets provide a `lease_id` + `lease_duration`; AWS provides `VersionStages`. A lease renewal loop runs in the background, refreshing credentials before lease expiry.

New Protocol method: `async renew(name: str) -> tuple[str, float]` returning (new_secret, ttl_seconds).

**Pros**:
- Natively handles Vault dynamic secrets and AWS rotation
- Lease-aware — rotates before expiry, not on fixed interval
- More secure: short-lived credentials with automatic renewal

**Cons**:
- Much higher complexity
- Vault dynamic secrets require Vault Enterprise or specific auth backends
- Not all resolvers support leases (EnvVarResolver has no lease concept)
- Significant resolver protocol change — breaking `ConnectionStringResolver` Protocol
- Requires `hvac` API changes, boto3 Secrets Manager rotation APIs

**Effort**: High

---

### Approach 4: Full Disconnect/Reconnect Cycle (Simplest)

**Description**: On rotation trigger (manual or scheduled), shut down the pool entirely and recreate it with new credentials. All in-flight connections are dropped.

**Pros**:
- Trivially simple
- No pool reload complexity
- Guaranteed clean state

**Cons**:
- **Drops all in-flight connections** — production outage during rotation
- Not appropriate for a security library that should be transparent
- Violates the promise of "non-disruptive" rotation

**Effort**: Low (but unacceptable UX)

---

## Recommendation

**Approach 1: Graceful Pool Reload with Background Scheduler** is the right choice for v0.14:

1. **It matches the existing architecture**: `ThreatIntelScheduler` is the proven pattern — background `asyncio.Task`, `start()`/`stop()` lifecycle, per-target sub-tasks, `_sleep_with_cancel_check()` for clean cancellation, stats tracking.
2. **It reuses existing infrastructure**: The resolver chain (`ChainedResolver`) already exists and is wired into `DatabaseSecurityManager`. We just need to call it periodically and apply the result.
3. **Hot-swap pools**: `RedisPool._reconnect()` already does 90% of the work — close old client, create new from URL, PING, replace reference. We generalize this into `reload_url(url)`.
4. **No new dependencies**: `asyncio` is all we need.
5. **Observability**: Event bus integration with new `SECRET_ROTATED`/`SECRET_ROTATION_FAILED` events is trivial given the existing `emit()` pattern.

**For PGPool**: Since `asyncpg.Pool` doesn't support hot DSN swap, we accept a brief connection drain: close the pool, recreate with new DSN, call `start()`. Document this as a known limitation — in practice, the pool drain window is < 100ms with `_pool.close()` followed by immediate recreation.

**Implementation split into work units**:
1. Config + types + exceptions (new models)
2. Pool `reload_url()` / `reload_dsn()` methods
3. `SecretsRotationScheduler` background task
4. Shield integration (lifecycle wiring)
5. Admin endpoints (manual trigger + status)
6. CLI commands (`araxys secrets rotate`)

---

## Risks

- **PGPool DSN reload**: `asyncpg` has no built-in hot-swap. Workaround: close + recreate is sub-100ms but is technically a brief hard-disconnect. Mitigated by connection retry logic in FastAPI + pool min_size pre-warming on `start()`.
- **Sentinel/Cluster pool reload**: Sentinel pools track master topology — a `reload_url()` must preserve sentinel nodes. Cluster pools have `RedisCluster` which needs `_create_client()`. Both already have `_reconnect()` — generalization is straightforward but must be verified for each mode.
- **Race condition**: An `acquire()` that starts before the swap but completes after could receive a stale (closing) client. Mitigated by guard flag + lock pattern already used in `_reconnect()`.
- **Vault token expiry**: If the VaultResolver's token expires between rotation cycles, the resolver chain fails-soft (returns None), and rotation is skipped with a warning event. The `fail_closed` config option controls whether this is an error.
- **No mechanism to push new credentials to secret stores**: The rotation feature rotates credentials IN Araxys's pool. It does NOT write new passwords to Vault/AWS. For v0.14 we scope to **credential reload only**. Full write-back rotation (generate new password → push to Vault → reload pool) is v0.15.

---

## Ready for Proposal

**Yes.** The exploration confirms:

1. The resolver chain architecture fully supports periodic re-resolution.
2. Pool reload can be built on existing `_reconnect()` infrastructure.
3. The scheduling pattern (`ThreatIntelScheduler`) is proven and directly applicable.
4. No new dependencies are needed.
5. The scope is well-defined: `SecretsRotationScheduler` + pool `reload_url()` + config + events + CLI/admin.

The two unresolved design decisions to address in the proposal phase:
- Should `reload_url()` be a protocol method on `ConnectionPool`, or pool-type-specific?
- Should PG pool reload use full close+start (simpler) or attempt partial connection migration (complex)?
