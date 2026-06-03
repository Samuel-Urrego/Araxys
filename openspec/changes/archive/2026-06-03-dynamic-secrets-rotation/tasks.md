# Tasks: Dynamic Secrets Rotation

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 650–800 |
| 400-line budget risk | **High** |
| Chained PRs recommended | Yes |
| Delivery strategy | force-chained |
| Decision needed before apply | No |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Base |
|------|------|-----------|------|
| 1 | Config model, event types, exception — standalone deliverable | PR 1 | main |
| 2 | Pool `reload_url()`/`reload_dsn()` methods on all pool variants | PR 2 | main (after PR 1 merged) |
| 3 | `SecretsRotationScheduler` + `manager.rotate_target()` | PR 3 | main (after PR 2 merged) |
| 4 | Shield lifecycle wiring, admin endpoints, CLI commands | PR 4 | main (after PR 3 merged) |

---

## Phase 1: Foundation (Config, Types, Exceptions)

- [x] 1.1 Add `SecretsRotationConfig` model to `src/araxys/core/config.py` — fields: `enabled: bool = False`, `interval_seconds: int = 3600`, `targets: list[str] = []`, `rotate_on_startup: bool = True`, `fail_closed: bool = False`; add as optional field (`SecretsRotationConfig | None`) on `AraxysConfig`
- [x] 1.2 Write RED test: `tests/test_config.py` — test `SecretsRotationConfig` defaults, `enabled=False` produces no scheduler, missing key disables rotation
- [x] 1.3 Write GREEN implementation for config model (covered by 1.1 — make test pass)
- [x] 1.4 Add `SECRET_ROTATING`, `SECRET_ROTATED`, `SECRET_ROTATION_FAILED` to `SecurityEventType` enum in `src/araxys/core/types.py`
- [x] 1.5 Write RED test: `tests/test_core.py` — test new enum values exist, can construct `SecurityEvent` with each type
- [x] 1.6 Add `SecretRotationError(AraxysError)` to `src/araxys/core/exceptions.py`
- [x] 1.7 Write RED test: `tests/test_core.py` — test `SecretRotationError` inherits from `AraxysError`, message propagation

---

## Phase 2: Pool Reload (Hot-Swap Methods)

- [ ] 2.1 Add `async def reload_url(self, url: str) -> None: ...` to `ConnectionPool` Protocol in `src/araxys/db_security/pool.py`
- [ ] 2.2 Write RED test: `tests/test_pool.py` — `test_reload_url_same_url_is_noop` (RedisPool), `test_reload_url_ping_failure_preserves_client` (mock PING raises), `test_reload_url_atomic_swap` (old client closed, new client in place after swap)
- [ ] 2.3 Implement `RedisPool.reload_url()` — PING new URL → acquire `_reconnect_lock` → create new `Redis` client → swap `self._redis` → close old. Raise `SecretRotationError` on PING failure
- [ ] 2.4 Implement `RedisSentinelPool.reload_url()` — generalize `_reconnect()` pattern for URL-based client swap with lock guard
- [ ] 2.5 Implement `RedisClusterPool.reload_url()` — same pattern using `_create_client()` and `_reconnect_lock`
- [ ] 2.6 Implement `InMemoryPool.reload_url()` — no-op (satisfy Protocol contract)
- [ ] 2.7 Implement `PGPool.reload_dsn()` in `src/araxys/db_security/pg_pool.py` — PING new DSN (create temp pool, `SELECT 1`), close old pool, create new pool with `min_size` pre-warming, swap `self._pool`. Raise `SecretRotationError` on PING failure
- [ ] 2.8 Write RED test: `tests/test_pg_pool.py` — `test_reload_dsn_same_dsn_noop`, `test_reload_dsn_ping_failure_preserves_pool`, `test_reload_dsn_prewarms_min_size`
- [ ] 2.9 Add pool reload unit tests for sentinel, cluster, and InMemory variants in `tests/test_pool.py`
- [ ] 2.10 REFACTOR: verify all pool `_reconnect()` implementations still pass existing tests; ensure lock reuse between `_reconnect()` and `reload_url()` serializes correctly

---

## Phase 3: Rotation Scheduler (Core Engine)

- [ ] 3.1 Create `src/araxys/db_security/rotation.py` — `SecretsRotationScheduler` class with `__init__(manager, resolver, config, event_bus)`, `start()`, `stop()`, per-target stats dict, `_sleep_with_cancel_check()` following ThreatIntelScheduler pattern
- [ ] 3.2 Write RED test: `tests/test_rotation.py` — `test_scheduler_start_creates_task`, `test_scheduler_stop_cancels_task`, `test_rotate_on_startup_fires_immediately`, `test_sleep_cancel_check_exits_on_stop`
- [ ] 3.3 Implement `_run()` loop — on each interval: for each target in `config.targets`: emit `SECRET_ROTATING`, resolve via manager resolver, compare with current value, call `manager.rotate_target()` if changed, emit `SECRET_ROTATED` on success or `SECRET_ROTATION_FAILED` on error
- [ ] 3.4 Write RED test: `tests/test_rotation.py` — `test_credential_unchanged_skips_rotation`, `test_fail_soft_emits_event_and_continues`, `test_fail_closed_stops_scheduler`
- [ ] 3.5 Add `rotate_target(target: str)` method to `DatabaseSecurityManager` in `src/araxys/db_security/manager.py` — if target is `"database"` → `pg_pool.reload_dsn()`, else → `pool.reload_url()` using resolver to rebuild URL/DSN
- [ ] 3.6 Expose resolver on manager (`manager.resolver` property) so scheduler can call `resolve()` to detect credential changes before triggering rotation
- [ ] 3.7 Write RED test: `tests/test_db_security.py` — `test_rotate_target_database_calls_reload_dsn`, `test_rotate_target_redis_calls_reload_url`
- [ ] 3.8 Implement `rotate_targets(targets)` public API on scheduler — on-demand rotation for admin/CLI; implement `stats()` returning per-target `last_success`, `last_error`, `last_rotated`
- [ ] 3.9 Write RED test: `tests/test_rotation.py` — `test_rotate_targets_specific_target`, `test_stats_tracks_success_and_failure`
- [ ] 3.10 REFACTOR: verify scheduler error isolation — one target failure must not block other targets

---

## Phase 4: Integration (Shield, Admin, CLI)

- [ ] 4.1 Wire scheduler creation and `start()` in `AraxysShield.__init__()` — conditioned on `config.rotation` not None and `rotation.enabled=True`; store as `self._rotation_scheduler`
- [ ] 4.2 Wire scheduler `stop()` in `AraxysShield.shutdown()` — stop rotation before db_security shutdown
- [ ] 4.3 Write RED test: `tests/test_shield_v3.py` — `test_rotation_enabled_creates_scheduler`, `test_rotation_disabled_no_scheduler`, `test_shutdown_stops_scheduler`
- [ ] 4.4 Add `POST /admin/secrets/rotate` endpoint to `src/araxys/admin/router.py` — body `{"targets": [...]}`, calls `scheduler.rotate_targets()`, returns per-target result
- [ ] 4.5 Add `GET /admin/secrets/status` endpoint — returns `enabled`, `interval_seconds`, `targets`, per-target `last_success`/`last_error`/`last_rotated` from `scheduler.stats()`
- [ ] 4.6 Write RED test: `tests/test_admin.py` — `test_secrets_rotate_manual_trigger`, `test_secrets_status_returns_config_and_stats`, `test_secrets_endpoints_require_admin`
- [ ] 4.7 Add `araxys secrets rotate [--target NAME]` Typer command to `src/araxys/cli.py` — parses config, resolves via environment, calls scheduler `rotate_targets()`, outputs Rich table with per-target status
- [ ] 4.8 Add `araxys secrets status` Typer command — prints Rich table: target name, last rotation timestamp, success/failure status, error message if any
- [ ] 4.9 Write RED test: `tests/test_cli.py` — `test_secrets_rotate_all_targets`, `test_secrets_rotate_specific_target`, `test_secrets_status_output`
