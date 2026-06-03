# Proposal: Dynamic Secrets Rotation

## Intent

Secrets are resolved once at init via the `ChainedResolver` chain (EnvVar → Vault → AWS), then never re-evaluated. Pools reconnect to the same URL indefinitely. No credential rotation exists — restarting the service is the only option. Production deployments with Vault/AWS-managed rotating credentials need this.

## Scope

### In Scope
- `SecretsRotationScheduler`: background `asyncio.Task` (ThreatIntelScheduler pattern) re-resolving credentials on configurable interval
- Pool hot-swap: `reload_url()` (Redis variants) and `reload_dsn()` (PGPool) — atomic client swap, zero dropped connections
- `SecretsRotationConfig`: `enabled`, `interval_seconds`, `targets`, `rotate_on_startup`, `fail_closed`
- Events: `SECRET_ROTATING`, `SECRET_ROTATED`, `SECRET_ROTATION_FAILED` via SecurityEventBus
- Shield lifecycle wiring, admin endpoints (`POST /admin/secrets/rotate`, `GET /admin/secrets/status`), CLI (`araxys secrets rotate|status`)

### Out of Scope
- Password generation + write-back to Vault/AWS (v0.15)
- Lease-based renewal, external cron coordinator, full disconnect/reconnect

## Capabilities

### New Capabilities
- `secret-rotation`: Core engine — scheduler, config, events, admin endpoints, CLI. Re-resolves creds via existing resolver chain and applies to pools.
- `pool-reload`: Hot-swap contract — `reload_url()`/`reload_dsn()` on `ConnectionPool` protocol. Redis pools generalize existing `_reconnect()`; PGPool uses close+recreate (sub-100ms, documented limitation).

### Modified Capabilities
- None

## Approach

**Graceful Pool Reload with Background Scheduler** — zero new dependencies, reuses proven patterns:

1. Scheduler: `asyncio.Task` loop with `start()`/`stop()`/`_sleep_with_cancel_check()`, per-target sub-tasks (matches ThreatIntelScheduler)
2. Resolve: call existing `ChainedResolver.resolve(name)` each interval
3. Hot-swap: if credential changed, `pool.reload_url(new_url)` — atomically swap client (PING before swap, lock-guarded)
4. Events: emit rotating → rotated (success) or rotation_failed (error); fail-soft default
5. PGPool limitation: close+recreate pool (sub-100ms drain, min_size pre-warming)

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `db_security/rotation.py` | New | Rotation scheduler |
| `db_security/manager.py` | Modified | Scheduler lifecycle, reload coordination |
| `db_security/pool.py` | Modified | `reload_url()` on all Redis pool variants |
| `db_security/pg_pool.py` | Modified | `reload_dsn()` on PGPool |
| `core/config.py` | Modified | `SecretsRotationConfig` model |
| `core/types.py` | Modified | 3 new `SecurityEventType` values |
| `core/exceptions.py` | Modified | `SecretRotationError` |
| `shield.py` | Modified | Start/stop rotation on boot/shutdown |
| `admin/router.py` | Modified | 2 new admin endpoints |
| `cli.py` | Modified | `secrets rotate`, `secrets status` |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| PGPool close+recreate drain window | Medium | min_size pre-warming, FastAPI retry, <100ms |
| Acquire during client swap race | Low | Guard flag + lock (same as `_reconnect()`) |
| Vault token expiry skips rotation silently | Low | Fail-soft default, `fail_closed` opt-in, warning event |
| Sentinel/Cluster mode-specific reload | Low | Generalize existing `_reconnect()`, not rewrite |

## Rollback Plan

1. `enabled=False` → scheduler never starts, zero impact
2. `reload_url()` is additive — acquire/reconnect paths untouched
3. Defaults to disabled — opt-in, no breaking change
4. Remove scheduler ref from Shield to fully revert

## Dependencies

None. `hvac` and `boto3` already optional deps.

## Success Criteria

- [ ] Pool reconnects with new credentials within one rotation interval
- [ ] Zero in-flight Redis connections dropped during reload (PING-then-swap)
- [ ] PGPool reload < 100ms with min_size pre-warming
- [ ] Events emitted on success (`SECRET_ROTATED`) and failure (`SECRET_ROTATION_FAILED`)
- [ ] CLI and admin endpoints functional for manual trigger and status inspection
- [ ] All existing pool tests pass; 100% branch coverage on rotation module
