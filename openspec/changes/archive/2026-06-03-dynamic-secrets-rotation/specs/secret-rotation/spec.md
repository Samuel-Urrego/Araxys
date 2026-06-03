# Secret Rotation Specification

> **New capability** — no existing spec to modify. This is the full spec for archive reference.
> See `openspec/specs/secret-rotation/spec.md` for the source of truth.

## Purpose

Dynamic credential rotation via background scheduler. Re-resolves secrets through the existing `ChainedResolver` chain and hot-swaps pool connections. Disabled by default; configurable interval, per-target control, fail-soft/fail-closed modes. Admin endpoints and CLI for manual control.

## ADDED Requirements

### Requirement: Rotation Configuration

The system MUST support `SecretsRotationConfig` gating rotation via `enabled: bool = False`. Configuration MUST expose: `interval_seconds`, `targets: list[str]`, `rotate_on_startup: bool`, and `fail_closed: bool`.

#### Scenario: Rotation disabled by default

- GIVEN no `rotation` config key
- WHEN the shield initializes
- THEN no scheduler task is created and no automatic rotation occurs

#### Scenario: Selective target configuration

- GIVEN `rotation.enabled=true` with targets `["database", "redis_cache"]`
- WHEN the scheduler runs
- THEN only `database` and `redis_cache` credentials are re-resolved; other secrets are ignored

### Requirement: Background Scheduler

The system MUST run rotation as an `asyncio.Task` loop matching the ThreatIntelScheduler pattern. It MUST support `start()` and `stop()` with cancellation. Each target MUST be processed in its own sub-task per interval. An async sleep with cancellation check MUST allow clean shutdown.

#### Scenario: Scheduler starts on shield init

- GIVEN `rotation.enabled=true` and `interval_seconds=3600`
- WHEN `AraxysShield.__init__()` runs
- THEN `asyncio.create_task()` launches the scheduler loop; `rotate_on_startup` triggers immediate first rotation if true

#### Scenario: Graceful shutdown

- GIVEN a running scheduler task
- WHEN `shield.shutdown()` is called
- THEN the in-flight rotation task is cancelled, awaited, and all resources are released

### Requirement: Credential Re-resolution

The system MUST call `ChainedResolver.resolve(target_name)` on each interval. If the resolved value differs from the current credential, rotation proceeds. If `fail_closed=true`, any resolver error MUST block the service; if `fail_closed=false` (default), the error MUST emit a warning event and continue.

#### Scenario: Credential unchanged — rotation skipped

- GIVEN database password resolved as `abc123` and current secret is also `abc123`
- WHEN the scheduler re-resolves
- THEN no pool reload is triggered; no rotation event is emitted

#### Scenario: Resolver error with fail-soft (default)

- GIVEN `fail_closed=false` and Vault returns HTTP 500 during re-resolution
- WHEN the scheduler re-resolves a target
- THEN `SECRET_ROTATION_FAILED` event is emitted with target name and error details; scheduler continues to next target

#### Scenario: Resolver error with fail-closed

- GIVEN `fail_closed=true` and Vault returns HTTP 500 during re-resolution
- WHEN the scheduler re-resolves a target
- THEN `SECRET_ROTATION_FAILED` event is emitted; the service enters a blocked state until manual intervention

### Requirement: Rotation Events

The system MUST emit `SECRET_ROTATING` before each target rotation, `SECRET_ROTATED` on success, and `SECRET_ROTATION_FAILED` on any error via `SecurityEventBus`. Each event MUST include target name, timestamp, and on failure the error message.

#### Scenario: Successful rotation event chain

- GIVEN database credential changes from `old` to `new` and pool reload succeeds
- WHEN rotation runs for `database`
- THEN `SECRET_ROTATING` is emitted before the reload, `SECRET_ROTATED` is emitted after success

#### Scenario: Failed rotation event

- GIVEN redis_cache credential re-resolution fails
- WHEN rotation runs for `redis_cache`
- THEN `SECRET_ROTATION_FAILED` is emitted with the target name and error details

### Requirement: Admin Endpoints

The system MUST expose `POST /admin/secrets/rotate` to trigger on-demand rotation for one or more targets. `GET /admin/secrets/status` MUST return config state, last rotation timestamps per target, and recent error history. Both endpoints MUST require admin authentication.

#### Scenario: Manual rotation via admin

- GIVEN a running shield with rotation scheduler
- WHEN `POST /admin/secrets/rotate {"targets": ["redis_cache"]}` is called
- THEN `redis_cache` credential is re-resolved and its pool reloaded immediately; the full event chain fires

#### Scenario: Status inspection

- GIVEN `database` was rotated successfully 10 minutes ago and `redis_cache` failed 5 minutes ago
- WHEN `GET /admin/secrets/status` is called
- THEN response includes `last_success` timestamp for `database` and `last_error` with message for `redis_cache`

### Requirement: CLI Commands

The system MUST support `araxys secrets rotate [--target NAME]` and `araxys secrets status`. `rotate` without `--target` MUST rotate all configured targets.

#### Scenario: CLI rotate all targets

- GIVEN rotation configured with targets `["database", "redis_cache"]`
- WHEN `araxys secrets rotate` is executed
- THEN both targets are re-resolved sequentially; status output is printed per target

#### Scenario: CLI status output

- GIVEN rotation has run at least once
- WHEN `araxys secrets status` is executed
- THEN a table displays each target's name, last rotation timestamp, and success/failure status
