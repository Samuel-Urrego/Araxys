# Pool Reload Specification

> **New capability** — no existing spec to modify. This is the full spec for archive reference.
> See `openspec/specs/pool-reload/spec.md` for the source of truth.

## Purpose

Hot-swap contract for connection pools receiving rotated credentials. Defines `reload_url()` for Redis-based pools and `reload_dsn()` for PGPool. Atomic client swap with zero dropped in-flight connections on Redis; close+recreate drain for PostgreSQL. Guard flag and lock prevent race conditions during acquire.

## ADDED Requirements

### Requirement: ConnectionPool Protocol — Reload Contract

The system MUST define a `reload_url(url: str) -> Awaitable[None]` method on the `ConnectionPool` protocol for Redis-based pools. The method MUST atomically swap the internal client while preserving in-flight connections and the acquire/reconnect path.

#### Scenario: Redis pool reloads URL without dropping connections

- GIVEN a Redis pool with 5 active connections and URL `redis://old:pass@host:6379/0`
- WHEN `pool.reload_url("redis://new:pass@host:6379/0")` is called
- THEN the new client connects with the new credentials; existing in-flight connections continue serving; no acquire errors occur

#### Scenario: Reload with unchanged URL is a no-op

- GIVEN a Redis pool currently using URL `redis://user:pass@host:6379/0`
- WHEN `pool.reload_url("redis://user:pass@host:6379/0")` is called
- THEN no client swap occurs; no connections are disrupted

### Requirement: PGPool DSN Reload

The system MUST define `reload_dsn(dsn: str) -> Awaitable[None]` on PGPool. Due to asyncpg pool limitations, this MUST close existing connections, create a new pool with the updated DSN, and pre-warm to `min_size`. The total drain window MUST be under 100ms under normal conditions.

#### Scenario: PGPool reload with pre-warming

- GIVEN a PGPool with `min_size=5` and current DSN
- WHEN `pool.reload_dsn(new_dsn)` is called
- THEN the existing pool is drained; a new pool is created with `min_size=5` pre-warmed connections; drain plus recreate completes in under 100ms

#### Scenario: PGPool reload with concurrent acquires

- GIVEN a PGPool undergoing reload
- WHEN an acquire request arrives mid-drain
- THEN a `PoolClosedError` or retryable error is raised; the caller retries via FastAPI retry middleware

### Requirement: Acquire Guard During Swap

The system MUST protect the client swap with a guard flag and async lock to prevent race conditions where an acquire occurs mid-swap. This pattern MUST generalize the existing `_reconnect()` lock on Redis pools.

#### Scenario: Acquire blocked during swap

- GIVEN a Redis pool executing `reload_url()` with the swap lock held
- WHEN another coroutine attempts `pool.acquire()`
- THEN acquire waits until the swap completes; it then acquires from the new client

#### Scenario: Concurrent reload requests serialized

- GIVEN two rotation targets both triggering `reload_url()` on the same pool
- WHEN both calls arrive simultaneously
- THEN they execute sequentially; only the last swap with differing credentials actually changes the client

### Requirement: Connection PING Before Swap

The system MUST PING the new DSN/URL before swapping the pool client to validate credentials. A failed PING MUST NOT swap the client and MUST raise `SecretRotationError`.

#### Scenario: Invalid credentials rejected before swap

- GIVEN a Redis pool and `reload_url()` called with a URL containing a wrong password
- WHEN the pre-swap PING fails
- THEN the existing client is preserved; `SecretRotationError` is raised; the pool continues serving with old credentials

#### Scenario: Valid credentials pass PING

- GIVEN a Redis pool and valid new credentials
- WHEN `reload_url()` performs the pre-swap PING
- THEN the PING succeeds; the client swap proceeds atomically
