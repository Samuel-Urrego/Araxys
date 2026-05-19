# Tasks: v0.6 — Database Security Enhancements + Gap Closure

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~509 (186 source + 323 tests) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1: Phase 1 (Tasks 1.1-1.4, ~209 lines) → PR 2: Phase 2 (Tasks 2.1-2.3, ~152 lines) → PR 3: Phase 3 (Task 3.1, ~148 lines) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Base Target |
|------|------|-----------|-------------|
| 1 | Phase 1: independent fixes (storage metadata, async resolvers, accessor, body scan) | PR 1 | main |
| 2 | Phase 2: RedisPool health/idle/acquire timeout enforcement | PR 2 | main or PR 1 branch |
| 3 | Phase 3: sqlparse-based SQL parser | PR 3 | main or PR 2 branch |

---

## Phase 1 — Independent Fixes (4 tasks)

### Task 1.1: Storage metadata serialization fix
- **Phase**: 1
- **Depends on**: none
- **Files**: `src/araxys/sessions/storage.py`, `tests/test_sessions.py`
- **Description**: Line 159: replace `str(metadata)` with `json.dumps(metadata, default=str)`. Add `ast.literal_eval` fallback in `get_session()` for backward compat with old single-quote format. `import ast` + ~5 lines.
- **Tests**: Round-trip with int/bool/nested dict metadata; empty metadata (None→{}); datetime in metadata (must not raise); old single-quote format loads via ast.literal_eval.
- **Est. lines**: 6 source + 50 test = 56
- **Verification**: `uv run pytest tests/test_sessions.py -v`

### Task 1.2: Async Vault/AWS secret resolvers
- **Phase**: 1
- **Depends on**: none
- **Files**: `src/araxys/db_security/secrets.py`, `tests/test_secrets.py`
- **Description**: Wrap sync I/O in `VaultResolver.resolve()` and `AWSSecretsResolver.resolve()` with `await asyncio.to_thread(...)`. Fail-soft exceptions preserved.
- **Tests**: Mock `asyncio.to_thread` to verify it's called with correct args for both resolvers; verify `Exception` → `None` preserved.
- **Est. lines**: 4 source + 45 test = 49
- **Verification**: `uv run pytest tests/test_secrets.py -v`

### Task 1.3: get_redis_client() accessor + shield cleanup
- **Phase**: 1
- **Depends on**: none
- **Files**: `src/araxys/db_security/pool.py`, `src/araxys/shield.py`, `tests/test_pool.py`
- **Description**: Add `get_redis_client() -> Redis` to `RedisPool`. In `shield.py` lines 374, 398: replace `pool._redis` with `pool.get_redis_client()`, drop `# type: ignore[attr-defined]`.
- **Tests**: Accessor returns `self._redist`; accessor after close returns closed client (no crash).
- **Est. lines**: 9 source + 20 test = 29
- **Verification**: `uv run pytest tests/test_pool.py -v && uv run pytest tests/test_shield_v3.py -v`

### Task 1.4: JSON body full scan for NoSQL/command/path-traversal
- **Phase**: 1
- **Depends on**: none
- **Files**: `src/araxys/sanitize/middleware.py`, `tests/test_sanitize.py`
- **Description**: After `sanitize_payload()` in `dispatch()`, walk sanitized dict/list leaf strings and call `scan_value()` for NoSQL/command/path-traversal checks. Return 400 on detection. Respect config flags.
- **Tests**: Integration tests: POST with `{"$where":"sleep(5000)"}` → 400; POST `{"; cat /etc/passwd":""}` → 400; POST with `{"../../etc/shadow":""}` → 400; all flags disabled → passes; combined SQLi+NoSQL payload.
- **Est. lines**: 15 source + 60 test = 75
- **Verification**: `uv run pytest tests/test_sanitize.py -v`

---

## Phase 2 — RedisPool Enforcement (depends on G6)

### Task 2.1: Health check interval wiring
- **Phase**: 2
- **Depends on**: Task 1.3 (G6)
- **Files**: `src/araxys/db_security/pool.py`, `src/araxys/db_security/manager.py`, `tests/test_pool.py`
- **Description**: Add `_last_active: float` and `_health_task` to `RedisPool.__init__()`. Create `_health_loop()` that PINGs every `health_check_interval_seconds`. Cancel in `close()`. In `manager.py`: pass `health_check_interval_seconds` from config to `RedisPool`.
- **Tests**: Health loop starts on init and calls `ping()`; `close()` cancels task (task done, no warning); loop failure logs but doesn't propagate.
- **Est. lines**: 26 source + 35 test = 61
- **Verification**: `uv run pytest tests/test_pool.py -v`

### Task 2.2: Idle timeout enforcement
- **Phase**: 2
- **Depends on**: Task 2.1 (G2 — needs `_last_active`)
- **Files**: `src/araxys/db_security/pool.py`, `tests/test_pool.py`
- **Description**: In `acquire()`, before returning connection, check `time.time() - self._last_active > idle_timeout_seconds`. If idle, run `await self._redis.ping()`. On success, reset timer. On failure, reconnect (raise ConnectionError). PING check uses existing `self._redis.ping()`.
- **Tests**: Mock `_last_active` to be old → verify `ping()` called; PING failure → `ConnectionError`; active connection skips PING; timer reset after successful PING.
- **Est. lines**: 18 source + 35 test = 53
- **Verification**: `uv run pytest tests/test_pool.py -v`

### Task 2.3: Acquire timeout enforcement
- **Phase**: 2
- **Depends on**: Task 2.2 (Item 4 — both modify `acquire()`)
- **Files**: `src/araxys/db_security/pool.py`, `tests/test_pool.py`
- **Description**: Wrap `acquire()` body in `asyncio.wait_for(body, timeout=self.acquire_timeout_seconds)`. On `TimeoutError`, raise `ConnectionError("Acquire timed out")`.
- **Tests**: Mock `asyncio.wait_for` to raise `TimeoutError` → verify `ConnectionError` raised; happy path with `wait_for` returning Redis client.
- **Est. lines**: 8 source + 30 test = 38
- **Verification**: `uv run pytest tests/test_pool.py -v`

---

## Phase 3 — SQL Parser (independent)

### Task 3.1: SqlInjectionAnalyzer with sqlparse
- **Phase**: 3
- **Depends on**: none (runs in parallel with Phase 1)
- **Files**: `src/araxys/sanitize/sqlparser.py` (create), `src/araxys/sanitize/filters.py` (modify), `pyproject.toml` (modify), `tests/test_sqlparser.py`
- **Description**: Create `sqlparser.py` with `SqlInjectionAnalyzer` class using `sqlparse` for tokenization. Detect stacked queries, UNION SELECT, tautologies, time-based patterns, SQL comments. Update `detect_sqli()` to try import `SqlInjectionAnalyzer` first, fall back to regex. Add optional dep `sqlparse>=0.5.0` as `araxys[sqlparse]` extra.
- **Tests**: Stacked query `"1; DROP TABLE users; --"` detected; tautology `"' OR '1'='1' --"` detected; time-based `"WAITFOR DELAY '0:0:5'"` detected; UNION SELECT detected; comment injection detected; clean input returns None; `ImportError` fallback to regex works.
- **Est. lines**: 93 source + 55 test = 148
- **Verification**: `uv run pytest tests/test_sqlparser.py -v && pip install -e ".[sqlparse]" && uv run pytest tests/test_sqlparser.py -v`

---

## Implementation Order

1. **Phase 1 first** (Tasks 1.1→1.4) — all independent, zero conflict risk
2. **Phase 2 second** (Tasks 2.1→2.2→2.3) — sequential due to shared `pool.py` modifications; G2 first (adds init fields), then idle check (uses them), then acquire timeout (wraps full method)
3. **Phase 3** (Task 3.1) — can run in parallel with either phase; fully independent

Total: 3 chained PRs recommended. **Decision needed before apply**: which chain strategy to use (stacked-to-main vs feature-branch-chain).
