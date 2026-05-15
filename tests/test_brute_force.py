"""Tests for the Brute Force Protection and Password Policy module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request  # noqa: TC002 — needed at runtime by FastAPI
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from araxys.brute_force.limiter import BruteForceBackend
    from araxys.core.config import BruteForceConfig


# ── InMemory Backend Tests ────────────────────────────────────────────────


class TestInMemoryBruteForceBackend:
    """Tests for InMemoryBruteForceBackend."""

    @pytest.fixture
    def backend(self) -> BruteForceBackend:
        from araxys.brute_force.limiter import InMemoryBruteForceBackend

        return InMemoryBruteForceBackend()

    async def test_record_attempt_increments_counter(
        self, backend: BruteForceBackend
    ) -> None:
        """record_attempt should increment the attempt counter."""
        count1 = await backend.record_attempt("testuser")
        assert count1 == 1
        count2 = await backend.record_attempt("testuser")
        assert count2 == 2

    async def test_record_attempt_separate_identifiers(
        self, backend: BruteForceBackend
    ) -> None:
        """record_attempt should track different identifiers separately."""
        await backend.record_attempt("user1")
        await backend.record_attempt("user1")
        await backend.record_attempt("user2")
        assert await backend.get_attempts("user1") == 2
        assert await backend.get_attempts("user2") == 1

    async def test_is_locked_returns_false_by_default(
        self, backend: BruteForceBackend
    ) -> None:
        """is_locked should return False when no lockout is set."""
        locked = await backend.is_locked("testuser")
        assert locked is False

    async def test_is_locked_returns_true_after_lockout(
        self, backend: BruteForceBackend
    ) -> None:
        """is_locked should return True after set_lockout."""
        await backend.set_lockout("testuser", 60)
        locked = await backend.is_locked("testuser")
        assert locked is True

    async def test_reset_clears_attempts_and_lockout(
        self, backend: BruteForceBackend
    ) -> None:
        """reset should clear attempts and lockout for an identifier."""
        await backend.record_attempt("testuser")
        await backend.record_attempt("testuser")
        await backend.set_lockout("testuser", 60)
        assert await backend.get_attempts("testuser") == 2
        assert await backend.is_locked("testuser") is True

        await backend.reset("testuser")
        assert await backend.get_attempts("testuser") == 0
        assert await backend.is_locked("testuser") is False

    async def test_get_attempts_returns_zero_for_unknown(
        self, backend: BruteForceBackend
    ) -> None:
        """get_attempts should return 0 for unknown identifier."""
        assert await backend.get_attempts("nobody") == 0

    async def test_lockout_expires_after_ttl(self) -> None:
        """is_locked should return False after lockout TTL expires."""
        import asyncio

        from araxys.brute_force.limiter import InMemoryBruteForceBackend

        backend = InMemoryBruteForceBackend()
        await backend.set_lockout("testuser", 1)  # 1 second
        assert await backend.is_locked("testuser") is True

        await asyncio.sleep(1.1)

        assert await backend.is_locked("testuser") is False


# ── BruteForceMiddleware Tests ────────────────────────────────────────────


class _BruteForceTestApp:
    """Helper to create FastAPI apps with BruteForceMiddleware."""

    @staticmethod
    def make_app(
        config: BruteForceConfig | None = None,
        backend: BruteForceBackend | None = None,
    ) -> FastAPI:
        from araxys.brute_force.limiter import (
            BruteForceMiddleware,
            InMemoryBruteForceBackend,
        )
        from araxys.core.config import BruteForceConfig

        cfg = config or BruteForceConfig()
        bk = backend or InMemoryBruteForceBackend()
        app = FastAPI()

        @app.post("/login", response_model=None)
        async def login(_request: Request) -> JSONResponse:
            return JSONResponse(status_code=401, content={"detail": "Invalid"})

        app.add_middleware(
            BruteForceMiddleware,
            config=cfg,
            backend=bk,
        )

        return app

    @staticmethod
    def make_conditional_app(
        config: BruteForceConfig | None = None,
        backend: BruteForceBackend | None = None,
    ) -> FastAPI:
        """App where login endpoint decides success based on request body."""
        from araxys.brute_force.limiter import (
            BruteForceMiddleware,
            InMemoryBruteForceBackend,
        )
        from araxys.core.config import BruteForceConfig

        cfg = config or BruteForceConfig()
        bk = backend or InMemoryBruteForceBackend()
        app = FastAPI()

        @app.post("/login", response_model=None)
        async def login(_request: Request) -> JSONResponse | dict[str, str]:
            body = await _request.json()
            if body.get("password") == "correct":
                return {"message": "OK"}
            return JSONResponse(status_code=401, content={"detail": "Invalid"})

        app.add_middleware(
            BruteForceMiddleware,
            config=cfg,
            backend=bk,
        )

        return app


class TestBruteForceMiddleware:
    """Tests for BruteForceMiddleware."""

    async def test_allows_requests_under_threshold(self) -> None:
        """Middleware should allow requests when under max_attempts."""
        from araxys.core.config import BruteForceConfig

        config = BruteForceConfig(max_attempts=5, lockout_duration_seconds=60)
        app = _BruteForceTestApp.make_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/login", json={"username": "user"})
            assert response.status_code == 401  # Returns endpoint 401, not 423

    async def test_blocks_after_max_attempts(self) -> None:
        """Middleware should return 423 after max_attempts reached."""
        from araxys.core.config import BruteForceConfig

        config = BruteForceConfig(max_attempts=3, lockout_duration_seconds=60)
        app = _BruteForceTestApp.make_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Make max_attempts failed requests
            for _ in range(3):
                resp = await client.post("/login", json={"username": "lockuser"})
                assert resp.status_code == 401

            # Next attempt should be locked
            resp = await client.post("/login", json={"username": "lockuser"})
            assert resp.status_code == 423
            body = resp.json()
            assert "detail" in body
            assert "retry_after_seconds" in body

    async def test_successful_login_resets_counter(self) -> None:
        """Successful login should reset the attempt counter."""
        from araxys.brute_force.limiter import InMemoryBruteForceBackend
        from araxys.core.config import BruteForceConfig

        backend = InMemoryBruteForceBackend()
        config = BruteForceConfig(max_attempts=5, lockout_duration_seconds=60)
        app = _BruteForceTestApp.make_conditional_app(config, backend)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 3 failed attempts for the same user
            for _ in range(3):
                resp = await client.post(
                    "/login",
                    json={"username": "testuser", "password": "wrong"},
                )
                assert resp.status_code == 401

            assert await backend.get_attempts("testuser") == 3

            # Successful login
            resp = await client.post(
                "/login",
                json={"username": "testuser", "password": "correct"},
            )
            assert resp.status_code == 200

            # Counter should be reset
            assert await backend.get_attempts("testuser") == 0

    async def test_different_identifiers_tracked_separately(self) -> None:
        """Middleware should track different identifiers separately."""
        from araxys.core.config import BruteForceConfig

        config = BruteForceConfig(max_attempts=3, lockout_duration_seconds=60)
        app = _BruteForceTestApp.make_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Lock user1
            for _ in range(3):
                await client.post("/login", json={"username": "user1"})
            resp = await client.post("/login", json={"username": "user1"})
            assert resp.status_code == 423

            # user2 should still be allowed
            resp = await client.post("/login", json={"username": "user2"})
            assert resp.status_code == 401

    async def test_lockout_expires_after_ttl(self) -> None:
        """Lockout should auto-expire after lockout_duration_seconds."""
        import asyncio

        from araxys.brute_force.limiter import InMemoryBruteForceBackend
        from araxys.core.config import BruteForceConfig

        backend = InMemoryBruteForceBackend()
        config = BruteForceConfig(max_attempts=2, lockout_duration_seconds=1)
        app = _BruteForceTestApp.make_app(config, backend)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Lock the user
            for _ in range(2):
                await client.post("/login", json={"username": "ttluser"})
            resp = await client.post("/login", json={"username": "ttluser"})
            assert resp.status_code == 423

            # Wait for lockout to expire
            await asyncio.sleep(1.1)

            # Should be allowed again
            resp = await client.post("/login", json={"username": "ttluser"})
            assert resp.status_code == 401


# ── PasswordPolicy Tests ──────────────────────────────────────────────────


class TestPasswordPolicy:
    """Tests for PasswordPolicy validation."""

    def _make_policy(self, **kwargs: object) -> Any:
        from araxys.brute_force.password_policy import PasswordPolicyConfig

        config = PasswordPolicyConfig(**kwargs)  # type: ignore[arg-type]
        from araxys.brute_force.password_policy import PasswordPolicy

        return PasswordPolicy(config)

    def test_valid_password_returns_empty_list(self) -> None:
        """A password meeting all rules should return empty list."""
        policy = self._make_policy()
        errors = policy.validate("ValidP@ss1")
        assert errors == []

    def test_too_short_returns_error(self) -> None:
        """Password shorter than min_length should return error."""
        policy = self._make_policy()
        errors = policy.validate("Sh0rt!A")
        assert any("8" in e and "character" in e.lower() for e in errors)

    def test_missing_uppercase_returns_error(self) -> None:
        """Password without uppercase should return error."""
        policy = self._make_policy()
        errors = policy.validate("lowercase1!")
        assert any("uppercase" in e.lower() for e in errors)

    def test_missing_lowercase_returns_error(self) -> None:
        """Password without lowercase should return error."""
        policy = self._make_policy()
        errors = policy.validate("UPPERCASE1!")
        assert any("lowercase" in e.lower() for e in errors)

    def test_missing_digit_returns_error(self) -> None:
        """Password without digit should return error."""
        policy = self._make_policy()
        errors = policy.validate("NoDigitsA!")
        assert any("digit" in e.lower() for e in errors)

    def test_missing_special_returns_error(self) -> None:
        """Password without special char should return error."""
        policy = self._make_policy()
        errors = policy.validate("NoSpecial1A")
        assert any("special" in e.lower() for e in errors)

    def test_multiple_failures_returned_together(self) -> None:
        """Multiple failures should be returned in one list."""
        policy = self._make_policy()
        errors = policy.validate("short")
        assert len(errors) >= 3  # too short, missing uppercase, digit, special

    def test_too_long_returns_error(self) -> None:
        """Password longer than max_length should return error."""
        policy = self._make_policy(max_length=10)
        errors = policy.validate("ValidP@ss1Extra")
        assert any("128" in e or "10" in e for e in errors)

    def test_individual_rules_can_be_disabled(self) -> None:
        """When a rule is disabled, it should not be checked."""
        policy = self._make_policy(
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_special=False,
        )
        errors = policy.validate("alllower")
        # Only length rules apply
        assert all("uppercase" not in e.lower() for e in errors)
        assert all("lowercase" not in e.lower() for e in errors)
        assert all("digit" not in e.lower() for e in errors)
        assert all("special" not in e.lower() for e in errors)

    def test_empty_password_returns_errors(self) -> None:
        """Empty password should fail length validation."""
        policy = self._make_policy()
        errors = policy.validate("")
        assert len(errors) >= 1
