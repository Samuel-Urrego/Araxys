"""End-to-end tests for Account Enumeration Prevention.

Full FastAPI app with AraxysShield — tests integration across all modules.

Covers:
- 4.1: API key with protection enabled returns same message for all failure modes
- 4.2: MFA returns generic "Invalid verification code" with protection enabled
- 4.3: Middleware normalizes timing on auth paths, skips non-auth paths
- 4.4: Enumeration detector fires audit event after threshold
- 4.5: Backward compat: default config preserves original behavior
- 4.6: Shield: correct middleware ordering via app.user_middleware
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from starlette.responses import JSONResponse

from araxys.account_protection.middleware import AccountProtectionMiddleware
from araxys.core.config import (
    AccountProtectionConfig,
    AraxysConfig,
    IPControlConfig,
)
from araxys.core.exceptions import InvalidAPIKey

# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def on_audit() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def enabled_config() -> AraxysConfig:
    """Config with account_protection enabled and API key manager."""
    return AraxysConfig(
        secret_key="test-secret-key-1234567890abcdef",
        account_protection=AccountProtectionConfig(
            enabled=True,
            fake_hash_work_factor=4,
            timing_jitter_ms=0,
            minimum_response_time_ms=50,
            enumeration_threshold=3,
            enumeration_window_seconds=60,
        ),
    )


@pytest.fixture
def disabled_config() -> AraxysConfig:
    """Config with account_protection disabled."""
    return AraxysConfig(
        secret_key="test-secret-key-1234567890abcdef",
        account_protection=AccountProtectionConfig(enabled=False),
    )


@pytest.fixture
def default_config() -> AraxysConfig:
    """Default config (account_protection=None) — backward compat."""
    return AraxysConfig(secret_key="test-secret-key-1234567890abcdef")


def _build_app(config: AraxysConfig, on_audit: Any = None) -> FastAPI:
    """Build a FastAPI app with AraxysShield and test auth endpoints."""
    from araxys.shield import AraxysShield

    app = FastAPI()

    # Override audit callback if provided
    if on_audit is not None:
        # We can't easily inject on_audit into shield without modifying it.
        # Instead, we'll add AccountProtectionMiddleware directly to test
        # enumeration detection.
        pass

    AraxysShield(app, config)

    # API key test endpoint
    @app.get("/data/read")
    async def read_data() -> dict[str, str]:
        return {"data": "sensitive"}

    # Auth endpoint that returns 401
    @app.get("/auth/login-fail")
    async def auth_login_fail() -> Any:
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid username or password"},
        )

    # Auth endpoint that returns 403
    @app.get("/auth/forbidden")
    async def auth_forbidden() -> Any:
        return JSONResponse(
            status_code=403,
            content={"detail": "Not enough permissions"},
        )

    # Non-protected endpoint
    @app.get("/public/health")
    async def public_health() -> dict[str, str]:
        return {"status": "ok"}

    # Success auth endpoint
    @app.get("/auth/me")
    async def auth_me() -> dict[str, str]:
        return {"user": "test", "detail": "Success"}

    return app


# ── 4.6: Middleware Order ─────────────────────────────────────────────────


class TestMiddlewareOrder:
    """Verify correct middleware ordering via shield."""

    def test_account_protection_position(self) -> None:
        """AccountProtectionMiddleware should be between honeypot and ip_access."""
        from araxys.shield import AraxysShield

        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(enabled=True),
            ip_control=IPControlConfig(
                enabled=True,
                mode="block",
                blocklist=["10.0.0.0/8"],
            ),
        )
        app = FastAPI()
        AraxysShield(app, config)

        names = [m.cls.__name__ for m in app.user_middleware]  # type: ignore[attr-defined]
        assert "AccountProtectionMiddleware" in names

        ap_idx = names.index("AccountProtectionMiddleware")
        honeypot_idx = names.index("HoneypotMiddleware")
        ip_access_idx = names.index("IPAccessMiddleware")

        # Starlette's add_middleware uses insert(0, ...) so user_middleware
        # is in REVERSE registration order: [0] = outermost, [-1] = innermost.
        # Registration order: Sanitize → Honeypot → AccountProtection → IPAccess → ...
        # user_middleware order: ... → IPAccess → AccountProtection → Honeypot → Sanitize  # noqa: E501
        # So AccountProtection should have index between IPAccess and Honeypot.
        assert ip_access_idx < ap_idx < honeypot_idx, (
            f"Expected ip_access({ip_access_idx}) < account_protection({ap_idx}) "
            f"< honeypot({honeypot_idx}), got {names}"
        )


# ── 4.1: API Key Unified Messages ─────────────────────────────────────────


class TestAPIKeyUnifiedMessages:
    """API key with protection enabled returns same message for all failures."""

    async def test_all_failure_modes_same_message(self) -> None:
        """Unknown prefix, wrong key, and expired key all return 'Invalid API key'."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(enabled=True),
        )
        # Use a separate API Key manager to test the protection
        from araxys.api_keys.manager import APIKeyManager
        from araxys.api_keys.storage import InMemoryAPIKeyStorage

        storage = InMemoryAPIKeyStorage()
        manager = APIKeyManager(
            storage=storage,
            protection_config=config.account_protection,
        )

        # Create a valid key then expire it

        result = await manager.create_key(owner="user1", scopes=[])
        valid_key = result.raw_key

        # 1. Unknown prefix
        with pytest.raises(InvalidAPIKey) as exc:
            await manager.verify_key("sk_nonexistent_key_that_does_not_exist_!!!")
        assert str(exc.value) == "Invalid API key"

        # 2. Wrong hash (tampered key)
        with pytest.raises(InvalidAPIKey) as exc:
            await manager.verify_key(valid_key + "tampered")
        assert str(exc.value) == "Invalid API key"

        # 3. Revoked key
        await manager.revoke_key(result.prefix)
        with pytest.raises(InvalidAPIKey) as exc:
            await manager.verify_key(valid_key)
        assert str(exc.value) == "Invalid API key"


# ── 4.2: MFA Generic Messages ────────────────────────────────────────────


class TestMFAGenericMessages:
    """MFA returns generic 'Invalid verification code' with protection enabled."""

    def test_mfa_code_generic_message(self) -> None:
        """verify_mfa_code should return generic message."""
        from unittest.mock import MagicMock

        import araxys.mfa.dependencies as mfa_deps
        from araxys.mfa.dependencies import verify_mfa_code

        config = AccountProtectionConfig(
            enabled=True,
            generic_verification_message="Invalid verification code",
        )
        mfa_deps._account_protection_config = config
        try:
            mock_manager = MagicMock()
            mock_manager.verify.return_value = False

            with pytest.raises(HTTPException) as exc:
                verify_mfa_code(mock_manager, "secret", "000000")
            assert exc.value.detail == "Invalid verification code"
        finally:
            mfa_deps._account_protection_config = None

    def test_recovery_code_generic_message(self) -> None:
        """verify_recovery_code should return generic message."""
        import araxys.mfa.dependencies as mfa_deps
        from araxys.mfa.dependencies import verify_recovery_code

        config = AccountProtectionConfig(
            enabled=True,
            generic_verification_message="Invalid verification code",
        )
        mfa_deps._account_protection_config = config
        try:
            with pytest.raises(HTTPException) as exc:
                verify_recovery_code("FAKE-CODE", ["hash1"])
            assert exc.value.detail == "Invalid verification code"
        finally:
            mfa_deps._account_protection_config = None


# ── 4.3: Timing Normalization ─────────────────────────────────────────────


class TestTimingNormalizationE2E:
    """Middleware normalizes timing on auth paths, skips non-auth paths."""

    async def test_auth_path_timing_padded(self) -> None:
        """Auth path response should take at least minimum_response_time_ms."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(
                enabled=True,
                minimum_response_time_ms=100,
                timing_jitter_ms=0,
            ),
        )
        app = _build_app(config)
        transport = ASGITransport(app=app)

        start = time.monotonic()
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/login-fail")
        elapsed_ms = (time.monotonic() - start) * 1000

        assert response.status_code == 401
        assert elapsed_ms >= 80  # Allow tolerance

    async def test_non_auth_path_no_padding(self) -> None:
        """Non-auth path should not get timing padding."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(
                enabled=True,
                minimum_response_time_ms=200,  # Large to make failure obvious
                timing_jitter_ms=0,
            ),
        )
        app = _build_app(config)
        transport = ASGITransport(app=app)

        start = time.monotonic()
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/public/health")
        elapsed_ms = (time.monotonic() - start) * 1000

        assert response.status_code == 200
        assert elapsed_ms < 150  # Should not be padded

    async def test_401_detail_normalized(self) -> None:
        """401 detail should be replaced with generic message."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(
                enabled=True,
                generic_unauthorized_message="Invalid credentials",
                timing_jitter_ms=0,
                minimum_response_time_ms=0,
            ),
        )
        app = _build_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/login-fail")

        assert response.status_code == 401
        body = response.json()
        assert body["detail"] == "Invalid credentials"

    async def test_200_response_unchanged(self) -> None:
        """200 responses should not be modified."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(
                enabled=True,
                generic_unauthorized_message="Invalid credentials",
            ),
        )
        app = _build_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/me")

        assert response.status_code == 200
        body = response.json()
        assert body["detail"] == "Success"


# ── 4.4: Enumeration Detection ────────────────────────────────────────────


class TestEnumerationDetectionE2E:
    """Enumeration detector fires after threshold."""

    async def test_detection_after_threshold(self) -> None:
        """Should detect enumeration after threshold exceeded."""

        on_audit = AsyncMock()

        config = AccountProtectionConfig(
            enabled=True,
            enumeration_threshold=3,
            enumeration_window_seconds=60,
        )
        app = FastAPI()

        @app.get("/auth/login-fail")
        async def fail() -> Any:
            return JSONResponse(status_code=401, content={"detail": "fail"})

        app.add_middleware(
            AccountProtectionMiddleware,
            config=config,
            on_audit=on_audit,
        )
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for _ in range(3):
                response = await client.get("/auth/login-fail")
                assert response.status_code == 401
            await asyncio.sleep(0.05)

        on_audit.assert_awaited_once()

    async def test_no_detection_below_threshold(self) -> None:
        """Should NOT detect before threshold is reached."""

        on_audit = AsyncMock()

        config = AccountProtectionConfig(
            enabled=True,
            enumeration_threshold=10,
            enumeration_window_seconds=60,
        )
        app = FastAPI()

        @app.get("/auth/login-fail")
        async def fail() -> Any:
            return JSONResponse(status_code=401, content={"detail": "fail"})

        app.add_middleware(
            AccountProtectionMiddleware,
            config=config,
            on_audit=on_audit,
        )
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            for _ in range(3):
                response = await client.get("/auth/login-fail")
                assert response.status_code == 401
            await asyncio.sleep(0.05)

        on_audit.assert_not_awaited()

    async def test_non_401_not_tracked(self) -> None:
        """200 responses should not be tracked as enumeration."""

        on_audit = AsyncMock()

        config = AccountProtectionConfig(
            enabled=True,
            enumeration_threshold=3,
        )
        app = FastAPI()

        @app.get("/auth/login")
        async def login() -> dict[str, str]:
            return {"detail": "ok"}

        @app.get("/auth/login-fail")
        async def fail() -> Any:
            return JSONResponse(status_code=401, content={"detail": "fail"})

        app.add_middleware(
            AccountProtectionMiddleware,
            config=config,
            on_audit=on_audit,
        )
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 10 non-401 responses should not trigger detection
            for _ in range(10):
                await client.get("/auth/login")
            # 1 more 401 should not hit threshold of 3
            await client.get("/auth/login-fail")
            await asyncio.sleep(0.05)

        on_audit.assert_not_awaited()


# ── 4.5: Backward Compat ──────────────────────────────────────────────────


class TestBackwardCompat:
    """Default config preserves original error messages and timing."""

    async def test_default_config_preserves_messages(self) -> None:
        """Default config (account_protection=None) should not normalize messages."""
        config = AraxysConfig(secret_key="test-secret-key-1234567890abcdef")
        assert config.account_protection is None

        app = _build_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/login-fail")

        assert response.status_code == 401
        body = response.json()
        assert body["detail"] == "Invalid username or password"  # Original

    async def test_disabled_config_preserves_messages(self) -> None:
        """Disabled config should not normalize messages."""
        config = AraxysConfig(
            secret_key="test-secret-key-1234567890abcdef",
            account_protection=AccountProtectionConfig(enabled=False),
        )

        app = _build_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/login-fail")

        assert response.status_code == 401
        body = response.json()
        assert body["detail"] == "Invalid username or password"  # Original

    async def test_default_config_does_not_normalize_timing(self) -> None:
        """Default config should not add timing padding."""
        config = AraxysConfig(secret_key="test-secret-key-1234567890abcdef")

        app = _build_app(config)
        transport = ASGITransport(app=app)

        start = time.monotonic()
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/auth/login-fail")
        elapsed_ms = (time.monotonic() - start) * 1000

        assert response.status_code == 401
        assert elapsed_ms < 150  # No padding — fast
