"""Tests for the CSRF Protection module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient

if TYPE_CHECKING:
    from araxys.core.config import CSRFConfig


# ── CSRFConfig Tests ──────────────────────────────────────────────────────


class TestCSRFConfig:
    """Tests for the extended CSRFConfig — new fields and defaults."""

    def test_config_defaults(self) -> None:
        """New fields should have spec-defined defaults."""
        from araxys.core.config import CSRFConfig

        config = CSRFConfig()
        assert config.exclude_paths == ["/webhooks/*"]
        assert config.safe_methods == ["GET", "HEAD", "OPTIONS", "TRACE"]
        assert config.cookie_samesite == "strict"
        assert config.cookie_domain is None
        assert config.cookie_path == "/"
        assert config.cookie_httponly is False
        assert config.auto_refresh_cookie is True

    def test_config_custom_values(self) -> None:
        """Each new field should accept custom overrides."""
        from araxys.core.config import CSRFConfig

        config = CSRFConfig(
            exclude_paths=["/custom/*"],
            safe_methods=["GET"],
            cookie_samesite="lax",
            cookie_domain="example.com",
            cookie_path="/api",
            cookie_httponly=True,
            auto_refresh_cookie=False,
        )
        assert config.exclude_paths == ["/custom/*"]
        assert config.safe_methods == ["GET"]
        assert config.cookie_samesite == "lax"
        assert config.cookie_domain == "example.com"
        assert config.cookie_path == "/api"
        assert config.cookie_httponly is True
        assert config.auto_refresh_cookie is False

    def test_config_backward_compat(self) -> None:
        """Empty CSRFConfig should still work (existing fields unaffected)."""
        from araxys.core.config import CSRFConfig

        config = CSRFConfig()
        assert config.enabled is False
        assert config.token_expiry_seconds == 3600
        assert config.cookie_name == "csrf_token"
        assert config.header_name == "X-CSRF-Token"
        assert config.secure_cookie is True

    def test_create_cookie_respects_path(self) -> None:
        """create_cookie should use config.cookie_path instead of hardcoded '/'."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig(cookie_path="/api")
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "Path=/api" in cookie

    def test_create_cookie_respects_samesite(self) -> None:
        """create_cookie should use config.cookie_samesite over hardcoded Strict."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig(cookie_samesite="lax")
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "SameSite=lax" in cookie
        assert "SameSite=Strict" not in cookie

    def test_create_cookie_respects_domain(self) -> None:
        """create_cookie should include Domain when config.cookie_domain is set."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig(cookie_domain="example.com")
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "Domain=example.com" in cookie

    def test_create_cookie_omits_domain_when_none(self) -> None:
        """create_cookie should omit Domain when config.cookie_domain is None."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig()
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "Domain=" not in cookie

    def test_create_cookie_respects_httponly(self) -> None:
        """create_cookie should use config.cookie_httponly over hardcoded False."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        # cookie_httponly=True
        config = CSRFConfig(cookie_httponly=True)
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "HttpOnly=True" in cookie
        assert "HttpOnly=False" not in cookie

    def test_create_cookie_default_httponly_false(self) -> None:
        """Default cookie_httponly=False should set HttpOnly=False."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig()
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "HttpOnly=False" in cookie


# ── CSRFHandler Tests ─────────────────────────────────────────────────────


class TestCSRFHandler:
    """Tests for CSRFHandler — token generation, validation, cookie creation."""

    def test_generate_token_produces_different_tokens(self) -> None:
        """generate_token should produce different tokens each call."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token1 = handler.generate_token()
        token2 = handler.generate_token()
        assert token1 != token2
        assert isinstance(token1, str)
        assert len(token1) > 20  # token_urlsafe(32) -> 43 chars

    def test_validate_token_matching_returns_true(self) -> None:
        """validate_token with matching tokens should return True."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token = handler.generate_token()
        assert handler.validate_token(token, token) is True

    def test_validate_token_mismatched_returns_false(self) -> None:
        """validate_token with mismatched tokens should return False."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token1 = handler.generate_token()
        token2 = handler.generate_token()
        assert handler.validate_token(token1, token2) is False

    def test_create_cookie_secure_format(self) -> None:
        """create_cookie returns proper Set-Cookie header value with Secure=True."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig(secure_cookie=True)
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert config.cookie_name in cookie
        assert token in cookie
        # HttpOnly=False means JS can read it (required for double-submit)
        assert "HttpOnly=False" in cookie
        assert "Secure" in cookie
        assert "SameSite=strict" in cookie
        assert "Path=/" in cookie

    def test_create_cookie_insecure_format(self) -> None:
        """create_cookie should omit Secure when secure_cookie is False."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        config = CSRFConfig(secure_cookie=False)
        token = handler.generate_token()
        cookie = handler.create_cookie(token, config)
        assert "Secure" not in cookie


# ── CSRF Dependency Tests ─────────────────────────────────────────────────


class _CSRFTestApp:
    """Helper to create FastAPI apps with CSRF-protected routes."""

    @staticmethod
    def make_app(config: CSRFConfig | None = None) -> FastAPI:
        from fastapi import Depends

        from araxys.core.config import CSRFConfig
        from araxys.csrf.dependencies import csrf_protected

        cfg = config or CSRFConfig()
        app = FastAPI()

        @app.post("/protected")
        async def protected_route(
            _: None = Depends(csrf_protected(cfg)),
        ) -> dict[str, str]:
            return {"message": "OK"}

        @app.get("/unprotected")
        async def unprotected_route() -> dict[str, str]:
            return {"message": "no csrf"}

        return app

    @staticmethod
    def make_login_app(config: CSRFConfig | None = None) -> FastAPI:
        from araxys.core.config import CSRFConfig
        from araxys.csrf.dependencies import set_csrf_cookie
        from araxys.csrf.tokens import CSRFHandler

        cfg = config or CSRFConfig()
        handler = CSRFHandler()
        app = FastAPI()

        @app.post("/login")
        async def login(response: Response) -> dict[str, str]:
            set_csrf_cookie(response, handler, cfg)
            return {"message": "logged in"}

        return app


class TestCSRFProtectedDependency:
    """Tests for the csrf_protected FastAPI dependency."""

    async def test_missing_header_returns_403(self) -> None:
        """When header token is missing, should return 403."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        config = CSRFConfig()
        handler = CSRFHandler()
        token = handler.generate_token()
        app = _CSRFTestApp.make_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/protected",
                headers={"Cookie": f"csrf_token={token}"},
            )
            assert response.status_code == 403
            detail = response.json().get("detail", "")
            assert "missing" in detail.lower()

    async def test_missing_cookie_returns_403(self) -> None:
        """When cookie token is missing, should return 403."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token = handler.generate_token()
        app = _CSRFTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/protected",
                headers={"X-CSRF-Token": token},
            )
            assert response.status_code == 403

    async def test_valid_tokens_passes(self) -> None:
        """When both header and cookie tokens match, should pass (200)."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        config = CSRFConfig()
        handler = CSRFHandler()
        token = handler.generate_token()
        app = _CSRFTestApp.make_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/protected",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            assert response.json() == {"message": "OK"}

    async def test_unprotected_get_passes_without_tokens(self) -> None:
        """GET route without CSRF dependency should pass without tokens."""
        app = _CSRFTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/unprotected")
            assert response.status_code == 200
            assert response.json() == {"message": "no csrf"}

    async def test_set_csrf_cookie_injects_set_cookie_header(self) -> None:
        """set_csrf_cookie should inject a Set-Cookie header."""
        from araxys.core.config import CSRFConfig

        config = CSRFConfig(secure_cookie=True)
        app = _CSRFTestApp.make_login_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/login")
            set_cookie = response.headers.get("set-cookie")
            assert set_cookie is not None
            assert "csrf_token=" in set_cookie
            assert "Secure" in set_cookie
            assert "SameSite=strict" in set_cookie

    async def test_set_csrf_cookie_insecure(self) -> None:
        from araxys.core.config import CSRFConfig

        config = CSRFConfig(secure_cookie=False)
        app = _CSRFTestApp.make_login_app(config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/login")
            set_cookie = response.headers.get("set-cookie")
            assert set_cookie is not None
            assert "csrf_token=" in set_cookie
            assert "Secure" not in set_cookie


# ── CSRFMiddleware Tests ──────────────────────────────────────────────────


class _CSRFMiddlewareTestApp:
    """Helper to create FastAPI apps with CSRFMiddleware."""

    @staticmethod
    def make_app(config: CSRFConfig | None = None) -> FastAPI:
        from araxys.core.config import CSRFConfig
        from araxys.csrf.middleware import CSRFMiddleware
        from araxys.csrf.tokens import CSRFHandler

        cfg = config or CSRFConfig()
        handler = CSRFHandler()
        app = FastAPI()

        # Register middleware
        app.add_middleware(CSRFMiddleware, config=cfg, handler=handler)

        @app.post("/transfer")
        async def transfer() -> dict[str, str]:
            return {"message": "transferred"}

        @app.get("/balance")
        async def balance() -> dict[str, str]:
            return {"message": "balance"}

        @app.post("/webhooks/stripe")
        async def webhook() -> dict[str, str]:
            return {"message": "webhook received"}

        return app


class TestCSRFMiddleware:
    """Tests for CSRFMiddleware — automatic CSRF validation."""

    async def test_safe_method_passes_without_token(self) -> None:
        """GET (safe method) should pass without any CSRF token."""
        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/balance")
            assert response.status_code == 200
            assert response.json() == {"message": "balance"}

    async def test_excluded_path_passes_without_token(self) -> None:
        """POST to excluded path (/webhooks/*) should pass without token."""
        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/webhooks/stripe")
            assert response.status_code == 200
            assert response.json() == {"message": "webhook received"}

    async def test_missing_token_returns_403(self) -> None:
        """POST without CSRF token should return 403."""
        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/transfer")
            assert response.status_code == 403
            body = response.json()
            assert body["error"] == "CSRF validation failed"
            assert "missing" in body["detail"].lower()

    async def test_valid_token_passes(self) -> None:
        """POST with valid header+cookie tokens should pass."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token = handler.generate_token()
        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/transfer",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            assert response.json() == {"message": "transferred"}

    async def test_token_mismatch_returns_403(self) -> None:
        """POST with mismatched header vs cookie tokens should return 403."""
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token1 = handler.generate_token()
        token2 = handler.generate_token()
        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/transfer",
                headers={
                    "X-CSRF-Token": token1,
                    "Cookie": f"csrf_token={token2}",
                },
            )
            assert response.status_code == 403
            body = response.json()
            assert body["error"] == "CSRF validation failed"
            assert "mismatch" in body["detail"].lower()

    async def test_expired_token_returns_403(self) -> None:
        """POST with expired token should return 403."""
        from araxys.csrf.tokens import _make_expiring_token

        app = _CSRFMiddlewareTestApp.make_app()
        transport = ASGITransport(app=app)

        # Generate a token that expired 1 hour ago
        token, _ = _make_expiring_token(expiry_seconds=-3600)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/transfer",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 403
            body = response.json()
            assert body["error"] == "CSRF validation failed"

    async def test_auto_refresh_sets_cookie_on_valid_post(self) -> None:
        """Valid POST with auto_refresh_cookie=True should get Set-Cookie."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token = handler.generate_token()
        config = CSRFConfig(auto_refresh_cookie=True)
        app = _CSRFMiddlewareTestApp.make_app(config=config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/transfer",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie")
            assert set_cookie is not None
            assert "csrf_token=" in set_cookie

    async def test_auto_refresh_disabled_omits_cookie(self) -> None:
        """Valid POST with auto_refresh_cookie=False should not Set-Cookie."""
        from araxys.core.config import CSRFConfig
        from araxys.csrf.tokens import CSRFHandler

        handler = CSRFHandler()
        token = handler.generate_token()
        config = CSRFConfig(auto_refresh_cookie=False)
        app = _CSRFMiddlewareTestApp.make_app(config=config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/transfer",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie")
            assert set_cookie is None

    async def test_event_emitted_on_failure(self) -> None:
        """CSRF validation failure should emit a SecurityEvent."""
        from unittest.mock import AsyncMock, MagicMock

        import araxys.csrf.middleware as _csrf_mw
        from araxys.core.types import SecurityEventType

        # Create a mock event bus and inject into module-level reference
        event_bus = MagicMock()
        event_bus.emit = AsyncMock()
        _csrf_mw._event_bus = event_bus
        try:
            app = _CSRFMiddlewareTestApp.make_app()
            transport = ASGITransport(app=app)

            base_url = "http://test"
            async with AsyncClient(transport=transport, base_url=base_url) as client:
                response = await client.post("/transfer")
                assert response.status_code == 403

            # Verify event was emitted
            event_bus.emit.assert_awaited_once()
            call_args = event_bus.emit.call_args[0][0]
            assert call_args.event_type == SecurityEventType.CSRF_VALIDATION_FAILED
            assert call_args.severity == "warning"
            assert "source_ip" in call_args.metadata
            assert "path" in call_args.metadata
            assert "detail" in call_args.metadata
        finally:
            _csrf_mw._event_bus = None


# ── Shield Integration Tests (E2E) ────────────────────────────────────────


class TestCSRFShieldIntegration:
    """Full integration tests: AraxysShield with CSRF enabled."""

    async def test_shield_registers_middleware_when_enabled(self) -> None:
        """CSRFMiddleware should be registered when csrf.enabled=True."""
        from araxys import AraxysConfig, AraxysShield

        config = AraxysConfig(
            secret_key="a" * 32,
            csrf={"enabled": True},
        )
        app = FastAPI()

        @app.post("/transfer")
        async def transfer() -> dict[str, str]:
            return {"message": "OK"}

        AraxysShield(app, config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # POST without token → 403
            response = await client.post("/transfer")
            assert response.status_code == 403
            body = response.json()
            assert body["error"] == "CSRF validation failed"

    async def test_shield_middleware_off_by_default(self) -> None:
        """CSRFMiddleware should NOT be registered when csrf is None."""
        from araxys import AraxysConfig, AraxysShield

        config = AraxysConfig(secret_key="a" * 32)  # no csrf config at all
        app = FastAPI()

        @app.post("/transfer")
        async def transfer() -> dict[str, str]:
            return {"message": "OK"}

        AraxysShield(app, config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # POST without token → should pass (no CSRF middleware)
            response = await client.post("/transfer")
            assert response.status_code == 200
            assert response.json() == {"message": "OK"}

    async def test_shield_skipped_when_enabled_false(self) -> None:
        """CSRFMiddleware should NOT be registered when csrf.enabled=False."""
        from araxys import AraxysConfig, AraxysShield

        config = AraxysConfig(
            secret_key="a" * 32,
            csrf={"enabled": False},
        )
        app = FastAPI()

        @app.post("/transfer")
        async def transfer() -> dict[str, str]:
            return {"message": "OK"}

        AraxysShield(app, config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/transfer")
            assert response.status_code == 200

    async def test_shield_backward_compat_with_depends(self) -> None:
        """Both CSRFMiddleware and Depends should work simultaneously."""
        from fastapi import Depends

        from araxys import AraxysConfig, AraxysShield
        from araxys.csrf.dependencies import csrf_protected, set_csrf_cookie
        from araxys.csrf.tokens import CSRFHandler

        config = AraxysConfig(
            secret_key="a" * 32,
            csrf={"enabled": True, "exclude_paths": ["/webhooks/*", "/login"]},
        )
        app = FastAPI()

        @app.post("/with-depends")
        async def with_depends(
            _: None = Depends(csrf_protected(config.csrf)),
        ) -> dict[str, str]:
            return {"message": "via depends"}

        @app.post("/middleware-only")
        async def middleware_only() -> dict[str, str]:
            return {"message": "via middleware"}

        @app.post("/login")
        async def login(response: Response) -> dict[str, str]:
            handler = CSRFHandler()
            set_csrf_cookie(response, handler, config.csrf)
            return {"message": "logged in"}

        AraxysShield(app, config)
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # First login to get a cookie
            login_resp = await client.post("/login")
            assert login_resp.status_code == 200
            csrf_cookie = login_resp.headers.get("set-cookie")
            assert csrf_cookie is not None

            # Extract the token from the set-cookie header
            token = csrf_cookie.split(";")[0].split("=", 1)[1]

            # Both Depends + middleware route should pass with valid token
            response = await client.post(
                "/with-depends",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            assert response.json() == {"message": "via depends"}

            # Middleware-only route should also pass with valid token
            response = await client.post(
                "/middleware-only",
                headers={
                    "X-CSRF-Token": token,
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 200
            assert response.json() == {"message": "via middleware"}

            # Both should reject invalid tokens
            response = await client.post(
                "/with-depends",
                headers={
                    "X-CSRF-Token": "invalid-token",
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 403

            response = await client.post(
                "/middleware-only",
                headers={
                    "X-CSRF-Token": "invalid-token",
                    "Cookie": f"csrf_token={token}",
                },
            )
            assert response.status_code == 403
