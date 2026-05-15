"""Tests for the CSRF Protection module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient

if TYPE_CHECKING:
    from araxys.core.config import CSRFConfig


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
        assert "SameSite=Strict" in cookie
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
        async def protected_route(  # type: ignore[misc]
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
            assert "SameSite=Strict" in set_cookie

    async def test_set_csrf_cookie_insecure(self) -> None:
        """set_csrf_cookie should omit Secure when config says so."""
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
