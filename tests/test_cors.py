"""Tests for the CORS Policy Manager module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

if TYPE_CHECKING:
    from araxys.core.config import CORSConfig


# ── Helpers ──────────────────────────────────────────────────────────────


def _make_config(**kwargs: object) -> CORSConfig:
    """Create a CORSConfig with the given overrides."""
    from araxys.core.config import CORSConfig

    return CORSConfig(**kwargs)  # type: ignore[arg-type]


def _make_app(cors_config: CORSConfig) -> FastAPI:
    """Create a FastAPI app with CORS middleware applied."""
    from araxys.cors.middleware import CORSMiddleware

    app = FastAPI()

    @app.get("/hello")
    async def hello() -> dict[str, str]:
        return {"message": "Hello, World!"}

    app.add_middleware(CORSMiddleware, cors_config=cors_config)

    return app


# ── Tests ────────────────────────────────────────────────────────────────


class TestCORSMiddleware:
    """Tests for CORSMiddleware."""

    async def test_no_origin_passes_through(self) -> None:
        """Request without Origin header should pass through normally."""
        cfg = _make_config(allow_origins=["https://app.example.com"])
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/hello")
            assert response.status_code == 200
            assert response.json() == {"message": "Hello, World!"}

    async def test_origin_not_in_allowlist_returns_400(self) -> None:
        """Origin not in allowlist should return 400."""
        cfg = _make_config(allow_origins=["https://app.example.com"])
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://evil.com"}
            )
            assert response.status_code == 400
            assert response.json() == {"detail": "Origin not allowed"}

    async def test_wildcard_allows_any_origin(self) -> None:
        """Wildcard '*' should allow any origin and echo it."""
        cfg = _make_config(allow_origins=["*"], allow_methods=["GET", "OPTIONS"])
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://anywhere.com"}
            )
            assert response.status_code == 200
            assert response.headers.get("access-control-allow-origin") == "*"

    async def test_exact_origin_match_returns_cors_headers(self) -> None:
        """Exact origin match should return ACAO header with that origin."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://app.example.com"}
            )
            assert response.status_code == 200
            assert (
                response.headers.get("access-control-allow-origin")
                == "https://app.example.com"
            )

    async def test_preflight_returns_correct_headers(self) -> None:
        """OPTIONS preflight should return 200 with CORS headers."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.options(
                "/hello",
                headers={
                    "Origin": "https://app.example.com",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert response.status_code == 200
            assert (
                response.headers.get("access-control-allow-origin")
                == "https://app.example.com"
            )
            assert response.headers.get("access-control-allow-methods") is not None
            methods = response.headers["access-control-allow-methods"]
            assert "GET" in methods
            assert "POST" in methods
            assert response.headers.get("access-control-allow-headers") is not None
            assert response.headers.get("access-control-max-age") is not None

    async def test_allow_credentials_in_preflight(self) -> None:
        """When allow_credentials is True, preflight should include the header."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "OPTIONS"],
            allow_credentials=True,
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.options(
                "/hello",
                headers={
                    "Origin": "https://app.example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert response.status_code == 200
            assert response.headers.get("access-control-allow-credentials") == "true"

    async def test_allow_credentials_in_normal_response(self) -> None:
        """When allow_credentials is True, normal response should include the header."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "OPTIONS"],
            allow_credentials=True,
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://app.example.com"}
            )
            assert response.status_code == 200
            assert response.headers.get("access-control-allow-credentials") == "true"

    async def test_expose_headers_appear_in_normal_response(self) -> None:
        """configured expose_headers should appear in normal response."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "OPTIONS"],
            expose_headers=["X-Custom-Header", "X-Request-ID"],
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://app.example.com"}
            )
            assert response.status_code == 200
            expose = response.headers.get("access-control-expose-headers")
            assert expose is not None
            assert "X-Custom-Header" in expose
            assert "X-Request-ID" in expose

    async def test_vary_origin_header_present(self) -> None:
        """Vary: Origin header should be present in normal responses."""
        cfg = _make_config(
            allow_origins=["https://app.example.com"],
            allow_methods=["GET", "OPTIONS"],
        )
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://app.example.com"}
            )
            assert response.status_code == 200
            vary = response.headers.get("vary")
            assert vary is not None
            assert "Origin" in vary

    async def test_fail_closed_empty_allowlist(self) -> None:
        """Empty allowlist should deny all origins (fail-closed)."""
        cfg = _make_config()
        app = _make_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello", headers={"Origin": "https://app.example.com"}
            )
            assert response.status_code == 400
            assert response.json() == {"detail": "Origin not allowed"}
