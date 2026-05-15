"""Tests for the secure headers middleware."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.config import SecureHeadersConfig
from araxys.headers.middleware import SecureHeadersMiddleware


@pytest.fixture
def headers_app() -> FastAPI:
    app = FastAPI()

    app.add_middleware(SecureHeadersMiddleware, config=SecureHeadersConfig())

    @app.get("/test")
    async def test_endpoint() -> None:
        return {"status": "ok"}  # type: ignore

    return app


@pytest.fixture
async def headers_client(headers_app: FastAPI) -> AsyncClient:  # type: ignore
    transport = ASGITransport(app=headers_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestSecureHeaders:
    async def test_hsts_header(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert "strict-transport-security" in response.headers
        hsts = response.headers["strict-transport-security"]
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    async def test_content_type_nosniff(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_frame_options(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-frame-options") == "DENY"

    async def test_xss_protection_disabled(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-xss-protection") == "0"

    async def test_referrer_policy(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert (
            response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        )

    async def test_csp_not_set_by_default(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert "content-security-policy" not in response.headers

    async def test_custom_csp(self) -> None:
        app = FastAPI()
        config = SecureHeadersConfig(content_security_policy="default-src 'self'")
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def test_endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            assert (
                response.headers.get("content-security-policy") == "default-src 'self'"
            )
