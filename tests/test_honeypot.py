"""Tests for the honeypot module."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys import AraxysConfig, AraxysShield


@pytest.fixture
def honeypot_app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/health")
    async def health():  # type: ignore
        return {"status": "ok"}

    return app


@pytest.fixture
def honeypot_shield(honeypot_app: FastAPI) -> AraxysShield:
    config = AraxysConfig(
        secret_key="test-secret-key-must-be-32-chars!!",
        honeypot={"paths": ["/admin/config", "/.env"], "ban_duration_seconds": 60},  # type: ignore
        rate_limit={"enabled": False},  # type: ignore
        sanitize={"enabled": False},  # type: ignore
        secure_headers={"enabled": False},  # type: ignore
    )
    return AraxysShield(honeypot_app, config)


@pytest.fixture
async def honeypot_client(  # type: ignore
    honeypot_app: FastAPI, honeypot_shield: AraxysShield
) -> AsyncClient:
    transport = ASGITransport(app=honeypot_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestHoneypot:
    async def test_normal_requests_pass_through(
        self, honeypot_client: AsyncClient
    ) -> None:
        response = await honeypot_client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    async def test_honeypot_returns_fake_response(
        self, honeypot_client: AsyncClient
    ) -> None:
        response = await honeypot_client.get("/admin/config")
        # Honeypot returns 200 to not alert the bot
        assert response.status_code == 200

    async def test_ip_banned_after_honeypot(self, honeypot_client: AsyncClient) -> None:
        # Trigger the honeypot
        await honeypot_client.get("/.env")

        # Now ALL requests from this IP should be blocked
        response = await honeypot_client.get("/api/health")
        assert response.status_code == 403
        assert response.json()["detail"] == "Access denied"
