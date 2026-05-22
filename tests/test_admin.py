"""Tests for the Admin API module."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.config import AraxysConfig, SessionConfig
from araxys.core.types import Scope


@pytest.fixture
async def admin_setup() -> tuple[FastAPI, str]:
    """Create a FastAPI app with admin router and return (app, admin_key)."""
    app = FastAPI()
    config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
    from araxys.shield import AraxysShield
    shield = AraxysShield(app, config)

    result = await shield.api_key_manager.create_key(
        owner="test-admin",
        scopes=[Scope.ADMIN],
        label="test",
        key_type="secret",
    )

    from araxys.admin import create_admin_router
    app.include_router(create_admin_router(shield))
    return (app, result.raw_key)


@pytest.fixture
async def admin_setup_sessions() -> tuple[FastAPI, str]:
    """Create a FastAPI app with sessions enabled and return (app, admin_key)."""
    app = FastAPI()
    config = AraxysConfig(
        secret_key="test-key-32-chars-long!!!!!!!!!!!!",
        session=SessionConfig(enabled=True),
    )
    from araxys.shield import AraxysShield
    shield = AraxysShield(app, config)

    result = await shield.api_key_manager.create_key(
        owner="test-admin",
        scopes=[Scope.ADMIN],
        label="test",
        key_type="secret",
    )

    from araxys.admin import create_admin_router
    app.include_router(create_admin_router(shield))
    return (app, result.raw_key)


class TestAdminRouter:
    """Tests for create_admin_router."""

    def test_router_creation(self) -> None:
        """create_admin_router should return an APIRouter."""
        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        from araxys.shield import AraxysShield
        shield = AraxysShield(app, config)

        from araxys.admin import create_admin_router
        router = create_admin_router(shield)
        app.include_router(router)

        assert router.prefix == "/admin"

    async def test_health_endpoint(self, admin_setup: tuple[FastAPI, str]) -> None:
        """GET /admin/health should return module status."""
        app, admin_key = admin_setup
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/admin/health", headers={"X-API-Key": admin_key}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "rate_limit" in data["modules"]
            assert "jwt" in data["modules"]

    async def test_sessions_endpoint_requires_user_id(
        self, admin_setup_sessions: tuple[FastAPI, str]
    ) -> None:
        """GET /admin/sessions without user_id should return 400."""
        app, admin_key = admin_setup_sessions
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/admin/sessions", headers={"X-API-Key": admin_key}
            )
            assert resp.status_code == 400

    async def test_api_keys_list(self, admin_setup: tuple[FastAPI, str]) -> None:
        """GET /admin/api-keys should return key list."""
        app, admin_key = admin_setup
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/admin/api-keys", headers={"X-API-Key": admin_key}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "keys" in data
            assert "count" in data

    async def test_missing_module_returns_404(
        self, admin_setup: tuple[FastAPI, str]
    ) -> None:
        """Endpoints should return 404 when module is disabled."""
        app, admin_key = admin_setup
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Session manager is disabled by default
            resp = await client.get(
                "/admin/sessions?user_id=test",
                headers={"X-API-Key": admin_key},
            )
            assert resp.status_code == 404
