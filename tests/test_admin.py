"""Tests for the Admin API module."""

from __future__ import annotations


class TestAdminRouter:
    """Tests for create_admin_router."""

    def test_router_creation(self) -> None:
        """create_admin_router should return an APIRouter."""
        from fastapi import FastAPI

        from araxys.admin import create_admin_router
        from araxys.core.config import AraxysConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        shield = AraxysShield(app, config)
        router = create_admin_router(shield)
        app.include_router(router)

        assert router.prefix == "/admin"

    async def test_health_endpoint(self) -> None:
        """GET /admin/health should return module status."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.admin import create_admin_router
        from araxys.core.config import AraxysConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        shield = AraxysShield(app, config)
        app.include_router(create_admin_router(shield))
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert "rate_limit" in data["modules"]
            assert "jwt" in data["modules"]

    async def test_sessions_endpoint_requires_user_id(self) -> None:
        """GET /admin/sessions without user_id should return 400."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.admin import create_admin_router
        from araxys.core.config import AraxysConfig, SessionConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(
            secret_key="test-key-32-chars-long!!!!!!!!!!!!",
            session=SessionConfig(enabled=True),
        )
        shield = AraxysShield(app, config)
        app.include_router(create_admin_router(shield))
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/sessions")
            assert resp.status_code == 400

    async def test_api_keys_list(self) -> None:
        """GET /admin/api-keys should return key list."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.admin import create_admin_router
        from araxys.core.config import AraxysConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        shield = AraxysShield(app, config)
        app.include_router(create_admin_router(shield))
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/admin/api-keys")
            assert resp.status_code == 200
            data = resp.json()
            assert "keys" in data
            assert "count" in data

    async def test_missing_module_returns_404(self) -> None:
        """Endpoints should return 404 when module is disabled."""
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.admin import create_admin_router
        from araxys.core.config import AraxysConfig
        from araxys.shield import AraxysShield

        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        shield = AraxysShield(app, config)
        app.include_router(create_admin_router(shield))
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Session manager is disabled by default
            resp = await client.get("/admin/sessions?user_id=test")
            assert resp.status_code == 404
