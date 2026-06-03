"""Tests for the Admin API module."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.config import (
    AraxysConfig,
    SecretsRotationConfig,
    SessionConfig,
)
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


# ── v0.14 — Dynamic Secrets Rotation Admin Endpoints ────────────────────────


@pytest.fixture
async def rotation_admin_setup() -> tuple[FastAPI, str, Any]:
    """Create app with rotation admin router; returns (app, admin_key, shield).
    
    Creates a minimal shield, then manually attaches a mock SecretsRotationScheduler
    to enable the /admin/secrets endpoints without requiring real Redis.
    """

    app = FastAPI()
    config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
    from araxys.shield import AraxysShield
    shield = AraxysShield(app, config)

    # Manually attach a fake rotation scheduler
    from araxys.db_security.rotation import SecretsRotationScheduler

    mock_manager = MagicMock()
    mock_resolver = MagicMock()
    mock_config = SecretsRotationConfig(
        enabled=True,
        interval_seconds=60,
        targets=["redis", "postgres"],
    )
    scheduler = SecretsRotationScheduler(
        manager=mock_manager,
        resolver=mock_resolver,
        config=mock_config,
    )
    # Set mock stats for deterministic output
    scheduler._stats = {  # noqa: SLF001
        "redis": {
            "last_success": 0.1, "last_error": None,
            "last_rotated": 1717500000.0, "rotations": 3, "failures": 0,
        },
        "postgres": {
            "last_success": None, "last_error": 2.5,
            "last_rotated": None, "rotations": 0, "failures": 1,
        },
    }
    shield._rotation_scheduler = scheduler  # noqa: SLF001

    result = await shield.api_key_manager.create_key(
        owner="test-admin",
        scopes=[Scope.ADMIN],
        label="test",
        key_type="secret",
    )

    from araxys.admin import create_admin_router
    app.include_router(create_admin_router(shield))
    return (app, result.raw_key, shield)


class TestSecretsRotationAdmin:
    """Admin endpoints for dynamic secrets rotation."""

    async def test_secrets_status_returns_config_and_stats(
        self, rotation_admin_setup: tuple[FastAPI, str, Any],
    ) -> None:
        """GET /admin/secrets/status returns enabled, interval, targets, stats."""
        app, admin_key, shield = rotation_admin_setup
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/admin/secrets/status", headers={"X-API-Key": admin_key}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["enabled"] is True
            assert data["interval_seconds"] == 60
            assert data["targets"] == ["redis", "postgres"]
            assert data["per_target"]["redis"]["rotations"] == 3
            assert data["per_target"]["postgres"]["failures"] == 1

    async def test_secrets_rotate_manual_trigger(
        self, rotation_admin_setup: tuple[FastAPI, str, Any],
    ) -> None:
        """POST /admin/secrets/rotate triggers rotate_targets and returns results."""
        app, admin_key, shield = rotation_admin_setup
        transport = ASGITransport(app=app)

        # Patch rotate_targets to avoid actual rotation (needs Redis)
        async def mock_rotate(targets: list[str]) -> None:
            pass

        with patch.object(
            shield._rotation_scheduler, "rotate_targets",  # noqa: SLF001
            side_effect=mock_rotate,
        ):
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/admin/secrets/rotate",
                    json={"targets": ["redis"]},
                    headers={"X-API-Key": admin_key},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "completed"
                assert "redis" in data["results"]

    async def test_secrets_rotate_invalid_target(
        self, rotation_admin_setup: tuple[FastAPI, str, Any],
    ) -> None:
        """POST /admin/secrets/rotate returns error for unknown target."""
        app, admin_key, shield = rotation_admin_setup
        transport = ASGITransport(app=app)

        # Let the real rotate_targets run — it will fail on unknown target
        # Patch _rotate_one to avoid actual Redis connection
        async def mock_rotate_one(target: str) -> None:
            raise ValueError(f"Unknown target: {target}")

        with patch.object(
            shield._rotation_scheduler, "_rotate_one", side_effect=mock_rotate_one,  # noqa: SLF001
        ):
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                resp = await client.post(
                    "/admin/secrets/rotate",
                    json={"targets": ["unknown-target"]},
                    headers={"X-API-Key": admin_key},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "completed"
                assert "unknown-target" in data["results"]
                assert data["results"]["unknown-target"] == "error"

    async def test_secrets_endpoints_require_admin(self) -> None:
        """Secrets endpoints return 401/403 without valid admin credentials."""

        app = FastAPI()
        config = AraxysConfig(secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        from araxys.shield import AraxysShield
        shield = AraxysShield(app, config)

        # Manually attach a fake scheduler (no Redis needed)
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=MagicMock(),
            resolver=MagicMock(),
            config=SecretsRotationConfig(
                enabled=True, interval_seconds=60, targets=["redis"],
            ),
        )
        shield._rotation_scheduler = scheduler  # noqa: SLF001

        from araxys.admin import create_admin_router
        app.include_router(create_admin_router(shield))
        transport = ASGITransport(app=app)

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # No auth headers
            resp = await client.get("/admin/secrets/status")
            assert resp.status_code == 401  # noqa: S101

            resp = await client.post(
                "/admin/secrets/rotate", json={"targets": ["redis"]}
            )
            assert resp.status_code == 401  # noqa: S101
