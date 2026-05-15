"""Shared test fixtures for Araxys."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys import AraxysConfig, AraxysShield


@pytest.fixture
def config() -> AraxysConfig:
    """AraxysConfig with all modules enabled for testing."""
    return AraxysConfig(
        secret_key="test-secret-key-must-be-32-chars!!",
        rate_limit={  # type: ignore
            "max_requests": 5,
            "window_seconds": 60,
            "ban_threshold": 3,
            "ban_duration_seconds": 10,
        },
        honeypot={"paths": ["/admin/config", "/.env"]},  # type: ignore
    )


@pytest.fixture
def app() -> FastAPI:
    """Clean FastAPI app for testing."""
    return FastAPI()


@pytest.fixture
def shield(app: FastAPI, config: AraxysConfig) -> AraxysShield:
    """AraxysShield with all modules registered."""
    return AraxysShield(app, config)


@pytest.fixture
async def client(app: FastAPI, shield: AraxysShield) -> AsyncClient:  # type: ignore
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
