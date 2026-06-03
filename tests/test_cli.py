from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from araxys.cli import app
from araxys.core.types import Scope

runner = CliRunner()

@pytest.fixture
def mock_manager() -> Generator[Any]:
    with patch("araxys.cli.get_manager") as mock:
        manager = MagicMock()
        manager.create_key = AsyncMock()
        manager.list_keys = AsyncMock()
        manager.revoke_key = AsyncMock()
        mock.return_value = manager
        yield manager

def test_cli_create_key(mock_manager: Any) -> None:
    mock_manager.create_key.return_value = MagicMock(
        raw_key="test_raw_key",
        prefix="testpref",
        expires_at=None
    )
    
    result = runner.invoke(app, ["keys", "create", "--owner", "test-user"])
    
    assert result.exit_code == 0
    assert "API Key successfully created for test-user" in result.stdout
    assert "test_raw_key" in result.stdout
    assert "testpref" in result.stdout

def test_cli_list_keys(mock_manager: Any) -> None:
    mock_manager.list_keys.return_value = [
        MagicMock(
            prefix="testpref",
            owner="test-user",
            label="test-label",
            scopes=[Scope.READ],
            expires_at=None,
            created_at=MagicMock()
        )
    ]
    
    result = runner.invoke(app, ["keys", "list"])
    
    assert result.exit_code == 0
    assert "testpref" in result.stdout
    assert "test-user" in result.stdout
    assert "read" in result.stdout

def test_cli_revoke_key(mock_manager: Any) -> None:
    mock_manager.revoke_key.return_value = True
    
    result = runner.invoke(app, ["keys", "revoke", "testpref"])
    
    assert result.exit_code == 0
    assert "Key testpref has been revoked" in result.stdout

def test_cli_revoke_key_not_found(mock_manager: Any) -> None:
    mock_manager.revoke_key.return_value = False
    
    result = runner.invoke(app, ["keys", "revoke", "nonexistent"])
    
    assert result.exit_code == 0
    assert "Key nonexistent not found" in result.stdout


# ── v0.14 — Secrets Rotation CLI Commands ───────────────────────────────────


class MockResponse:
    """Mock httpx.Response for CLI tests."""
    def __init__(self, status_code: int, json_data: dict[str, Any]) -> None:
        self.status_code = status_code
        self._json = json_data

    def json(self) -> dict[str, Any]:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture
def mock_httpx_client() -> Generator[MagicMock, None, None]:
    """Mock httpx.AsyncClient for CLI HTTP requests."""
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client
        yield mock_client


def test_secrets_rotate_all_targets(
    mock_httpx_client: MagicMock, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """araxys secrets rotate triggers rotation for all configured targets."""
    monkeypatch.setenv("ARAXYS_API_KEY", "sk-test-admin-key")
    monkeypatch.setenv("ARAXYS_BASE_URL", "http://localhost:8000")

    mock_httpx_client.post = AsyncMock(return_value=MockResponse(200, {
        "status": "completed",
        "results": {"redis": "ok", "postgres": "ok"},
    }))

    result = runner.invoke(app, ["secrets", "rotate"])

    assert result.exit_code == 0
    assert "Rotation triggered successfully" in result.stdout


def test_secrets_rotate_specific_target(
    mock_httpx_client: MagicMock, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """araxys secrets rotate --target redis rotates only that target."""
    monkeypatch.setenv("ARAXYS_API_KEY", "sk-test-admin-key")
    monkeypatch.setenv("ARAXYS_BASE_URL", "http://localhost:8000")

    mock_httpx_client.post = AsyncMock(return_value=MockResponse(200, {
        "status": "completed",
        "results": {"redis": "ok"},
    }))

    result = runner.invoke(app, ["secrets", "rotate", "--target", "redis"])

    assert result.exit_code == 0
    assert "Rotation triggered successfully" in result.stdout


def test_secrets_status_output(
    mock_httpx_client: MagicMock, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """araxys secrets status shows a Rich table with rotation config and stats."""
    monkeypatch.setenv("ARAXYS_API_KEY", "sk-test-admin-key")
    monkeypatch.setenv("ARAXYS_BASE_URL", "http://localhost:8000")

    mock_httpx_client.get = AsyncMock(return_value=MockResponse(200, {
        "enabled": True,
        "interval_seconds": 300,
        "targets": ["redis", "postgres"],
        "per_target": {
            "redis": {
                "last_success": 0.1, "last_error": None,
                "last_rotated": 1717500000.0, "rotations": 5, "failures": 0,
            },
            "postgres": {
                "last_success": None, "last_error": 2.5,
                "last_rotated": None, "rotations": 0, "failures": 1,
            },
        },
    }))

    result = runner.invoke(app, ["secrets", "status"])

    assert result.exit_code == 0
    # Verify key data appears in output
    assert "Enabled" in result.stdout
    assert "300" in result.stdout
    assert "redis" in result.stdout
    assert "postgres" in result.stdout
    assert "5" in result.stdout  # rotations count
    assert "1" in result.stdout  # failures count
