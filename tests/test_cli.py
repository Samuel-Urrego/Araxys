import pytest
from typer.testing import CliRunner
from araxys.cli import app
from unittest.mock import MagicMock, patch, AsyncMock
from araxys.api_keys.models import APIKeyResponse
from araxys.core.types import Scope

runner = CliRunner()

@pytest.fixture
def mock_manager():
    with patch("araxys.cli.get_manager") as mock:
        manager = MagicMock()
        manager.create_key = AsyncMock()
        manager.list_keys = AsyncMock()
        manager.revoke_key = AsyncMock()
        mock.return_value = manager
        yield manager

def test_cli_create_key(mock_manager):
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

def test_cli_list_keys(mock_manager):
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

def test_cli_revoke_key(mock_manager):
    mock_manager.revoke_key.return_value = True
    
    result = runner.invoke(app, ["keys", "revoke", "testpref"])
    
    assert result.exit_code == 0
    assert "Key testpref has been revoked" in result.stdout

def test_cli_revoke_key_not_found(mock_manager):
    mock_manager.revoke_key.return_value = False
    
    result = runner.invoke(app, ["keys", "revoke", "nonexistent"])
    
    assert result.exit_code == 0
    assert "Key nonexistent not found" in result.stdout
