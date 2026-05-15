"""Tests for the API keys module."""

import pytest

from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import InMemoryAPIKeyStorage
from araxys.core.exceptions import InvalidAPIKey
from araxys.core.types import Scope


@pytest.fixture
def storage() -> InMemoryAPIKeyStorage:
    return InMemoryAPIKeyStorage()


@pytest.fixture
def manager(storage: InMemoryAPIKeyStorage) -> APIKeyManager:
    return APIKeyManager(storage=storage)


class TestAPIKeyManager:
    async def test_create_key(self, manager: APIKeyManager) -> None:
        result = await manager.create_key(
            owner="test-user",
            scopes=[Scope.READ],
            label="Test key",
        )
        assert result.raw_key
        assert len(result.prefix) == 8
        assert result.owner == "test-user"
        assert Scope.READ in result.scopes

    async def test_verify_valid_key(self, manager: APIKeyManager) -> None:
        result = await manager.create_key(owner="user1", scopes=[Scope.READ])
        record = await manager.verify_key(result.raw_key)
        assert record.owner == "user1"

    async def test_verify_invalid_key(self, manager: APIKeyManager) -> None:
        with pytest.raises(InvalidAPIKey):
            await manager.verify_key("totally-fake-key-that-does-not-exist")

    async def test_verify_scope_enforcement(self, manager: APIKeyManager) -> None:
        result = await manager.create_key(owner="user1", scopes=[Scope.READ])

        # Should pass — has READ scope
        await manager.verify_key(result.raw_key, required_scopes=[Scope.READ])

        # Should fail — doesn't have ADMIN scope
        with pytest.raises(InvalidAPIKey, match="Missing required scopes"):
            await manager.verify_key(result.raw_key, required_scopes=[Scope.ADMIN])

    async def test_revoke_key(self, manager: APIKeyManager) -> None:
        result = await manager.create_key(owner="user1", scopes=[Scope.READ])

        success = await manager.revoke_key(result.prefix)
        assert success

        with pytest.raises(InvalidAPIKey):
            await manager.verify_key(result.raw_key)

    async def test_list_keys(self, manager: APIKeyManager) -> None:
        await manager.create_key(owner="user1", scopes=[Scope.READ])
        await manager.create_key(owner="user2", scopes=[Scope.WRITE])

        all_keys = await manager.list_keys()
        assert len(all_keys) == 2

        user1_keys = await manager.list_keys(owner="user1")
        assert len(user1_keys) == 1
        assert user1_keys[0].owner == "user1"

    async def test_create_key_with_expiration(self, manager: APIKeyManager) -> None:
        result = await manager.create_key(
            owner="user1", scopes=[Scope.READ], ttl_days=30
        )
        assert result.expires_at is not None
