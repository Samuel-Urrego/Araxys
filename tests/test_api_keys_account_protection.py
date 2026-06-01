"""Tests for API key manager with account enumeration protection.

Tests that:
- APIKeyManager accepts optional AccountProtectionConfig
- verify_key() unifies error messages to "Invalid API key"
- simulate_hash_lookup runs when prefix not found + protection enabled
- Timing equalization works via fake hash + constant_time_compare
- Scope errors no longer enumerate missing scopes
- Backward compat when protection is disabled
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from araxys.account_protection.helpers import simulate_hash_lookup
from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import InMemoryAPIKeyStorage
from araxys.core.config import AccountProtectionConfig
from araxys.core.exceptions import InvalidAPIKey
from araxys.core.types import Scope


@pytest.fixture
def storage() -> InMemoryAPIKeyStorage:
    return InMemoryAPIKeyStorage()


@pytest.fixture
def manager(storage: InMemoryAPIKeyStorage) -> APIKeyManager:
    return APIKeyManager(storage=storage)


class TestAPIKeyManagerWithProtection:
    """APIKeyManager with AccountProtectionConfig enabled."""

    @pytest.fixture
    def protection_config(self) -> AccountProtectionConfig:
        return AccountProtectionConfig(
            enabled=True,
            fake_hash_work_factor=4,  # Small work factor for speed
        )

    @pytest.fixture
    def protected_manager(
        self, storage: InMemoryAPIKeyStorage, protection_config: AccountProtectionConfig
    ) -> APIKeyManager:
        return APIKeyManager(
            storage=storage,
            protection_config=protection_config,
        )

    async def test_accepts_protection_config(self, protected_manager: APIKeyManager) -> None:  # noqa: E501
        """APIKeyManager should accept protection_config without error."""
        assert protected_manager is not None

    # ── Unified error messages ──

    async def test_unknown_prefix_returns_generic_message(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Unknown prefix should raise 'Invalid API key'."""
        with pytest.raises(InvalidAPIKey) as exc_info:
            await protected_manager.verify_key("sk_unknown_prefix_that_does_not_exist_!!!!")  # noqa: E501
        assert str(exc_info.value) == "Invalid API key"
        assert exc_info.value.reason == "Invalid API key"

    async def test_hash_mismatch_returns_generic_message(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Hash mismatch should raise 'Invalid API key'."""
        result = await protected_manager.create_key(owner="user1")
        # Replace the hash in storage to force mismatch
        record = (await protected_manager._storage.list_keys())[0]
        record.key_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # noqa: E501
        await protected_manager._storage.store(record)

        with pytest.raises(InvalidAPIKey) as exc_info:
            await protected_manager.verify_key(result.raw_key + "tampered")
        assert str(exc_info.value) == "Invalid API key"

    async def test_expired_key_returns_generic_message(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Expired key should raise 'Invalid API key'."""

        result = await protected_manager.create_key(
            owner="user1", ttl_days=-1  # Already expired
        )
        with pytest.raises(InvalidAPIKey) as exc_info:
            await protected_manager.verify_key(result.raw_key)
        assert str(exc_info.value) == "Invalid API key"

    async def test_scope_missing_no_enumeration(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Missing scope should not enumerate which scopes are missing."""
        result = await protected_manager.create_key(
            owner="user1", scopes=[Scope.READ],
        )
        with pytest.raises(InvalidAPIKey) as exc_info:
            await protected_manager.verify_key(
                result.raw_key, required_scopes=[Scope.ADMIN],
            )
        error_msg = str(exc_info.value)
        assert "ADMIN" not in error_msg
        assert "read" not in error_msg
        assert "Missing required scopes:" not in error_msg

    async def test_ip_restricted_keeps_specific_message(
        self, protected_manager: APIKeyManager
    ) -> None:
        """IP restriction should keep its specific message."""
        result = await protected_manager.create_key(
            owner="user1", scopes=[Scope.READ], allowed_ips=["192.168.1.0/24"],
        )
        with pytest.raises(InvalidAPIKey) as exc_info:
            await protected_manager.verify_key(
                result.raw_key, client_ip="10.0.0.1",
            )
        assert "IP" in str(exc_info.value)

    # ── Timing equalization ──

    async def test_missing_prefix_triggers_simulate_hash_lookup(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Missing prefix with protection should call simulate_hash_lookup."""
        with patch(
            "araxys.api_keys.manager.simulate_hash_lookup",
            wraps=simulate_hash_lookup,
        ) as mock_sim:
            with pytest.raises(InvalidAPIKey):
                await protected_manager.verify_key(
                    "sk_nonexistent_key_that_does_not_exist_!!!!"
                )
            mock_sim.assert_called_once()

    # ── Valid keys still work ──

    async def test_valid_key_still_works(
        self, protected_manager: APIKeyManager
    ) -> None:
        """Valid keys should still verify successfully."""
        result = await protected_manager.create_key(owner="user1", scopes=[Scope.READ])
        record = await protected_manager.verify_key(result.raw_key)
        assert record.owner == "user1"
        assert Scope.READ in record.scopes


class TestAPIKeyManagerNoProtection:
    """APIKeyManager without AccountProtectionConfig (backward compat)."""

    @pytest.fixture
    def no_protection_manager(self, storage: InMemoryAPIKeyStorage) -> APIKeyManager:
        return APIKeyManager(storage=storage)

    async def test_unknown_prefix_original_message(
        self, no_protection_manager: APIKeyManager
    ) -> None:
        """Without protection, unknown prefix should still raise."""
        with pytest.raises(InvalidAPIKey):
            await no_protection_manager.verify_key("sk_nonexistent")
        # Message should still be unified to "Invalid API key"
        with pytest.raises(InvalidAPIKey, match="Invalid API key"):
            await no_protection_manager.verify_key("sk_nonexistent")

    async def test_expired_key_original_message(
        self, no_protection_manager: APIKeyManager
    ) -> None:
        """Without protection, expired key should raise generic message too."""
        result = await no_protection_manager.create_key(
            owner="user1", ttl_days=-1,
        )
        with pytest.raises(InvalidAPIKey, match="Invalid API key"):
            await no_protection_manager.verify_key(result.raw_key)

    async def test_no_timing_simulation_without_protection(
        self, no_protection_manager: APIKeyManager
    ) -> None:
        """Without protection, missing prefix should NOT call simulate_hash_lookup."""
        with patch("araxys.api_keys.manager.simulate_hash_lookup") as mock_sim:
            with pytest.raises(InvalidAPIKey):
                await no_protection_manager.verify_key(
                    "sk_fast_missing_prefix_test_!!!!"
                )
            mock_sim.assert_not_called()
