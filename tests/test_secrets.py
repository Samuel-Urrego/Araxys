"""Tests for secret resolvers (v0.6 — async wrappers).

Tests follow strict TDD: written before implementation.

Task 1.2: Wrap blocking I/O in VaultResolver and AWSSecretsResolver
with asyncio.to_thread().
"""

from __future__ import annotations

from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestVaultResolverAsync:
    """VaultResolver.resolve() must use asyncio.to_thread()."""

    @pytest.fixture(autouse=True)
    def mock_hvac_module(self) -> Generator[None, None, None]:
        """Mock hvac module so VaultResolver.__init__ doesn't fail."""
        with patch.dict("sys.modules", {"hvac": MagicMock()}):
            yield

    @pytest.fixture
    def mock_hvac(self) -> MagicMock:
        """Mock hvac client."""
        client = MagicMock()
        client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"REDIS_URL": "redis://vault:6379"}},
        }
        return client

    async def test_resolve_wraps_in_to_thread(self, mock_hvac: MagicMock) -> None:
        """VaultResolver.resolve() wraps the sync call in to_thread()."""
        with patch("araxys.db_security.secrets.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = AsyncMock(
                return_value={"data": {"data": {"REDIS_URL": "redis://vault:6379"}}}
            )

            from araxys.db_security.secrets import VaultResolver

            resolver = VaultResolver(
                url="http://vault:8200",
                token="test-token",
                mount_path="araxys",
            )
            # Replace the hvac client with our mock
            resolver._client = mock_hvac

            result = await resolver.resolve("REDIS_URL")

            mock_asyncio.to_thread.assert_awaited_once()
            call_args = mock_asyncio.to_thread.await_args
            assert call_args is not None
            # First positional arg to to_thread is the client method
            assert call_args[0][0] == mock_hvac.secrets.kv.v2.read_secret_version
            assert result == "redis://vault:6379"

    async def test_resolve_exception_returns_none(
        self, mock_hvac: MagicMock
    ) -> None:
        """Exception in the thread must return None (fail-soft preserved)."""
        with patch("araxys.db_security.secrets.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = AsyncMock(
                side_effect=ConnectionError("Vault down")
            )

            from araxys.db_security.secrets import VaultResolver

            resolver = VaultResolver(
                url="http://vault:8200",
                token="test-token",
                mount_path="araxys",
            )
            resolver._client = mock_hvac

            result = await resolver.resolve("REDIS_URL")
            assert result is None


class TestAWSSecretsResolverAsync:
    """AWSSecretsResolver.resolve() must use asyncio.to_thread()."""

    @pytest.fixture(autouse=True)
    def mock_boto3_module(self) -> Generator[None, None, None]:
        """Mock boto3 module so AWSSecretsResolver.__init__ doesn't fail."""
        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            yield

    @pytest.fixture
    def mock_boto3_client(self) -> MagicMock:
        """Mock boto3 secretsmanager client."""
        client = MagicMock()
        client.get_secret_value.return_value = {
            "SecretString": "redis://aws:6379",
        }
        return client

    async def test_resolve_wraps_in_to_thread(
        self, mock_boto3_client: MagicMock
    ) -> None:
        """AWSSecretsResolver.resolve() must call asyncio.to_thread."""
        with patch("araxys.db_security.secrets.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = AsyncMock(
                return_value={"SecretString": "redis://aws:6379"}
            )

            from araxys.db_security.secrets import AWSSecretsResolver

            resolver = AWSSecretsResolver(
                secret_prefix="araxys/",
                region_name="us-east-1",
            )
            resolver._client = mock_boto3_client

            result = await resolver.resolve("REDIS_URL")

            mock_asyncio.to_thread.assert_awaited_once()
            call_args = mock_asyncio.to_thread.await_args
            assert call_args is not None
            assert call_args[0][0] == mock_boto3_client.get_secret_value
            assert result == "redis://aws:6379"

    async def test_resolve_exception_returns_none(
        self, mock_boto3_client: MagicMock
    ) -> None:
        """Exception in thread returns None (fail-soft preserved)."""
        with patch("araxys.db_security.secrets.asyncio") as mock_asyncio:
            mock_asyncio.to_thread = AsyncMock(
                side_effect=Exception("AWS error")
            )

            from araxys.db_security.secrets import AWSSecretsResolver

            resolver = AWSSecretsResolver(
                secret_prefix="araxys/",
                region_name="us-east-1",
            )
            resolver._client = mock_boto3_client

            result = await resolver.resolve("REDIS_URL")
            assert result is None
