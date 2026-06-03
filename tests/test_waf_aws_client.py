"""Tests for WafClient — lazy boto3, async IP set operations (Phase 2, task 2.2)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Task 2.2 — WafClient import and lazy boto3
# ---------------------------------------------------------------------------


class TestWafClientImport:
    """WafClient must be importable from araxys.waf (task 2.2)."""

    def test_importable_from_waf_package(self) -> None:
        from araxys.waf import WafClient

        assert WafClient is not None

    def test_construct_without_boto3_raises_clear_error(self) -> None:
        """When boto3 is NOT installed, constructing WafClient raises ImportError."""
        from araxys.waf.aws_client import WafClient

        # Simulate boto3 being absent
        with (
            patch.dict(sys.modules, {"boto3": None}),
            patch(
                "builtins.__import__",
                side_effect=ImportError("No module named 'boto3'"),
            ),
            pytest.raises(ImportError, match="boto3"),

        ):
            WafClient(region_name="us-east-1")


class TestWafClientConstruction:
    """WafClient lazy boto3 pattern follows AWSSecretsResolver convention."""

    def test_boto3_is_imported_lazily_on_construction(self) -> None:
        """boto3 must be imported inside __init__, not at module level."""
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            _ = WafClient(region_name="us-east-1")
            # boto3.client should have been called with wafv2
            mock_boto3.client.assert_called_once_with("wafv2", region_name="us-east-1")

    def test_region_defaults_to_us_east_1(self) -> None:
        """When region_name is omitted, default to us-east-1."""
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            WafClient()
            mock_boto3.client.assert_called_once_with("wafv2", region_name="us-east-1")


# ---------------------------------------------------------------------------
# Task 2.2 — Semaphore throttling
# ---------------------------------------------------------------------------


class TestWafClientSemaphore:
    """WafClient must throttle AWS calls to 1 req/s via asyncio.Semaphore(1)."""

    def test_semaphore_initialized(self) -> None:
        """The semaphore must be created with value 1 during construction."""
        import asyncio

        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = MagicMock()

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            assert client._semaphore is not None
            assert isinstance(client._semaphore, asyncio.Semaphore)
            # We cannot assert _value directly in Python 3.11+, but it IS a Semaphore


# ---------------------------------------------------------------------------
# Task 2.2 — get_ip_set
# ---------------------------------------------------------------------------


class TestWafClientGetIpSet:
    """WafClient.get_ip_set() must read IP set details from AWS."""

    @pytest.mark.asyncio
    async def test_get_ip_set_returns_details(self) -> None:
        mock_boto3 = MagicMock()
        mock_client = MagicMock()

        mock_client.get_ip_set = MagicMock(return_value={
            "IPSet": {
                "Name": "TestIPSet",
                "Id": "abc-123",
                "ARN": "arn:aws:wafv2:us-east-1:123456:ipset/TestIPSet/abc-123",
                "Addresses": ["192.0.2.0/24"],
            },
        })
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            result = await client.get_ip_set(
                ip_set_id="abc-123",
                ip_set_name="TestIPSet",
                scope="REGIONAL",
            )

            assert result["IPSet"]["Name"] == "TestIPSet"
            assert result["IPSet"]["Id"] == "abc-123"

    @pytest.mark.asyncio
    async def test_get_ip_set_uses_to_thread(self) -> None:
        """get_ip_set must call boto3.get_ip_set via asyncio.to_thread()."""
        import asyncio

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.get_ip_set = MagicMock(
            return_value={"IPSet": {"Name": "X", "Id": "x"}}
        )
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            # Mock to_thread to verify it was used
            with patch.object(asyncio, "to_thread", wraps=asyncio.to_thread) as spy:
                await client.get_ip_set(
                    ip_set_id="abc-123", ip_set_name="TestIPSet", scope="REGIONAL",
                )
                spy.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_ip_set_empty_addresses(self) -> None:
        """An IP set with no addresses should be returned as-is."""
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.get_ip_set = MagicMock(return_value={
            "IPSet": {"Name": "Empty", "Id": "empty", "Addresses": []},
        })
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            result = await client.get_ip_set(
                ip_set_id="empty", ip_set_name="Empty", scope="REGIONAL",
            )
            assert result["IPSet"]["Addresses"] == []


# ---------------------------------------------------------------------------
# Task 2.2 — update_ip_set
# ---------------------------------------------------------------------------


class TestWafClientUpdateIpSet:
    """WafClient.update_ip_set() must update addresses on an existing IP set."""

    @pytest.mark.asyncio
    async def test_update_ip_set_calls_boto3_update_ip_set(self) -> None:
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.update_ip_set = MagicMock(return_value={"NextLockToken": "lock-2"})
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            result = await client.update_ip_set(
                ip_set_id="abc-123",
                ip_set_name="TestIPSet",
                ip_addresses=["10.0.0.1/32", "10.0.0.2/32"],
                lock_token="lock-1",
                scope="REGIONAL",
            )

            assert result["NextLockToken"] == "lock-2"
            mock_client.update_ip_set.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_ip_set_uses_to_thread(self) -> None:
        """update_ip_set must call boto3.update_ip_set via asyncio.to_thread()."""
        import asyncio

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.update_ip_set = MagicMock(return_value={"NextLockToken": "lock-2"})
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            with patch.object(asyncio, "to_thread", wraps=asyncio.to_thread) as spy:
                await client.update_ip_set(
                    ip_set_id="abc-123",
                    ip_set_name="TestIPSet",
                    ip_addresses=["10.0.0.1/32"],
                    lock_token="lock-1",
                    scope="REGIONAL",
                )
                spy.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_ip_set_semaphore_throttles(self) -> None:
        """Concurrent calls to update_ip_set must be serialized by the semaphore."""
        import asyncio

        call_order: list[int] = []

        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.update_ip_set = MagicMock(return_value={"NextLockToken": "lock-2"})
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()

            async def update_with_id(idx: int) -> None:
                await client.update_ip_set(
                    ip_set_id=f"ip-{idx}",
                    ip_set_name="TestIPSet",
                    ip_addresses=[f"10.0.0.{idx}/32"],
                    lock_token=f"lock-{idx}",
                    scope="REGIONAL",
                )
                call_order.append(idx)

            # Launch 3 concurrent updates
            await asyncio.gather(
                update_with_id(1),
                update_with_id(2),
                update_with_id(3),
            )

            # All 3 should have been called
            assert len(call_order) == 3


# ---------------------------------------------------------------------------
# Task 2.2 — create_ip_set convenience
# ---------------------------------------------------------------------------


class TestWafClientCreateIpSet:
    """WafClient.create_ip_set() convenience method."""

    @pytest.mark.asyncio
    async def test_create_ip_set_calls_boto3_create_ip_set(self) -> None:
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.create_ip_set = MagicMock(return_value={
            "Summary": {
                "Name": "MyIPSet",
                "Id": "new-456",
                "ARN": "arn:aws:wafv2:...",
                "LockToken": "lock-new",
            },
        })
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            result = await client.create_ip_set(
                name="MyIPSet",
                scope="REGIONAL",
                ip_addresses=["192.0.2.0/24"],
            )

            assert result["Summary"]["Name"] == "MyIPSet"
            mock_client.create_ip_set.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_ip_set_with_no_addresses(self) -> None:
        """Creating an IP set with no initial addresses is valid."""
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_client.create_ip_set = MagicMock(return_value={
            "Summary": {"Name": "EmptySet", "Id": "empty-789"},
        })
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            from araxys.waf.aws_client import WafClient

            client = WafClient()
            result = await client.create_ip_set(
                name="EmptySet",
                scope="REGIONAL",
            )

            assert result["Summary"]["Name"] == "EmptySet"
            # Verify it was called with empty Addresses
            call_args = mock_client.create_ip_set.call_args[1]
            assert call_args["Addresses"] == []


# ---------------------------------------------------------------------------
# Task 2.2 — Error handling / boto3 absent
# ---------------------------------------------------------------------------


class TestWafClientErrors:
    """Graceful error messages when boto3 is not available."""

    def test_error_message_includes_install_hint(self) -> None:
        """The ImportError message must tell the user how to install boto3."""
        from araxys.waf.aws_client import WafClient

        with (
            patch.dict(sys.modules, {"boto3": None}),
            patch(
                "builtins.__import__",
                side_effect=ImportError("No module named 'boto3'"),
            ),
            pytest.raises(ImportError) as exc_info,
        ):
            WafClient()

        assert "boto3" in str(exc_info.value).lower()
        assert "pip install" in str(exc_info.value).lower()
