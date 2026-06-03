"""AWS WAF v2 client — lazy boto3, async IP set operations."""

from __future__ import annotations

import asyncio
from typing import Any


class WafClient:
    """Lazy-loaded boto3 WAFv2 client with semaphore-guarded async calls.

    Parameters
    ----------
    region_name:
        AWS region for the WAFv2 client (default ``"us-east-1"``).
    """

    def __init__(self, region_name: str = "us-east-1") -> None:
        try:
            import boto3  # noqa: F401
        except ImportError:
            raise ImportError(
                "boto3 not installed. Install with: pip install araxys[aws_waf]"
            ) from None

        self._region = region_name
        self._client: Any = boto3.client("wafv2", region_name=region_name)
        self._semaphore = asyncio.Semaphore(1)

    # ------------------------------------------------------------------
    # read
    # ------------------------------------------------------------------

    async def get_ip_set(
        self,
        ip_set_id: str,
        ip_set_name: str,
        scope: str = "REGIONAL",
    ) -> dict[str, Any]:
        """Fetch an IP set by ID and name.

        Uses :func:`asyncio.to_thread` to keep the event loop free.
        """
        async with self._semaphore:
            return await asyncio.to_thread(
                self._client.get_ip_set,
                Name=ip_set_name,
                Id=ip_set_id,
                Scope=scope,
            )

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------

    async def update_ip_set(
        self,
        ip_set_id: str,
        ip_set_name: str,
        ip_addresses: list[str],
        lock_token: str,
        scope: str = "REGIONAL",
    ) -> dict[str, Any]:
        """Update addresses on an existing IP set (optimistic locking).

        Uses :func:`asyncio.to_thread` to keep the event loop free.
        """
        async with self._semaphore:
            return await asyncio.to_thread(
                self._client.update_ip_set,
                Name=ip_set_name,
                Id=ip_set_id,
                Scope=scope,
                LockToken=lock_token,
                Addresses=ip_addresses,
            )

    # ------------------------------------------------------------------
    # convenience: create
    # ------------------------------------------------------------------

    async def create_ip_set(
        self,
        name: str,
        scope: str = "REGIONAL",
        ip_addresses: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new IP set (optionally with initial addresses).

        Uses :func:`asyncio.to_thread` to keep the event loop free.
        """
        addrs: list[str] = ip_addresses if ip_addresses is not None else []

        async with self._semaphore:
            return await asyncio.to_thread(
                self._client.create_ip_set,
                Name=name,
                Scope=scope,
                IPAddressVersion="IPV4",
                Addresses=addrs,
            )
