"""AlienVault OTX feed fetcher — pulses API.

Queries the AlienVault OTX indicator export endpoint and extracts
IPv4 indicators.
"""

from __future__ import annotations

import httpx

from araxys.core.config import FeedConfig
from araxys.threat_intel.feeds import FeedResult


class AlienVaultFeedFetcher:
    """Feed fetcher for the AlienVault OTX pulses API.

    Requires an ``api_key`` in the :class:`FeedConfig`.  The export
    endpoint returns indicators of compromise; only ``IPv4`` type
    indicators are collected.
    """

    name = "alienvault_otx"
    _DEFAULT_URL = "https://otx.alienvault.com/api/v1/indicators/export"

    async def fetch(self, config: FeedConfig) -> FeedResult:
        """Fetch AlienVault OTX indicators.

        Filters results to ``IPv4`` type indicators only.  Domains,
        hashes, and other indicator types are skipped.
        """
        if not config.api_key:
            return FeedResult(
                feed_name=self.name,
                errors=["api_key is required for AlienVault OTX"],
            )

        url = config.url or self._DEFAULT_URL

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={"X-OTX-API-KEY": config.api_key},
                )
                if response.status_code != 200:
                    return FeedResult(
                        feed_name=self.name,
                        errors=[f"HTTP {response.status_code}"],
                    )
                data = response.json()
                ips = [
                    item["indicator"]
                    for item in data.get("results", [])
                    if item.get("type") == "IPv4"
                ]
                return FeedResult(feed_name=self.name, ips=ips)
        except httpx.HTTPError as exc:
            return FeedResult(
                feed_name=self.name,
                errors=[str(exc)],
            )
