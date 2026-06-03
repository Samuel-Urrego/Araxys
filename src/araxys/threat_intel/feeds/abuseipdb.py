"""AbuseIPDB feed fetcher — REST API v2.

Queries the AbuseIPDB blacklist endpoint and returns IPs with their
abuse confidence scores.
"""

from __future__ import annotations

import httpx

from araxys.core.config import FeedConfig
from araxys.threat_intel.feeds import FeedResult


class AbuseIPDBFeedFetcher:
    """Feed fetcher for the AbuseIPDB v2 blacklist API.

    Requires an ``api_key`` in the :class:`FeedConfig`.  The
    blacklist endpoint returns recently reported abusive IPs.
    """

    name = "abuseipdb"
    _DEFAULT_URL = "https://api.abuseipdb.com/api/v2/blacklist"

    async def fetch(self, config: FeedConfig) -> FeedResult:
        """Fetch the AbuseIPDB blacklist.

        Returns all IP addresses from the response, regardless of
        abuse confidence score.
        """
        if not config.api_key:
            return FeedResult(
                feed_name=self.name,
                errors=["api_key is required for AbuseIPDB"],
            )

        url = config.url or self._DEFAULT_URL

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={"Key": config.api_key},
                )
                if response.status_code != 200:
                    return FeedResult(
                        feed_name=self.name,
                        errors=[f"HTTP {response.status_code}"],
                    )
                data = response.json()
                ips = [
                    item["ipAddress"]
                    for item in data.get("data", [])
                ]
                return FeedResult(feed_name=self.name, ips=ips)
        except httpx.HTTPError as exc:
            return FeedResult(
                feed_name=self.name,
                errors=[str(exc)],
            )
