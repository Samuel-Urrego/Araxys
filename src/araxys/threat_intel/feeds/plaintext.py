"""Plaintext feed fetcher — one IP/CIDR per line, ``#`` comments, blank lines skipped.

Used for Firehol, Spamhaus, Blocklist.de, and any feed that returns
a newline-delimited list of IPs or CIDR ranges.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from araxys.threat_intel.config import FEED_DEFAULTS
from araxys.threat_intel.feeds import FeedResult

if TYPE_CHECKING:
    from araxys.core.config import FeedConfig


class PlaintextFeedFetcher:
    """Feed fetcher for plaintext IP/CIDR list feeds.

    Parameters
    ----------
    name:
        Feed identifier (e.g. ``"firehol_level1"``). Used to look up
        the default URL from :data:`FEED_DEFAULTS` when no URL is
        specified in the :class:`FeedConfig`.
    """

    def __init__(self, name: str = "plaintext") -> None:
        self.name = name

    def _parse(self, feed_name: str, text: str) -> FeedResult:
        """Parse raw feed text into a :class:`FeedResult`.

        Strips ``#`` comments and blank lines.  Each remaining line
        is treated as an IP or CIDR.
        """
        ips: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            ips.append(stripped)
        return FeedResult(feed_name=feed_name, ips=ips)

    async def fetch(self, config: FeedConfig) -> FeedResult:
        """Fetch and parse the feed.

        Uses ``config.url`` when provided; otherwise falls back to
        the built-in URL from :data:`FEED_DEFAULTS` for the feed name.
        """
        url = config.url
        if url is None:
            defaults = FEED_DEFAULTS.get(self.name, {})
            url = defaults.get("url")
            if url is None or not isinstance(url, str):
                return FeedResult(
                    feed_name=self.name,
                    errors=[f"No URL configured for feed '{self.name}'"],
                )

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return FeedResult(
                        feed_name=self.name,
                        errors=[f"HTTP {response.status_code}"],
                    )
                return self._parse(self.name, response.text)
        except httpx.TimeoutException as exc:
            return FeedResult(
                feed_name=self.name,
                errors=[f"timeout: {exc}"],
            )
        except httpx.HTTPError as exc:
            return FeedResult(
                feed_name=self.name,
                errors=[str(exc)],
            )
