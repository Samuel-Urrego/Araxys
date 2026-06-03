"""FeedSource Protocol and FeedResult dataclass for Threat Intel Feeds."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from araxys.core.config import FeedConfig


@dataclass
class FeedResult:
    """Result of a feed fetch operation.

    Parameters
    ----------
    feed_name:
        The feed identifier (e.g. ``"firehol_level1"``).
    ips:
        Parsed IP addresses or CIDR ranges.
    fetched_at:
        UTC timestamp of when the fetch completed.
    errors:
        Non-fatal errors encountered during fetch (e.g. HTTP 503).
    """

    feed_name: str
    ips: list[str] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: list[str] = field(default_factory=list)


@runtime_checkable
class FeedSource(Protocol):
    """Protocol that all feed fetchers must satisfy.

    Implementations must expose a ``name`` attribute and an async
    ``fetch(config)`` method that returns a :class:`FeedResult`.
    """

    name: str

    async def fetch(self, config: FeedConfig) -> FeedResult:
        """Fetch and parse IPs from this feed.

        Parameters
        ----------
        config:
            Per-feed configuration (URL, API key, refresh interval, etc.).

        Returns
        -------
        FeedResult
            Parsed IPs, errors, and metadata.
        """
        ...
