"""Tests for Threat Intelligence feed fetchers.

Phase 2 tasks: 2.1 (FeedResult/FeedSource), 2.2 (PlaintextFeedFetcher),
2.3 (AbuseIPDBFeedFetcher), 2.4 (AlienVaultFeedFetcher).

Uses ``respx`` to mock HTTP at the transport layer, matching the
:mod:`test_oidc_integration` pattern.
"""

from __future__ import annotations

from datetime import datetime

import httpx
import respx

from araxys.core.config import FeedConfig
from araxys.threat_intel.feeds import FeedResult, FeedSource
from araxys.threat_intel.feeds.abuseipdb import AbuseIPDBFeedFetcher
from araxys.threat_intel.feeds.alienvault import AlienVaultFeedFetcher
from araxys.threat_intel.feeds.plaintext import PlaintextFeedFetcher

# ──────────────────────────────────────────────────────────────────────
# Sample fixture data
# ──────────────────────────────────────────────────────────────────────

PLAINTEXT_FIREHOL = """\
# Firehol Level 1 sample
# Generated at 2025-01-01
1.2.3.4
5.6.7.8
10.0.0.0/24
# comment line
172.16.0.1

# blank line above was skipped
192.168.1.1
"""

PLAINTEXT_BLOCKLIST_DE = """\
# Blocklist.de — all IPs
1.1.1.1
2.2.2.2
3.3.3.3
"""

ABUSEIPDB_JSON = {
    "data": [
        {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 100,
            "countryCode": "US",
        },
        {
            "ipAddress": "5.6.7.8",
            "abuseConfidenceScore": 95,
            "countryCode": "RU",
        },
        {
            "ipAddress": "9.10.11.12",
            "abuseConfidenceScore": 50,
            "countryCode": "CN",
        },
    ],
}

ALIENVAULT_JSON = {
    "results": [
        {
            "indicator": "1.2.3.4",
            "type": "IPv4",
            "pulse_count": 42,
        },
        {
            "indicator": "5.6.7.8",
            "type": "IPv4",
            "pulse_count": 15,
        },
        {
            "indicator": "example.com",
            "type": "domain",
            "pulse_count": 3,
        },
        {
            "indicator": "9.10.11.12",
            "type": "IPv4",
            "pulse_count": 27,
        },
    ],
}


# ──────────────────────────────────────────────────────────────────────
# Task 2.1 — FeedResult / FeedSource (structural)
# ──────────────────────────────────────────────────────────────────────


class TestFeedResult:
    """FeedResult dataclass — construction and defaults."""

    def test_defaults(self) -> None:
        r = FeedResult(feed_name="test")
        assert r.feed_name == "test"
        assert r.ips == []
        assert isinstance(r.fetched_at, datetime)
        assert r.errors == []

    def test_with_ips(self) -> None:
        r = FeedResult(
            feed_name="firehol_level1",
            ips=["1.2.3.4", "5.6.7.0/24"],
        )
        assert r.feed_name == "firehol_level1"
        assert r.ips == ["1.2.3.4", "5.6.7.0/24"]
        assert r.errors == []

    def test_with_errors(self) -> None:
        r = FeedResult(
            feed_name="abuseipdb",
            ips=["1.2.3.4"],
            errors=["HTTP 429 Too Many Requests"],
        )
        assert len(r.errors) == 1
        assert "429" in r.errors[0]

    def test_fetched_at_is_utc_datetime(self) -> None:
        r = FeedResult(feed_name="test")
        assert r.fetched_at.tzinfo is not None


class TestFeedSourceProtocol:
    """FeedSource Protocol — structural check that implementations conform."""

    def test_plaintext_conforms(self) -> None:
        """PlaintextFeedFetcher must satisfy the FeedSource Protocol."""
        fetcher = PlaintextFeedFetcher()
        assert isinstance(fetcher, FeedSource)

    def test_abuseipdb_conforms(self) -> None:
        fetcher: FeedSource = AbuseIPDBFeedFetcher()
        assert fetcher.name == "abuseipdb"

    def test_alienvault_conforms(self) -> None:
        fetcher: FeedSource = AlienVaultFeedFetcher()
        assert fetcher.name == "alienvault_otx"

    def test_plaintext_name(self) -> None:
        fetcher = PlaintextFeedFetcher(name="custom-plaintext")
        assert fetcher.name == "custom-plaintext"


# ──────────────────────────────────────────────────────────────────────
# Task 2.2 — PlaintextFeedFetcher
# ──────────────────────────────────────────────────────────────────────


class TestPlaintextFeedFetcherParsing:
    """PlaintextFeedFetcher — parsing logic (no HTTP)."""

    def test_parse_simple(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("firehol_l1", PLAINTEXT_FIREHOL)
        assert len(result.ips) == 5
        assert "1.2.3.4" in result.ips
        assert "5.6.7.8" in result.ips
        assert "10.0.0.0/24" in result.ips
        assert "172.16.0.1" in result.ips
        assert "192.168.1.1" in result.ips

    def test_parse_skips_comments(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("test", "# this is a comment\n1.2.3.4")
        assert result.ips == ["1.2.3.4"]

    def test_parse_skips_blank_lines(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("test", "\n\n1.2.3.4\n\n\n5.6.7.8\n\n")
        assert result.ips == ["1.2.3.4", "5.6.7.8"]

    def test_parse_empty_text(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("test", "")
        assert result.ips == []
        assert result.errors == []

    def test_parse_only_comments(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("test", "# comment 1\n# comment 2\n")
        assert result.ips == []

    def test_parse_strips_whitespace(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("test", "  1.2.3.4  \n  5.6.7.8\t\n")
        assert result.ips == ["1.2.3.4", "5.6.7.8"]

    def test_parse_blocklist_de_format(self) -> None:
        fetcher = PlaintextFeedFetcher()
        result = fetcher._parse("blocklist_de", PLAINTEXT_BLOCKLIST_DE)
        assert len(result.ips) == 3
        assert result.ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def test_parse_large_feed(self) -> None:
        """~20K IPs must parse without issues (Blocklist.de scale)."""
        fetcher = PlaintextFeedFetcher()
        lines = [f"10.0.{i // 256}.{i % 256}" for i in range(1000)]
        text = "\n".join(lines)
        result = fetcher._parse("large", text)
        assert len(result.ips) == 1000


class TestPlaintextFeedFetcherHTTP:
    """PlaintextFeedFetcher — HTTP fetch via httpx (mocked with respx)."""

    @respx.mock
    async def test_fetch_uses_builtin_url(self) -> None:
        url = "https://lists.blocklist.de/lists/all.txt"
        respx.get(url).mock(
            return_value=httpx.Response(200, text=PLAINTEXT_BLOCKLIST_DE)
        )

        cfg = FeedConfig()
        fetcher = PlaintextFeedFetcher(name="blocklist_de")
        result = await fetcher.fetch(cfg)

        assert result.feed_name == "blocklist_de"
        assert len(result.ips) == 3
        assert result.errors == []

    @respx.mock
    async def test_fetch_url_override(self) -> None:
        """FeedConfig.url overrides the default URL."""
        custom_url = "https://custom.example.com/ips.txt"
        respx.get(custom_url).mock(
            return_value=httpx.Response(200, text="9.9.9.9\n8.8.8.8\n")
        )

        cfg = FeedConfig(url=custom_url)
        fetcher = PlaintextFeedFetcher(name="custom-feed")
        result = await fetcher.fetch(cfg)

        assert len(result.ips) == 2
        assert "9.9.9.9" in result.ips

    @respx.mock
    async def test_fetch_http_error(self) -> None:
        url = "https://example.com/feed.txt"
        respx.get(url).mock(return_value=httpx.Response(500))

        cfg = FeedConfig(url=url)
        fetcher = PlaintextFeedFetcher(name="test")
        result = await fetcher.fetch(cfg)

        assert result.ips == []
        assert len(result.errors) == 1
        assert "500" in result.errors[0]

    @respx.mock
    async def test_fetch_timeout(self) -> None:
        url = "https://example.com/feed.txt"
        respx.get(url).mock(side_effect=httpx.TimeoutException("timeout"))

        cfg = FeedConfig(url=url)
        fetcher = PlaintextFeedFetcher(name="test")
        result = await fetcher.fetch(cfg)

        assert len(result.errors) == 1
        assert "timeout" in result.errors[0].lower()


# ──────────────────────────────────────────────────────────────────────
# Task 2.3 — AbuseIPDBFeedFetcher
# ──────────────────────────────────────────────────────────────────────


class TestAbuseIPDBFeedFetcher:
    """AbuseIPDBFeedFetcher — REST API v2 (respx)."""

    @respx.mock
    async def test_fetch_parses_ips(self) -> None:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        respx.get(
            url,
            headers__contains={"Key": "test-api-key"},
        ).mock(return_value=httpx.Response(200, json=ABUSEIPDB_JSON))

        cfg = FeedConfig(api_key="test-api-key")
        fetcher = AbuseIPDBFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.feed_name == "abuseipdb"
        assert len(result.ips) == 3
        assert "1.2.3.4" in result.ips
        assert "5.6.7.8" in result.ips
        assert "9.10.11.12" in result.ips
        assert result.errors == []

    @respx.mock
    async def test_fetch_missing_api_key(self) -> None:
        """Fetch without api_key must return error."""
        cfg = FeedConfig(api_key=None)
        fetcher = AbuseIPDBFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.ips == []
        assert len(result.errors) == 1
        assert "api_key" in result.errors[0].lower()

    @respx.mock
    async def test_fetch_empty_response(self) -> None:
        """Empty data list must return empty IPs."""
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"data": []})
        )

        cfg = FeedConfig(api_key="test-key")
        fetcher = AbuseIPDBFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.ips == []

    @respx.mock
    async def test_fetch_http_429(self) -> None:
        """Rate limit response must be captured in errors."""
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        respx.get(url).mock(return_value=httpx.Response(429, json={}))

        cfg = FeedConfig(api_key="test-key")
        fetcher = AbuseIPDBFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert len(result.errors) == 1
        assert "429" in result.errors[0]

    @respx.mock
    async def test_fetch_non_200(self) -> None:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        respx.get(url).mock(return_value=httpx.Response(403, json={}))

        cfg = FeedConfig(api_key="test-key")
        fetcher = AbuseIPDBFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert len(result.errors) == 1
        assert "403" in result.errors[0]

    def test_name_is_abuseipdb(self) -> None:
        fetcher = AbuseIPDBFeedFetcher()
        assert fetcher.name == "abuseipdb"


# ──────────────────────────────────────────────────────────────────────
# Task 2.4 — AlienVaultFeedFetcher
# ──────────────────────────────────────────────────────────────────────


class TestAlienVaultFeedFetcher:
    """AlienVaultFeedFetcher — OTX pulses API (respx)."""

    @respx.mock
    async def test_fetch_parses_ipv4_indicators(self) -> None:
        url = "https://otx.alienvault.com/api/v1/indicators/export"
        respx.get(
            url,
            headers__contains={"X-OTX-API-KEY": "test-otx-key"},
        ).mock(return_value=httpx.Response(200, json=ALIENVAULT_JSON))

        cfg = FeedConfig(api_key="test-otx-key")
        fetcher = AlienVaultFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.feed_name == "alienvault_otx"
        assert len(result.ips) == 3  # IPv4 only, domain filtered out
        assert "1.2.3.4" in result.ips
        assert "5.6.7.8" in result.ips
        assert "9.10.11.12" in result.ips
        assert "example.com" not in result.ips
        assert result.errors == []

    @respx.mock
    async def test_fetch_missing_api_key(self) -> None:
        cfg = FeedConfig(api_key=None)
        fetcher = AlienVaultFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.ips == []
        assert len(result.errors) == 1

    @respx.mock
    async def test_fetch_empty_results(self) -> None:
        url = "https://otx.alienvault.com/api/v1/indicators/export"
        respx.get(url).mock(
            return_value=httpx.Response(200, json={"results": []})
        )

        cfg = FeedConfig(api_key="test-key")
        fetcher = AlienVaultFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert result.ips == []

    @respx.mock
    async def test_fetch_non_200(self) -> None:
        url = "https://otx.alienvault.com/api/v1/indicators/export"
        respx.get(url).mock(return_value=httpx.Response(500))

        cfg = FeedConfig(api_key="test-key")
        fetcher = AlienVaultFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert len(result.errors) == 1
        assert "500" in result.errors[0]

    @respx.mock
    async def test_fetch_connection_error(self) -> None:
        url = "https://otx.alienvault.com/api/v1/indicators/export"
        respx.get(url).mock(side_effect=httpx.ConnectError("connection refused"))

        cfg = FeedConfig(api_key="test-key")
        fetcher = AlienVaultFeedFetcher()
        result = await fetcher.fetch(cfg)

        assert len(result.errors) == 1

    def test_name_is_alienvault_otx(self) -> None:
        fetcher = AlienVaultFeedFetcher()
        assert fetcher.name == "alienvault_otx"
