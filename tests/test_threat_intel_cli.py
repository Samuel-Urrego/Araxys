"""Tests for Threat Intelligence CLI commands.

Phase 5 task 5.5: CLI test coverage via CliRunner for refresh, feeds,
stats, and purge commands on the threat-intel Typer sub-app.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from araxys.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def mock_scheduler() -> MagicMock:
    """Return a MagicMock that looks like a ThreatIntelScheduler."""
    sched = MagicMock()
    sched._config = MagicMock()
    sched._config.enabled = True
    # Enable a few feeds via mock attributes
    for name in ["firehol_level1", "firehol_level2", "blocklist_de"]:
        feed_cfg = MagicMock()
        feed_cfg.enabled = True
        setattr(sched._config, name, feed_cfg)
    for name in ["firehol_level3", "spamhaus_drop", "spamhaus_edrop",
                  "abuseipdb", "alienvault_otx"]:
        feed_cfg = MagicMock()
        feed_cfg.enabled = False
        setattr(sched._config, name, feed_cfg)

    # Single-feed refresh
    sched.refresh = AsyncMock(return_value={
        "feed": "firehol_level1",
        "ips_added": 42,
        "ips_evicted": 0,
    })
    # All-feeds refresh
    sched.refresh.side_effect = None  # will be set per-test
    sched.stats.return_value = {
        "total_ips": 55,
        "feeds": {
            "firehol_level1": {
                "ip_count": 42,
                "last_fetch": "2026-01-01T00:00:00Z",
            },
            "blocklist_de": {
                "ip_count": 13,
                "last_fetch": "2026-01-01T00:00:00Z",
            },
        },
    }
    sched.purge = AsyncMock(return_value=55)
    return sched


# ──────────────────────────────────────────────────────────────────────
# Task 4.2 — CLI commands: refresh
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelCLIRefresh:
    """threat-intel refresh — on-demand feed refresh."""

    def test_refresh_specific_feed(
        self, runner: CliRunner, mock_scheduler: MagicMock,
    ) -> None:
        """refresh --feed firehol_level1 should refresh only that feed."""
        mock_scheduler.refresh = AsyncMock(return_value={
            "feed": "firehol_level1",
            "ips_added": 15,
            "ips_evicted": 0,
        })
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=mock_scheduler,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "refresh", "--feed", "firehol_level1"],
            )
        assert result.exit_code == 0
        assert "✅ Refreshed" in result.stdout

    def test_refresh_unknown_feed_shows_error(
        self, runner: CliRunner, mock_scheduler: MagicMock,
    ) -> None:
        """refresh --feed nonexistent should show error message."""
        mock_scheduler.refresh = AsyncMock(return_value={
            "feed": "nonexistent",
            "error": "Feed not found: nonexistent",
        })
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=mock_scheduler,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "refresh", "--feed", "nonexistent"],
            )
        assert "Error refreshing" in result.stdout


# ──────────────────────────────────────────────────────────────────────
# Task 4.2 — CLI commands: feeds
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelCLIFeeds:
    """threat-intel feeds — list configured feeds."""

    def test_feeds_lists_configured_feeds(
        self, runner: CliRunner, mock_scheduler: MagicMock,
    ) -> None:
        """feeds command should list available feeds from config."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=mock_scheduler,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "feeds"],
            )
        assert result.exit_code == 0
        assert "firehol_level1" in result.stdout
        assert "Total tracked IPs" in result.stdout


# ──────────────────────────────────────────────────────────────────────
# Task 4.2 — CLI commands: stats
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelCLIStats:
    """threat-intel stats — show feed statistics."""

    def test_stats_shows_total_and_per_feed(
        self, runner: CliRunner, mock_scheduler: MagicMock,
    ) -> None:
        """stats command should display total IPs and per-feed counts."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=mock_scheduler,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "stats"],
            )
        assert result.exit_code == 0
        assert "Tracked IPs" in result.stdout

    def test_stats_shows_empty_state(
        self, runner: CliRunner,
    ) -> None:
        """stats command should handle empty state gracefully."""
        empty_sched = MagicMock()
        empty_sched._config = MagicMock()
        empty_sched._config.enabled = True
        for name in ["firehol_level1", "firehol_level2", "firehol_level3",
                      "spamhaus_drop", "spamhaus_edrop", "blocklist_de",
                      "abuseipdb", "alienvault_otx"]:
            setattr(empty_sched._config, name, None)
        empty_sched.stats.return_value = {"total_ips": 0, "feeds": {}}
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=empty_sched,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "stats"],
            )
        assert result.exit_code == 0
        assert "0" in result.stdout


# ──────────────────────────────────────────────────────────────────────
# Task 4.2 — CLI commands: purge
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelCLIPurge:
    """threat-intel purge — remove all threat-intel tracked IPs."""

    def test_purge_removes_and_reports_count(
        self, runner: CliRunner, mock_scheduler: MagicMock,
    ) -> None:
        """purge command should remove all IPs and report count."""
        mock_scheduler.purge = AsyncMock(return_value=55)
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=mock_scheduler,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "purge"],
            )
        assert result.exit_code == 0
        assert "Purged 55" in result.stdout

    def test_purge_empty_scheduler(
        self, runner: CliRunner,
    ) -> None:
        """purge on empty scheduler should report 0."""
        empty_sched = MagicMock()
        empty_sched._config = MagicMock()
        empty_sched._config.enabled = True
        for name in ["firehol_level1", "firehol_level2", "firehol_level3",
                      "spamhaus_drop", "spamhaus_edrop", "blocklist_de",
                      "abuseipdb", "alienvault_otx"]:
            setattr(empty_sched._config, name, None)
        empty_sched.purge = AsyncMock(return_value=0)
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=empty_sched,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "purge"],
            )
        assert result.exit_code == 0
        assert "Purged 0" in result.stdout or "0" in result.stdout


# ──────────────────────────────────────────────────────────────────────
# Error: threat-intel not enabled
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelCLINotEnabled:
    """Commands when threat-intel is not enabled in config."""

    def test_refresh_not_enabled(
        self, runner: CliRunner,
    ) -> None:
        """When not enabled, refresh exits with error."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=None,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "refresh"],
            )
        assert result.exit_code == 1
        assert "not enabled" in result.stdout.lower()

    def test_feeds_not_enabled(
        self, runner: CliRunner,
    ) -> None:
        """When not enabled, feeds exits with error."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=None,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "feeds"],
            )
        assert result.exit_code == 1

    def test_stats_not_enabled(
        self, runner: CliRunner,
    ) -> None:
        """When not enabled, stats exits with error."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=None,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "stats"],
            )
        assert result.exit_code == 1

    def test_purge_not_enabled(
        self, runner: CliRunner,
    ) -> None:
        """When not enabled, purge exits with error."""
        with patch(
            "araxys.threat_intel.cli._get_threat_intel_scheduler",
            return_value=None,
        ):
            result = runner.invoke(
                app,
                ["threat-intel", "purge"],
            )
        assert result.exit_code == 1
