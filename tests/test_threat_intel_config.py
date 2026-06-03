"""Tests for Threat Intelligence Feeds configuration models.

Phase 1 tasks: 1.1 (ThreatIntelConfig + threat_intel field),
1.2 (SecurityEventType), 1.4 (FeedConfig + FEED_DEFAULTS).
"""

from __future__ import annotations

import pytest

from araxys.core.config import AraxysConfig, FeedConfig, ThreatIntelConfig
from araxys.core.types import SecurityEventType

# ──────────────────────────────────────────────────────────────────────
# Task 1.1 — ThreatIntelConfig
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelConfig:
    """ThreatIntelConfig — defaults and custom values."""

    def test_defaults(self) -> None:
        c = ThreatIntelConfig()
        assert c.enabled is False
        assert c.refresh_interval_seconds == 3600
        assert c.exclude_ips == []
        # All 8 feeds default to None (disabled)
        assert c.firehol_level1 is None
        assert c.firehol_level2 is None
        assert c.firehol_level3 is None
        assert c.spamhaus_drop is None
        assert c.spamhaus_edrop is None
        assert c.blocklist_de is None
        assert c.abuseipdb is None
        assert c.alienvault_otx is None

    def test_custom_values(self) -> None:
        c = ThreatIntelConfig(
            enabled=True,
            refresh_interval_seconds=1800,
            exclude_ips=["10.0.0.1", "192.168.1.0/24"],
        )
        assert c.enabled is True
        assert c.refresh_interval_seconds == 1800
        assert c.exclude_ips == ["10.0.0.1", "192.168.1.0/24"]

    def test_enabling_one_feed(self) -> None:
        """Setting a FeedConfig dict on a feed enables it."""
        c = ThreatIntelConfig(
            firehol_level1={"enabled": True},
        )  # type: ignore[arg-type]  # noqa: E501
        assert c.firehol_level1 is not None
        assert c.firehol_level1.enabled is True
        assert c.firehol_level1.refresh_interval_seconds == 3600  # default
        # Other feeds still disabled
        assert c.firehol_level2 is None

    def test_enabling_multiple_feeds(self) -> None:
        c = ThreatIntelConfig(
            spamhaus_drop={"enabled": True, "ttl_seconds": 86400},
            blocklist_de={"enabled": True, "refresh_interval_seconds": 600},
        )
        assert c.spamhaus_drop is not None
        assert c.spamhaus_drop.enabled is True
        assert c.spamhaus_drop.ttl_seconds == 86400
        assert c.blocklist_de is not None
        assert c.blocklist_de.enabled is True
        assert c.blocklist_de.refresh_interval_seconds == 600

    def test_refresh_interval_ge_validation(self) -> None:
        """refresh_interval_seconds must be >= 60."""
        import re

        with pytest.raises(
            Exception, match=re.escape("Input should be greater than or equal to 60")
        ):
            ThreatIntelConfig(refresh_interval_seconds=30)

    def test_refresh_interval_le_validation(self) -> None:
        """refresh_interval_seconds must be <= 86400."""
        import re

        with pytest.raises(
            Exception, match=re.escape("Input should be less than or equal to 86400")
        ):
            ThreatIntelConfig(refresh_interval_seconds=100000)

    # ── enabled_feeds property ────────────────────────────────────────

    def test_enabled_feeds_empty_when_disabled(self) -> None:
        c = ThreatIntelConfig()
        feeds = c.enabled_feeds()
        assert feeds == []

    def test_enabled_feeds_detects_enabled(self) -> None:
        c = ThreatIntelConfig(
            firehol_level1={"enabled": True},
            blocklist_de={"enabled": True},
            abuseipdb={"enabled": True, "api_key": "test-key"},
        )
        feeds = c.enabled_feeds()
        assert len(feeds) == 3
        feed_names = [f["name"] for f in feeds]
        assert "firehol_level1" in feed_names
        assert "blocklist_de" in feed_names
        assert "abuseipdb" in feed_names

    def test_enabled_feeds_skips_disabled(self) -> None:
        c = ThreatIntelConfig(
            firehol_level1={"enabled": True},
            spamhaus_drop={"enabled": False},
        )
        feeds = c.enabled_feeds()
        assert len(feeds) == 1
        assert feeds[0]["name"] == "firehol_level1"


# ──────────────────────────────────────────────────────────────────────
# Task 1.4 — FeedConfig (in core/config.py, used by ThreatIntelConfig)
# ──────────────────────────────────────────────────────────────────────


class TestFeedConfig:
    """FeedConfig — per-feed configuration."""

    def test_defaults(self) -> None:
        c = FeedConfig()
        assert c.enabled is True
        assert c.refresh_interval_seconds == 3600
        assert c.ttl_seconds == 86400
        assert c.api_key is None
        assert c.url is None

    def test_custom_values(self) -> None:
        c = FeedConfig(
            enabled=False,
            refresh_interval_seconds=600,
            ttl_seconds=43200,
            api_key="abc123",
            url="https://custom-feed.example.com/ips.txt",
        )
        assert c.enabled is False
        assert c.refresh_interval_seconds == 600
        assert c.ttl_seconds == 43200
        assert c.api_key == "abc123"
        assert c.url == "https://custom-feed.example.com/ips.txt"

    def test_url_override_none_by_default(self) -> None:
        """url is None — fetcher uses the built-in default."""
        c = FeedConfig()
        assert c.url is None

    def test_refresh_interval_ge_validation(self) -> None:
        import re

        with pytest.raises(
            Exception, match=re.escape("Input should be greater than or equal to 60")
        ):
            FeedConfig(refresh_interval_seconds=30)

    def test_ttl_ge_validation(self) -> None:
        import re

        with pytest.raises(
            Exception, match=re.escape("Input should be greater than or equal to 3600")
        ):
            FeedConfig(ttl_seconds=1800)


# ──────────────────────────────────────────────────────────────────────
# Task 1.1 — threat_intel field on AraxysConfig
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelInAraxysConfig:
    """threat_intel must be optional None on AraxysConfig."""

    def test_defaults_to_none(self) -> None:
        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        assert c.threat_intel is None

    def test_explicit_none(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            threat_intel=None,
        )
        assert c.threat_intel is None

    def test_provided_via_empty_dict(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            threat_intel={},  # type: ignore[arg-type]
        )
        assert c.threat_intel is not None
        assert c.threat_intel.enabled is False
        assert c.threat_intel.refresh_interval_seconds == 3600
        assert c.threat_intel.exclude_ips == []

    def test_provided_via_nested_dict(self) -> None:
        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            threat_intel={  # type: ignore[arg-type]
                "enabled": True,
                "refresh_interval_seconds": 1800,
                "exclude_ips": ["10.0.0.1"],
                "firehol_level1": {"enabled": True},
                "blocklist_de": {"enabled": True, "refresh_interval_seconds": 600},
            },
        )
        assert c.threat_intel is not None
        assert c.threat_intel.enabled is True
        assert c.threat_intel.refresh_interval_seconds == 1800
        assert c.threat_intel.exclude_ips == ["10.0.0.1"]
        assert c.threat_intel.firehol_level1 is not None
        assert c.threat_intel.firehol_level1.enabled is True
        assert c.threat_intel.blocklist_de is not None
        assert c.threat_intel.blocklist_de.refresh_interval_seconds == 600
        # Non-mentioned feeds stay None
        assert c.threat_intel.spamhaus_drop is None


# ──────────────────────────────────────────────────────────────────────
# Task 1.2 — SecurityEventType additions
# ──────────────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────────────
# Task 1.4 — FEED_DEFAULTS in threat_intel/config.py
# ──────────────────────────────────────────────────────────────────────


class TestFeedDefaults:
    """FEED_DEFAULTS dict — presets for all 8 feeds."""

    def test_imports(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS  # noqa: F811

        assert isinstance(FEED_DEFAULTS, dict)

    def test_all_eight_feeds_present(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        expected = [
            "firehol_level1", "firehol_level2", "firehol_level3",
            "spamhaus_drop", "spamhaus_edrop", "blocklist_de",
            "abuseipdb", "alienvault_otx",
        ]
        for name in expected:
            assert name in FEED_DEFAULTS, f"{name} missing from FEED_DEFAULTS"

    def test_firehol_l1_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["firehol_level1"]
        assert preset["url"] == (
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/"
            "master/firehol_level1.netset"
        )
        assert preset["refresh_interval_seconds"] == 300

    def test_firehol_l2_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["firehol_level2"]
        assert preset["refresh_interval_seconds"] == 300

    def test_spamhaus_drop_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["spamhaus_drop"]
        assert preset["url"] == "https://www.spamhaus.org/drop/drop.txt"
        assert preset["ttl_seconds"] == 86400

    def test_spamhaus_edrop_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["spamhaus_edrop"]
        assert preset["ttl_seconds"] == 604800  # 7 days

    def test_blocklist_de_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["blocklist_de"]
        assert preset["url"] == "https://lists.blocklist.de/lists/all.txt"
        assert preset["refresh_interval_seconds"] == 300

    def test_abuseipdb_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["abuseipdb"]
        assert preset["api_key"] is None  # user must provide
        assert preset["url"] == "https://api.abuseipdb.com/api/v2/blacklist"

    def test_alienvault_preset(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        preset = FEED_DEFAULTS["alienvault_otx"]
        assert preset["api_key"] is None  # user must provide
        assert preset["url"] == "https://otx.alienvault.com/api/v1/indicators/export"

    def test_no_extra_keys(self) -> None:
        from araxys.threat_intel.config import FEED_DEFAULTS

        allowed = frozenset({
            "firehol_level1", "firehol_level2", "firehol_level3",
            "spamhaus_drop", "spamhaus_edrop", "blocklist_de",
            "abuseipdb", "alienvault_otx",
        })
        assert set(FEED_DEFAULTS.keys()) == allowed


# ──────────────────────────────────────────────────────────────────────
# Task 1.3 — threat_intel/__init__.py exports
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelModuleExports:
    """threat_intel public API exports."""

    def test_import_module(self) -> None:
        """Module must be importable."""
        import araxys.threat_intel  # noqa: F401

    def test_threat_intel_config_exported(self) -> None:
        from araxys.threat_intel import ThreatIntelConfig

        assert ThreatIntelConfig is not None

    def test_feed_config_exported(self) -> None:
        from araxys.threat_intel import FeedConfig

        assert FeedConfig is not None

    def test_feed_defaults_exported(self) -> None:
        from araxys.threat_intel import FEED_DEFAULTS

        assert isinstance(FEED_DEFAULTS, dict)


class TestThreatIntelEventTypes:
    """THREAT_INTEL_LOADED and THREAT_INTEL_MATCH in SecurityEventType."""

    def test_threat_intel_loaded_exists(self) -> None:
        assert hasattr(SecurityEventType, "THREAT_INTEL_LOADED")
        assert SecurityEventType.THREAT_INTEL_LOADED.value == "threat_intel_loaded"

    def test_threat_intel_match_exists(self) -> None:
        assert hasattr(SecurityEventType, "THREAT_INTEL_MATCH")
        assert SecurityEventType.THREAT_INTEL_MATCH.value == "threat_intel_match"

    def test_enum_values_are_strings(self) -> None:
        assert isinstance(SecurityEventType.THREAT_INTEL_LOADED, str)
        assert isinstance(SecurityEventType.THREAT_INTEL_MATCH, str)
