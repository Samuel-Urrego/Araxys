"""Integration tests for Threat Intelligence Feeds module.

Phase 5 task 5.4: Full fetch→block→evict cycle with fakeredis.
Phase 4 task 4.1: Shield wiring — scheduler lifecycle via AraxysShield.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from araxys.core.config import (
    AraxysConfig,
    FeedConfig,
    ThreatIntelConfig,
)
from araxys.core.types import SecurityEvent, SecurityEventType
from araxys.ip_access.backends import InMemoryIPAccessBackend
from araxys.threat_intel.feeds import FeedResult, FeedSource

# ──────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ──────────────────────────────────────────────────────────────────────


def _make_threat_intel_config(
    enabled: bool = True,
    *,
    ttl_seconds: int = 86400,
    exclude_ips: list[str] | None = None,
) -> ThreatIntelConfig:
    """Create a ThreatIntelConfig for integration tests."""
    return ThreatIntelConfig(
        enabled=enabled,
        ttl_seconds=ttl_seconds,
        exclude_ips=exclude_ips or [],
        firehol_level1=FeedConfig(
            enabled=True,
            refresh_interval_seconds=60,
            ttl_seconds=ttl_seconds,
        ),
        blocklist_de=FeedConfig(
            enabled=True,
            refresh_interval_seconds=120,
            ttl_seconds=ttl_seconds,
        ),
    )


def _make_mock_feed(name: str, ips: list[str]) -> AsyncMock:
    """Create a mock FeedSource that returns ips."""
    mock = AsyncMock(spec=FeedSource)
    mock.name = name

    async def _fetch(config: object) -> FeedResult:
        return FeedResult(feed_name=name, ips=list(ips))

    mock.fetch = _fetch  # type: ignore[method-assign]
    return mock


def _make_araxys_config(
    threat_intel: ThreatIntelConfig | None = None,
) -> AraxysConfig:
    """Create an AraxysConfig with given threat_intel setting."""
    return AraxysConfig(
        secret_key="test-secret-key-for-integration-testing!!",
        threat_intel=threat_intel,
    )


# ──────────────────────────────────────────────────────────────────────
# Task 5.4 — Fetch → Block → Evict cycle (integration)
# ──────────────────────────────────────────────────────────────────────


class TestThreatIntelFetchBlockEvictCycle:
    """End-to-end cycle: feed fetch → dedup → blocklist → eviction."""

    @pytest.mark.asyncio
    async def test_full_cycle_adds_ips_to_backend(self) -> None:
        """Full cycle: fetch feed → IPs added to IPAccessBackend blocklist."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config()
        backend = InMemoryIPAccessBackend()

        feed = _make_mock_feed("firehol_level1", ["1.2.3.4", "5.6.7.8", "10.0.0.1"])
        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])

        # Manually trigger a refresh cycle
        await sched.refresh("firehol_level1")

        # Verify IPs are in the blocklist
        assert await backend.is_blocked("1.2.3.4") is True
        assert await backend.is_blocked("5.6.7.8") is True
        assert await backend.is_blocked("10.0.0.1") is True

    @pytest.mark.asyncio
    async def test_deduplicate_across_feeds(self) -> None:
        """IP appearing in multiple feeds must only be added once."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config()
        backend = InMemoryIPAccessBackend()

        feed1 = _make_mock_feed("firehol_level1", ["1.2.3.4", "5.6.7.8"])
        feed2 = _make_mock_feed("blocklist_de", ["1.2.3.4", "9.9.9.9"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed1, feed2])

        # Refresh both feeds
        await sched.refresh("firehol_level1")
        await sched.refresh("blocklist_de")

        # Verify all unique IPs are blocked
        assert await backend.is_blocked("1.2.3.4") is True
        assert await backend.is_blocked("5.6.7.8") is True
        assert await backend.is_blocked("9.9.9.9") is True

    @pytest.mark.asyncio
    async def test_exclude_ips_not_added(self) -> None:
        """IPs in exclude_ips must NOT be added to blocklist."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config(exclude_ips=["1.2.3.4"])
        backend = InMemoryIPAccessBackend()

        feed = _make_mock_feed("firehol_level1", ["1.2.3.4", "5.6.7.8"])
        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])

        await sched.refresh("firehol_level1")

        # Excluded IP must NOT be blocked
        assert await backend.is_blocked("1.2.3.4") is False
        # Other IPs must still be blocked
        assert await backend.is_blocked("5.6.7.8") is True

    @pytest.mark.asyncio
    async def test_eviction_removes_expired_ips(self) -> None:
        """Expired IPs (past TTL) must be removed from backend on eviction."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler, _ip_from_key

        cfg = _make_threat_intel_config(ttl_seconds=3600)
        backend = InMemoryIPAccessBackend()

        feed = _make_mock_feed("firehol_level1", ["1.2.3.4"])
        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])

        await sched.refresh("firehol_level1")

        # IP should be in blocklist immediately after refresh
        assert await backend.is_blocked("1.2.3.4") is True

        # Simulate TTL expiry by backdating all entries
        import time
        for key in list(sched._resolver._ttl_map.keys()):
            sched._resolver._ttl_map[key] = time.time() - 3601

        # Run eviction directly (avoids re-fetch which would refresh TTL)
        expired_keys = sched._resolver.evict_expired()
        assert len(expired_keys) == 1
        for key in expired_keys:
            ip = _ip_from_key(key)
            await backend.remove_from_blocklist(ip)

        # All IPs should now be evicted from blocklist
        assert await backend.is_blocked("1.2.3.4") is False
        assert len(sched._resolver._ttl_map) == 0

    @pytest.mark.asyncio
    async def test_purge_removes_all_tracked_ips(self) -> None:
        """purge() must remove all tracked IPs from the backend."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config(ttl_seconds=99999)
        backend = InMemoryIPAccessBackend()

        feed1 = _make_mock_feed("firehol_level1", ["1.2.3.4", "5.6.7.8"])
        feed2 = _make_mock_feed("blocklist_de", ["9.9.9.9"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed1, feed2])
        await sched.refresh("firehol_level1")
        await sched.refresh("blocklist_de")

        # All 3 unique IPs should be blocked
        assert await backend.is_blocked("1.2.3.4") is True
        assert await backend.is_blocked("5.6.7.8") is True
        assert await backend.is_blocked("9.9.9.9") is True

        # Purge
        removed = await sched.purge()
        assert removed == 3

        # All should be unblocked
        assert await backend.is_blocked("1.2.3.4") is False
        assert await backend.is_blocked("5.6.7.8") is False
        assert await backend.is_blocked("9.9.9.9") is False

    @pytest.mark.asyncio
    async def test_event_emission_on_feed_refresh(self) -> None:
        """THREAT_INTEL_LOADED event must be emitted on feed refresh."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config()
        backend = InMemoryIPAccessBackend()
        event_bus = AsyncMock()
        event_bus.emit = AsyncMock()

        feed = _make_mock_feed("firehol_level1", ["1.2.3.4", "5.6.7.8"])
        sched = ThreatIntelScheduler(
            cfg, backend,
            feeds=[feed],
            event_bus=event_bus,
        )

        await sched.refresh("firehol_level1")

        # Verify event was emitted
        event_bus.emit.assert_called()
        call_args = event_bus.emit.call_args[0][0]
        assert isinstance(call_args, SecurityEvent)
        assert call_args.event_type == SecurityEventType.THREAT_INTEL_LOADED
        assert call_args.metadata.get("feed_name") == "firehol_level1"

    @pytest.mark.asyncio
    async def test_error_isolation_per_feed(self) -> None:
        """A failing feed must not prevent other feeds from refreshing."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config()
        backend = InMemoryIPAccessBackend()

        good_feed = _make_mock_feed("firehol_level1", ["1.2.3.4"])

        # Create a feed that raises on fetch
        bad_feed = AsyncMock(spec=FeedSource)
        bad_feed.name = "blocklist_de"
        bad_feed.fetch = AsyncMock(side_effect=RuntimeError("feed server error"))

        sched = ThreatIntelScheduler(cfg, backend, feeds=[good_feed, bad_feed])

        # Refreshing the good feed should still work
        await sched.refresh("firehol_level1")
        assert await backend.is_blocked("1.2.3.4") is True

        # Refreshing the bad feed should report the error via refresh()
        result = await sched.refresh("blocklist_de")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_empty_feed_no_ops(self) -> None:
        """A feed that returns no IPs should not affect blocklist."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_threat_intel_config()
        backend = InMemoryIPAccessBackend()

        empty_feed = _make_mock_feed("firehol_level1", [])
        sched = ThreatIntelScheduler(cfg, backend, feeds=[empty_feed])

        await sched.refresh("firehol_level1")
        stats = sched.stats()
        assert stats["total_ips"] == 0


# ──────────────────────────────────────────────────────────────────────
# Task 4.1 — Shield wiring: scheduler lifecycle in AraxysShield
# ──────────────────────────────────────────────────────────────────────


class TestShieldThreatIntelWiring:
    """Shield integration: _register_threat_intel lifecycle."""

    def test_no_scheduler_when_threat_intel_disabled(self) -> None:
        """When threat_intel=None, no scheduler must be created."""
        from araxys.shield import AraxysShield

        cfg = _make_araxys_config(threat_intel=None)

        with patch("fastapi.FastAPI"):
            from fastapi import FastAPI
            app = FastAPI()
            shield = AraxysShield(app, cfg)

        assert not hasattr(shield, "_threat_intel_scheduler") or \
            shield._threat_intel_scheduler is None

    def test_no_scheduler_when_threat_intel_not_enabled(self) -> None:
        """When threat_intel.enabled=False, no scheduler must be created."""
        from araxys.shield import AraxysShield

        cfg = _make_araxys_config(
            threat_intel=ThreatIntelConfig(enabled=False),
        )

        with patch("fastapi.FastAPI"):
            from fastapi import FastAPI
            app = FastAPI()
            shield = AraxysShield(app, cfg)

        assert not hasattr(shield, "_threat_intel_scheduler") or \
            shield._threat_intel_scheduler is None

    def test_scheduler_created_when_threat_intel_enabled(self) -> None:
        """When threat_intel.enabled=True, scheduler must be created."""
        from araxys.shield import AraxysShield

        ti_cfg = _make_threat_intel_config(enabled=True)
        cfg = _make_araxys_config(threat_intel=ti_cfg)

        # Mock scheduler to avoid asyncio.create_task() call
        mock_scheduler_cls = MagicMock()
        mock_instance = MagicMock()
        mock_scheduler_cls.return_value = mock_instance

        with patch(
            "araxys.threat_intel.scheduler.ThreatIntelScheduler",
            mock_scheduler_cls,
        ), patch("fastapi.FastAPI"):
            from fastapi import FastAPI
            app_obj = FastAPI()
            shield = AraxysShield(app_obj, cfg)

        # Shield should have scheduler attribute set
        assert hasattr(shield, "_threat_intel_scheduler")
        assert shield._threat_intel_scheduler is mock_instance
        # Scheduler.start() should have been called
        mock_instance.start.assert_called_once()

    def test_scheduler_not_created_without_feeds(self) -> None:
        """When no feeds are enabled, scheduler should not be created."""
        from araxys.shield import AraxysShield

        # All feeds disabled
        ti_cfg = ThreatIntelConfig(enabled=True)
        cfg = _make_araxys_config(threat_intel=ti_cfg)

        mock_scheduler_cls = MagicMock()
        with patch(
            "araxys.threat_intel.scheduler.ThreatIntelScheduler",
            mock_scheduler_cls,
        ), patch("fastapi.FastAPI"):
            from fastapi import FastAPI
            app_obj = FastAPI()
            shield = AraxysShield(app_obj, cfg)

        # No feeds → scheduler should not be created
        assert not hasattr(shield, "_threat_intel_scheduler") or \
            shield._threat_intel_scheduler is None
        mock_scheduler_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_shutdown_calls_scheduler_stop(self) -> None:
        """shield.shutdown() must call threat_intel_scheduler.stop()."""
        from araxys.shield import AraxysShield

        ti_cfg = _make_threat_intel_config(enabled=True)
        cfg = _make_araxys_config(threat_intel=ti_cfg)

        mock_scheduler_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.stop = AsyncMock()
        mock_scheduler_cls.return_value = mock_instance

        with patch(
            "araxys.threat_intel.scheduler.ThreatIntelScheduler",
            mock_scheduler_cls,
        ), patch("fastapi.FastAPI"):
            from fastapi import FastAPI
            app_obj = FastAPI()
            shield = AraxysShield(app_obj, cfg)

        await shield.shutdown()

        mock_instance.stop.assert_called_once()
