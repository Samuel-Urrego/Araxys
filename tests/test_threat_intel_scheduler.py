"""Tests for Threat Intelligence Scheduler.

Phase 3 task 3.3: ThreatIntelScheduler — background loop, staggered timers,
per-feed error isolation, start/stop lifecycle.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from araxys.core.config import FeedConfig, ThreatIntelConfig
from araxys.ip_access.backends import InMemoryIPAccessBackend
from araxys.threat_intel.feeds import FeedResult, FeedSource

# ──────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ──────────────────────────────────────────────────────────────────────


def _make_config(enabled: bool = True) -> ThreatIntelConfig:
    """Create a ThreatIntelConfig with one feed enabled."""
    return ThreatIntelConfig(
        enabled=enabled,
        firehol_level1=FeedConfig(
            enabled=True,
            refresh_interval_seconds=60,
            ttl_seconds=86400,
        ),
        blocklist_de=FeedConfig(
            enabled=True,
            refresh_interval_seconds=120,
            ttl_seconds=86400,
        ),
    )


def _make_mock_feed(
    name: str,
    ips: list[str] | None = None,
    should_fail: bool = False,
) -> AsyncMock:
    """Create a mock FeedSource that returns a FeedResult."""
    mock = AsyncMock(spec=FeedSource)
    mock.name = name
    if should_fail:
        mock.fetch.side_effect = RuntimeError("feed down")
    else:

        async def _fetch(config: object) -> FeedResult:
            return FeedResult(feed_name=name, ips=ips or [])

        mock.fetch = _fetch  # type: ignore[method-assign]
    return mock


def _make_mock_event_bus() -> AsyncMock:
    """Create a mock SecurityEventBus."""
    mock = AsyncMock()
    mock.emit = AsyncMock()
    return mock


# ──────────────────────────────────────────────────────────────────────
# Task 3.3 — ThreatIntelScheduler construction and initial state
# ──────────────────────────────────────────────────────────────────────


class TestSchedulerInit:
    """ThreatIntelScheduler — construction and default state."""

    def test_creates_with_config_backend_and_feeds(self) -> None:
        """Scheduler must accept config, backend, feeds, and optional deps."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("test_feed")

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        assert sched is not None
        assert sched._config is cfg
        assert sched._backend is backend
        assert feed in sched._feeds

    def test_defaults_not_running(self) -> None:
        """Before start(), _running must be False."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])
        assert sched._running is False
        assert sched._task is None

    def test_resolver_created_internally(self) -> None:
        """Scheduler must create an IPResolver internally."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])
        assert sched._resolver is not None

    def test_accepts_optional_event_bus(self) -> None:
        """Scheduler must accept an optional SecurityEventBus."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        event_bus = _make_mock_event_bus()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[], event_bus=event_bus)
        assert sched._event_bus is event_bus

    def test_event_bus_defaults_to_none(self) -> None:
        """When no event_bus is provided, _event_bus must be None."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])
        assert sched._event_bus is None


# ──────────────────────────────────────────────────────────────────────
# start / stop lifecycle
# ──────────────────────────────────────────────────────────────────────


class TestSchedulerLifecycle:
    """ThreatIntelScheduler — start/stop lifecycle."""

    @pytest.mark.asyncio
    async def test_start_sets_running_and_creates_task(self) -> None:
        """start() must set _running=True and create a background task."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("test_feed")

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        sched.start()

        assert sched._running is True
        assert sched._task is not None
        assert not sched._task.done()

        # Clean up
        await sched.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_task_and_sets_not_running(self) -> None:
        """stop() must cancel the task and set _running=False."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("test_feed")

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        sched.start()
        assert sched._running is True

        await sched.stop()

        assert sched._running is False
        assert sched._task is None or sched._task.done()

    @pytest.mark.asyncio
    async def test_stop_idempotent(self) -> None:
        """Calling stop() twice must not raise."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("test_feed")

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        sched.start()
        await sched.stop()
        # Second stop must be safe
        await sched.stop()

        assert sched._running is False

    @pytest.mark.asyncio
    async def test_stop_no_start_is_safe(self) -> None:
        """Calling stop() without start() must not raise."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])
        await sched.stop()  # Must not raise


# ──────────────────────────────────────────────────────────────────────
# feed fetch and sync
# ──────────────────────────────────────────────────────────────────────


class TestSchedulerFetchAndSync:
    """ThreatIntelScheduler — feed fetch, dedup, sync, evict cycle."""

    @pytest.mark.asyncio
    async def test_fetches_feed_and_syncs_to_backend(self) -> None:
        """A successful fetch must result in IPs in the backend."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4", "5.6.7.8"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        # Use refresh() to trigger a single fetch
        result = await sched.refresh("firehol_level1")

        assert result["feed"] == "firehol_level1"
        assert result["ips_added"] == 2
        assert result["ips_evicted"] == 0
        assert await backend.is_blocked("1.2.3.4")
        assert await backend.is_blocked("5.6.7.8")

    @pytest.mark.asyncio
    async def test_refresh_unknown_feed_returns_error(self) -> None:
        """refresh() for an unknown feed must return an error dict."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])

        result = await sched.refresh("nonexistent_feed")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_feed_error_isolation(self) -> None:
        """One feed failing must not prevent other feeds from working."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        good_feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4"])
        bad_feed = _make_mock_feed("blocklist_de", should_fail=True)

        sched = ThreatIntelScheduler(cfg, backend, feeds=[good_feed, bad_feed])

        # Refresh the good feed — must succeed
        result = await sched.refresh("firehol_level1")
        assert result["ips_added"] == 1
        assert await backend.is_blocked("1.2.3.4")

        # Refresh the bad feed — must report error but not crash
        result = await sched.refresh("blocklist_de")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_refresh_all_feeds(self) -> None:
        """refresh() with no feed_name must refresh all feeds."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed1 = _make_mock_feed("firehol_level1", ips=["1.2.3.4"])
        feed2 = _make_mock_feed("blocklist_de", ips=["5.6.7.8"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed1, feed2])
        results = await sched.refresh()

        assert len(results) == 2
        names = {r["feed"] for r in results}
        assert names == {"firehol_level1", "blocklist_de"}

    @pytest.mark.asyncio
    async def test_eviction_removes_expired_ips(self) -> None:
        """Expired IPs from feeds no longer reporting them must be evicted."""
        import time

        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()

        # First fetch returns IPs; second fetch returns nothing
        call_count = [0]

        async def _fetch(config: object) -> FeedResult:
            call_count[0] += 1
            if call_count[0] == 1:
                return FeedResult(
                    feed_name="firehol_level1", ips=["1.2.3.4", "5.6.7.8"],
                )
            return FeedResult(feed_name="firehol_level1", ips=[])

        feed = AsyncMock(spec=FeedSource)
        feed.name = "firehol_level1"
        feed.fetch = _fetch  # type: ignore[method-assign]

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        await sched.refresh("firehol_level1")
        assert await backend.is_blocked("1.2.3.4")
        assert await backend.is_blocked("5.6.7.8")

        # Artificially expire the entries
        for key in list(sched._resolver._ttl_map.keys()):
            sched._resolver._ttl_map[key] = time.time() - 100

        # Second refresh — feed returns empty, eviction should fire
        await sched.refresh("firehol_level1")
        # The IPs should be evicted from backend
        assert not await backend.is_blocked("1.2.3.4")
        assert not await backend.is_blocked("5.6.7.8")


# ──────────────────────────────────────────────────────────────────────
# stats and purge
# ──────────────────────────────────────────────────────────────────────


class TestSchedulerStats:
    """ThreatIntelScheduler — stats() and purge() methods."""

    @pytest.mark.asyncio
    async def test_stats_initial_empty(self) -> None:
        """stats() must return empty state before any fetch."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])

        stats = sched.stats()
        assert stats["total_ips"] == 0
        assert isinstance(stats["feeds"], dict)

    @pytest.mark.asyncio
    async def test_stats_after_fetch(self) -> None:
        """stats() must reflect IPs after a refresh."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4", "5.6.7.8"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        await sched.refresh("firehol_level1")

        stats = sched.stats()
        assert stats["total_ips"] == 2

    @pytest.mark.asyncio
    async def test_purge_removes_all_ips(self) -> None:
        """purge() must remove all threat-intel tracked IPs from backend."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4", "5.6.7.8"])

        sched = ThreatIntelScheduler(cfg, backend, feeds=[feed])
        await sched.refresh("firehol_level1")
        assert await backend.is_blocked("1.2.3.4")

        count = await sched.purge()
        assert count == 2
        assert not await backend.is_blocked("1.2.3.4")
        assert not await backend.is_blocked("5.6.7.8")

    @pytest.mark.asyncio
    async def test_purge_empty_is_zero(self) -> None:
        """purge() with no IPs must return 0."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        sched = ThreatIntelScheduler(cfg, backend, feeds=[])

        count = await sched.purge()
        assert count == 0


# ──────────────────────────────────────────────────────────────────────
# event bus emissions
# ──────────────────────────────────────────────────────────────────────


class TestSchedulerEventBus:
    """ThreatIntelScheduler — event bus integration."""

    @pytest.mark.asyncio
    async def test_emits_threat_intel_loaded_on_refresh(self) -> None:
        """refresh() must emit THREAT_INTEL_LOADED via event_bus."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4", "5.6.7.8"])
        event_bus = _make_mock_event_bus()

        sched = ThreatIntelScheduler(
            cfg, backend, feeds=[feed], event_bus=event_bus,
        )
        await sched.refresh("firehol_level1")

        event_bus.emit.assert_called()
        # The event must be THREAT_INTEL_LOADED
        call_args = event_bus.emit.call_args[0]
        assert len(call_args) == 1
        event = call_args[0]
        from araxys.core.types import SecurityEventType

        assert event.event_type == SecurityEventType.THREAT_INTEL_LOADED

    @pytest.mark.asyncio
    async def test_no_event_bus_is_safe(self) -> None:
        """refresh() must not crash when event_bus is None."""
        from araxys.threat_intel.scheduler import ThreatIntelScheduler

        cfg = _make_config()
        backend = InMemoryIPAccessBackend()
        feed = _make_mock_feed("firehol_level1", ips=["1.2.3.4"])

        sched = ThreatIntelScheduler(
            cfg, backend, feeds=[feed], event_bus=None,
        )
        # Must not raise
        result = await sched.refresh("firehol_level1")
        assert result["ips_added"] == 1
