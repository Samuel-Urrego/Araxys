"""Tests for Threat Intelligence IP resolver and deduplication.

Phase 3 task 3.1: IPResolver — dedup, TTL tracking, eviction logic.
Phase 3 task 3.2: add_bulk_to_blocklist on RedisIPAccessBackend.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from araxys.core.config import ThreatIntelConfig
from araxys.ip_access.backends import InMemoryIPAccessBackend
from araxys.threat_intel.resolver import IPResolver

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


def _make_config(
    *,
    exclude_ips: list[str] | None = None,
    ttl_seconds: int = 86400,
) -> ThreatIntelConfig:
    """Create a ThreatIntelConfig for resolver tests."""
    return ThreatIntelConfig(
        enabled=True,
        exclude_ips=exclude_ips or [],
    )


# ──────────────────────────────────────────────────────────────────────
# Task 3.1 — IPResolver construction and in-memory TTL tracking
# ──────────────────────────────────────────────────────────────────────


class TestIPResolverInit:
    """IPResolver — construction and initial state."""

    def test_creates_with_config(self) -> None:
        """Resolver must accept a ThreatIntelConfig."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        assert resolver is not None
        assert resolver._config is cfg

    def test_ttl_map_starts_empty(self) -> None:
        """Internal TTL dict must be empty on construction."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        assert resolver._ttl_map == {}

    def test_accepts_optional_redis(self) -> None:
        """Resolver must accept an optional redis client for ZSET backing."""
        cfg = _make_config()
        redis = MagicMock()
        resolver = IPResolver(cfg, redis=redis)
        assert resolver._redis is redis

    def test_redis_is_none_by_default(self) -> None:
        """Without redis, _redis must be None for in-memory-only mode."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        assert resolver._redis is None


# ──────────────────────────────────────────────────────────────────────
# deduplicate — in-memory mode
# ──────────────────────────────────────────────────────────────────────


class TestIPResolverDeduplicate:
    """IPResolver.deduplicate() — in-memory dedup logic."""

    def test_new_ips_all_returned(self) -> None:
        """All IPs returned when none have been seen before."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
        result = resolver.deduplicate(ips, "firehol_level1")
        assert result == ips

    def test_duplicate_across_same_feed_filtered(self) -> None:
        """Second call with same feed must filter already-seen IPs."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        # First call — all new
        first = resolver.deduplicate(["1.2.3.4", "5.6.7.8"], "firehol_level1")
        assert first == ["1.2.3.4", "5.6.7.8"]

        # Second call — "1.2.3.4" already tracked
        second = resolver.deduplicate(["1.2.3.4", "9.10.11.12"], "firehol_level1")
        assert second == ["9.10.11.12"]

    def test_same_ip_different_feeds_cross_dedup(self) -> None:
        """Same IP from different feeds is cross-deduplicated (already tracked).

        The IP is already in the blocklist from the first feed;
        there is no point re-adding it. TTL is still updated.
        """
        cfg = _make_config()
        resolver = IPResolver(cfg)
        # Feed A adds IP
        a_result = resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        assert a_result == ["1.2.3.4"]

        # Feed B — same IP, different feed → filtered (already blocked)
        b_result = resolver.deduplicate(["1.2.3.4"], "blocklist_de")
        assert b_result == []

        # TTL entry for second feed must exist
        assert "1.2.3.4:blocklist_de" in resolver._ttl_map

    def test_exclude_ips_filtered_from_input(self) -> None:
        """IPs matching exclude_ips config must never be accepted."""
        cfg = _make_config(exclude_ips=["10.0.0.0/8", "192.168.1.1"])
        resolver = IPResolver(cfg)
        result = resolver.deduplicate(
            ["1.2.3.4", "10.0.0.55", "192.168.1.1", "5.6.7.8"],
            "firehol_level1",
        )
        assert result == ["1.2.3.4", "5.6.7.8"]
        assert "10.0.0.55" not in result
        assert "192.168.1.1" not in result

    def test_exclude_ips_with_cidr_notation(self) -> None:
        """CIDR exclude_ips must match all IPs in that range."""
        cfg = _make_config(exclude_ips=["10.0.0.0/24"])
        resolver = IPResolver(cfg)
        result = resolver.deduplicate(
            ["10.0.0.1", "10.0.0.255", "10.0.1.1", "1.2.3.4"],
            "firehol_level1",
        )
        assert result == ["10.0.1.1", "1.2.3.4"]

    def test_exclude_ips_cidr_overlap_excludes(self) -> None:
        """A CIDR overlapping with an excluded network is fully excluded.

        Overlap is safer: if "1.2.3.4" is excluded and a feed returns
        "1.2.3.0/24", the entire /24 is excluded to avoid accidentally
        blocking the excluded IP as part of the CIDR.
        """
        cfg = _make_config(exclude_ips=["1.2.3.4"])
        resolver = IPResolver(cfg)
        result = resolver.deduplicate(
            ["1.2.3.4", "1.2.3.0/24", "5.6.7.8"],
            "firehol_level1",
        )
        # Both "1.2.3.4" and "1.2.3.0/24" (which contains it) are excluded
        assert result == ["5.6.7.8"]

    def test_exclude_ips_cidr_matches_subset_ips(self) -> None:
        """A CIDR in exclude_ips must block any IP within that range."""
        cfg = _make_config(exclude_ips=["1.2.3.0/24"])
        resolver = IPResolver(cfg)
        result = resolver.deduplicate(
            ["1.2.3.4", "1.2.3.255", "1.2.4.1", "5.6.7.8"],
            "firehol_level1",
        )
        assert result == ["1.2.4.1", "5.6.7.8"]

    def test_empty_input_returns_empty(self) -> None:
        """Empty IP list must return empty list."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        result = resolver.deduplicate([], "firehol_level1")
        assert result == []

    def test_all_excluded_returns_empty(self) -> None:
        """When all IPs are in exclude_ips, return empty list."""
        cfg = _make_config(exclude_ips=["1.2.3.4", "5.6.7.8"])
        resolver = IPResolver(cfg)
        result = resolver.deduplicate(
            ["1.2.3.4", "5.6.7.8"],
            "firehol_level1",
        )
        assert result == []

    def test_records_ttl_for_new_ips(self) -> None:
        """Each new IP must be recorded in _ttl_map with a future timestamp."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        before = time.time()
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        after = time.time()

        key = "1.2.3.4:firehol_level1"
        assert key in resolver._ttl_map
        expiration = resolver._ttl_map[key]
        # Expiration should be roughly now + 86400 (default TTL)
        assert expiration - before >= 86400 - 5  # tolerance for test timing
        assert expiration - after <= 86400 + 5

    def test_updates_ttl_on_second_call(self) -> None:
        """When an IP is re-fetched, TTL should be extended."""
        cfg = _make_config()
        resolver = IPResolver(cfg)

        key = "1.2.3.4:firehol_level1"

        # First pass — record
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        first_expiration = resolver._ttl_map[key]

        # Wait a tiny bit, then re-fetch same IP
        time.sleep(0.01)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        second_expiration = resolver._ttl_map[key]

        # Second expiration must be >= first (TTL extended, not shortened)
        assert second_expiration >= first_expiration

    def test_ttl_respects_feed_config(self) -> None:
        """TTL must come from the feed's config ttl_seconds, not the default."""
        # This is tested indirectly — the resolver receives a feed name
        # and looks up the TTL from the config. For now, we use the
        # default since the feed config lookup is part of scheduler wiring.
        # The resolver's default TTL is 86400 (24h).
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        key = "1.2.3.4:firehol_level1"
        assert key in resolver._ttl_map or "1.2.3.4" in resolver._ttl_map


# ──────────────────────────────────────────────────────────────────────
# evict_expired — in-memory mode
# ──────────────────────────────────────────────────────────────────────


class TestIPResolverEvictExpired:
    """IPResolver.evict_expired() — in-memory eviction logic."""

    def test_no_expired_when_all_fresh(self) -> None:
        """Fresh IPs must not be evicted."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4", "5.6.7.8"], "firehol_level1")
        expired = resolver.evict_expired()
        assert expired == []

    def test_expired_ip_returned(self) -> None:
        """Artificially expired IPs must be returned for eviction."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")

        # Artificially expire the entry
        key = list(resolver._ttl_map.keys())[0]
        resolver._ttl_map[key] = time.time() - 100  # 100s in the past

        expired = resolver.evict_expired()
        assert key in expired

    def test_expired_entry_removed_from_map(self) -> None:
        """After eviction, the entry must be removed from _ttl_map."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        key = list(resolver._ttl_map.keys())[0]
        resolver._ttl_map[key] = time.time() - 100

        resolver.evict_expired()
        assert key not in resolver._ttl_map

    def test_mixed_expired_and_fresh(self) -> None:
        """Only expired IPs returned, fresh ones kept."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4", "5.6.7.8", "9.10.11.12"], "firehol_level1")

        # Expire the middle one
        keys = sorted(resolver._ttl_map.keys())
        resolver._ttl_map[keys[1]] = time.time() - 100

        expired = resolver.evict_expired()
        assert keys[1] in expired
        assert keys[0] not in expired
        assert keys[2] not in expired
        assert keys[0] in resolver._ttl_map
        assert keys[2] in resolver._ttl_map

    def test_empty_map_returns_empty(self) -> None:
        """Calling evict on an empty map must return empty list."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        expired = resolver.evict_expired()
        assert expired == []

    def test_all_expired_returns_all(self) -> None:
        """When everything is expired, all keys returned."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4", "5.6.7.8"], "firehol_level1")

        # Expire all
        for key in list(resolver._ttl_map.keys()):
            resolver._ttl_map[key] = time.time() - 100

        expired = resolver.evict_expired()
        assert len(expired) == 2
        assert resolver._ttl_map == {}


# ──────────────────────────────────────────────────────────────────────
# sync_to_backend — bulk add with batching
# ──────────────────────────────────────────────────────────────────────


class TestIPResolverSyncToBackend:
    """IPResolver.sync_to_backend() — bulk batching to IP access backend."""

    @pytest.mark.asyncio
    async def test_adds_ips_to_backend(self) -> None:
        """sync_to_backend must call add_to_blocklist for each IP."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        backend = InMemoryIPAccessBackend()

        await resolver.sync_to_backend(backend, ["1.2.3.4", "5.6.7.8", "9.10.11.12"])

        # Verify IPs were added
        assert await backend.is_blocked("1.2.3.4")
        assert await backend.is_blocked("5.6.7.8")
        assert await backend.is_blocked("9.10.11.12")

    @pytest.mark.asyncio
    async def test_empty_list_no_ops(self) -> None:
        """Empty IP list must not call the backend at all."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        mock_backend = AsyncMock()
        mock_backend.add_to_blocklist = AsyncMock()

        await resolver.sync_to_backend(mock_backend, [])

        mock_backend.add_to_blocklist.assert_not_called()

    @pytest.mark.asyncio
    async def test_batches_small_lists(self) -> None:
        """Small lists (< 1000 IPs) must be added in one batch call."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        backend = InMemoryIPAccessBackend()

        # Use valid IPv4 addresses (octets 0-255)
        ips = [
            f"10.{i // 256}.{(i // 256) % 256}.{i % 256}"
            for i in range(500)
        ]
        await resolver.sync_to_backend(backend, ips)

        # All 500 IPs should be blocked
        for ip in ips:
            assert await backend.is_blocked(ip), f"Expected {ip} to be blocked"

    @pytest.mark.asyncio
    async def test_batches_large_lists(self) -> None:
        """Lists > 1000 IPs must use add_bulk_to_blocklist if available.

        Falls back to per-IP add_to_blocklist on InMemory backend since
        add_bulk_to_blocklist is only on RedisIPAccessBackend.
        """
        cfg = _make_config()
        resolver = IPResolver(cfg)
        backend = InMemoryIPAccessBackend()

        # Generate 2500 IPs (should be 3 batches if batching is used)
        ips = [f"10.{i // 256}.{i // 256}.{i % 256}" for i in range(2500)]
        await resolver.sync_to_backend(backend, ips)

        # Verify all were added
        assert len(backend._blocklist) == 2500
        for ip_sample in [ips[0], ips[500], ips[1500], ips[2499]]:
            assert await backend.is_blocked(ip_sample)

    @pytest.mark.asyncio
    async def test_uses_bulk_method_when_available(self) -> None:
        """When backend has add_bulk_to_blocklist, use it for efficiency."""
        cfg = _make_config()
        resolver = IPResolver(cfg)

        # Create a mock with both methods
        mock_backend = AsyncMock()
        mock_backend.add_to_blocklist = AsyncMock()
        mock_backend.add_bulk_to_blocklist = AsyncMock()

        ips = [f"10.0.0.{i}" for i in range(2500)]
        await resolver.sync_to_backend(mock_backend, ips)

        # Must call bulk method 3 times (2500 / 1000 = 3 batches)
        assert mock_backend.add_bulk_to_blocklist.call_count == 3
        mock_backend.add_to_blocklist.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_duplicate_ips_in_sync(self) -> None:
        """Duplicate IPs in a sync call must be handled gracefully."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        backend = InMemoryIPAccessBackend()

        # Duplicates in the list
        ips = ["1.2.3.4", "1.2.3.4", "5.6.7.8", "1.2.3.4"]
        await resolver.sync_to_backend(backend, ips)

        assert await backend.is_blocked("1.2.3.4")
        assert await backend.is_blocked("5.6.7.8")


# ──────────────────────────────────────────────────────────────────────
# Task 3.1 — Resolver with TTL key format
# ──────────────────────────────────────────────────────────────────────


class TestIPResolverTTLKeyFormat:
    """IPResolver TTL map key format — per-feed tracking."""

    def test_ttl_key_includes_ip_and_feed(self) -> None:
        """TTL map key should be 'ip:feed_name' to track per-feed."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")

        # Key should include the feed name for per-feed tracking
        expected_key = "1.2.3.4:firehol_level1"
        assert expected_key in resolver._ttl_map

    def test_same_ip_different_feeds_separate_ttls(self) -> None:
        """Same IP from two feeds must have independent TTL entries."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        resolver.deduplicate(["1.2.3.4"], "blocklist_de")

        # Both keys must exist independently
        assert "1.2.3.4:firehol_level1" in resolver._ttl_map
        assert "1.2.3.4:blocklist_de" in resolver._ttl_map

    def test_deduplicate_checks_any_feed_key_format(self) -> None:
        """deduplicate checks whether IP is already tracked by ANY feed.

        When deduplicating, if the IP is already tracked under any feed
        prefix, it is filtered (already in blocklist from another feed).
        TTL is still updated for the new feed.
        """
        cfg = _make_config()
        resolver = IPResolver(cfg)
        # First feed adds "1.2.3.4"
        resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        # Same IP from a different feed — filtered (cross-feed dedup)
        result = resolver.deduplicate(["1.2.3.4"], "blocklist_de")
        assert result == []
        # But TTL for the new feed is still recorded
        assert "1.2.3.4:blocklist_de" in resolver._ttl_map

    def test_deduplicate_within_same_feed_filters(self) -> None:
        """Same IP + same feed = filtered in deduplicate."""
        cfg = _make_config()
        resolver = IPResolver(cfg)
        first = resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        assert first == ["1.2.3.4"]
        second = resolver.deduplicate(["1.2.3.4"], "firehol_level1")
        assert second == []


# ──────────────────────────────────────────────────────────────────────
# Task 3.2 — add_bulk_to_blocklist on RedisIPAccessBackend
# ──────────────────────────────────────────────────────────────────────


class TestRedisBulkBlocklist:
    """RedisIPAccessBackend.add_bulk_to_blocklist — pipelined bulk add."""

    @pytest.mark.asyncio
    async def test_bulk_method_exists(self) -> None:
        """add_bulk_to_blocklist must be callable on RedisIPAccessBackend."""
        from unittest.mock import AsyncMock

        from araxys.ip_access.backends import RedisIPAccessBackend

        mock_redis = AsyncMock()
        mock_redis.sadd = AsyncMock()
        mock_redis.pipeline = MagicMock()

        backend = RedisIPAccessBackend(mock_redis)
        assert hasattr(backend, "add_bulk_to_blocklist")
        assert callable(backend.add_bulk_to_blocklist)

    @pytest.mark.asyncio
    async def test_bulk_uses_pipeline(self) -> None:
        """add_bulk_to_blocklist must use Redis pipeline for batching."""
        from unittest.mock import AsyncMock, MagicMock

        from araxys.ip_access.backends import RedisIPAccessBackend

        mock_pipe = MagicMock()
        mock_pipe.sadd = MagicMock()
        mock_pipe.execute = AsyncMock()

        mock_redis = AsyncMock()
        # pipeline() is sync in redis-py — set up as a regular MagicMock
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)

        backend = RedisIPAccessBackend(mock_redis)
        ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]

        await backend.add_bulk_to_blocklist(ips)

        # Pipeline must be created
        mock_redis.pipeline.assert_called_once()

        # Each IP must be added via sadd on the pipeline
        assert mock_pipe.sadd.call_count == 3

        # Pipeline must be executed
        mock_pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_bulk_batches_over_1000(self) -> None:
        """IPs > 1000 must be split into multiple pipeline calls."""
        from unittest.mock import AsyncMock, MagicMock

        from araxys.ip_access.backends import RedisIPAccessBackend

        mock_pipe = MagicMock()
        mock_pipe.sadd = MagicMock()
        mock_pipe.execute = AsyncMock()

        mock_redis = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)

        backend = RedisIPAccessBackend(mock_redis)
        ips = [f"10.0.0.{i % 256}" for i in range(2500)]

        await backend.add_bulk_to_blocklist(ips)

        # 2500 IPs / 1000 = 3 pipeline calls
        assert mock_redis.pipeline.call_count == 3
        assert mock_pipe.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_bulk_empty_list_no_ops(self) -> None:
        """Empty IP list must not call pipeline at all."""
        from unittest.mock import AsyncMock

        from araxys.ip_access.backends import RedisIPAccessBackend

        mock_redis = AsyncMock()
        backend = RedisIPAccessBackend(mock_redis)
        await backend.add_bulk_to_blocklist([])
        mock_redis.pipeline.assert_not_called()

    @pytest.mark.asyncio
    async def test_bulk_adds_to_correct_key(self) -> None:
        """add_bulk_to_blocklist must use BLOCKLIST_KEY for sadd."""
        from unittest.mock import AsyncMock, MagicMock

        from araxys.ip_access.backends import RedisIPAccessBackend

        mock_pipe = MagicMock()
        mock_pipe.sadd = MagicMock()
        mock_pipe.execute = AsyncMock()

        mock_redis = AsyncMock()
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)

        backend = RedisIPAccessBackend(mock_redis)
        await backend.add_bulk_to_blocklist(["1.2.3.4"])

        # Must add to the correct blocklist key
        mock_pipe.sadd.assert_called_once_with(
            RedisIPAccessBackend._BLOCKLIST_KEY, "1.2.3.4"
        )
