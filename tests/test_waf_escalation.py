"""Tests for WafEscalationSubscriber — multi-strike, dry-run, TTL, filtering."""  # noqa: E501

from __future__ import annotations

import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from araxys.core.config import WafEscalationConfig
from araxys.core.types import SecurityEvent, SecurityEventType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    event_type: SecurityEventType,
    source_ip: str | None = "1.2.3.4",
    severity: str = "warning",
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        message="test event",
        timestamp=datetime.now(UTC),
        source_ip=source_ip,
    )


# ---------------------------------------------------------------------------
# Task 4.1 — Construction and subscription
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberConstruction:
    """Subscriber must subscribe to the event bus on construction."""

    def test_importable_from_waf_package(self) -> None:
        """WafEscalationSubscriber must be importable from araxys.waf."""
        from araxys.waf import WafEscalationSubscriber

        assert WafEscalationSubscriber is not None

    def test_subscribes_to_event_bus_on_init(self) -> None:
        """On construction, the subscriber registers via event_bus.subscribe()."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        mock_bus.subscribe = MagicMock()
        config = WafEscalationConfig(enabled=True)

        sub = WafEscalationSubscriber(config, mock_bus)
        mock_bus.subscribe.assert_called_once_with(sub._on_event)


# ---------------------------------------------------------------------------
# Task 5.4 — Event type filtering
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberEventFiltering:
    """Subscriber must only count strikes for allowed event types."""

    def test_allowed_event_type_increments_counter(self) -> None:
        """An allowed event type increments the strike counter for the source IP."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            allowed_event_types=["rate_limit_exceeded"],
            multi_strike_count=3,
        )
        sub = WafEscalationSubscriber(config, mock_bus)

        # Access internal strikes dict to verify counting
        event = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4")

        import asyncio
        asyncio.run(sub._on_event(event))

        assert "1.2.3.4" in sub._strikes
        assert len(sub._strikes["1.2.3.4"]) == 1

    def test_filtered_event_type_is_ignored(self) -> None:
        """An event type NOT in allowed_event_types must be ignored."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            allowed_event_types=["rate_limit_exceeded"],
        )
        sub = WafEscalationSubscriber(config, mock_bus)

        event = _make_event(SecurityEventType.SANITIZE_BLOCKED, source_ip="1.2.3.4")

        import asyncio
        asyncio.run(sub._on_event(event))

        # SANITIZE_BLOCKED not in allowed list — no strike recorded
        assert "1.2.3.4" not in sub._strikes

    def test_event_without_source_ip_is_ignored(self) -> None:
        """Events without a source_ip must be skipped."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            allowed_event_types=["rate_limit_exceeded"],
        )
        sub = WafEscalationSubscriber(config, mock_bus)

        event = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip=None)

        import asyncio
        asyncio.run(sub._on_event(event))

        assert "1.2.3.4" not in sub._strikes


# ---------------------------------------------------------------------------
# Task 5.4 — Multi-strike threshold
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberMultiStrike:
    """Threshold met → escalate; not met → no escalation."""

    def test_threshold_not_met_no_escalation(self) -> None:
        """When strike count is below threshold, _escalate is NOT called."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            multi_strike_count=3,
            multi_strike_window_seconds=60,
        )
        sub = WafEscalationSubscriber(config, mock_bus)
        mock_escalate = AsyncMock()
        sub._escalate = mock_escalate  # type: ignore[method-assign]

        import asyncio

        # Send 2 events from same IP — below threshold of 3
        for _ in range(2):
            event = _make_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4",
            )
            asyncio.run(sub._on_event(event))

        mock_escalate.assert_not_called()
        assert len(sub._strikes.get("1.2.3.4", [])) == 2

    def test_threshold_met_triggers_escalation(self) -> None:
        """When strike count reaches threshold, _escalate IS called."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            multi_strike_count=3,
            multi_strike_window_seconds=60,
        )
        sub = WafEscalationSubscriber(config, mock_bus)
        mock_escalate = AsyncMock()
        sub._escalate = mock_escalate  # type: ignore[method-assign]

        import asyncio

        # Send 3 events from same IP — meets threshold
        for _ in range(3):
            event = _make_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4",
            )
            asyncio.run(sub._on_event(event))

        mock_escalate.assert_called_once()
        call_args = mock_escalate.call_args
        assert call_args[0][0] == "1.2.3.4"

    def test_different_ips_counted_separately(self) -> None:
        """Each IP has its own independent strike counter."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            multi_strike_count=3,
            multi_strike_window_seconds=60,
        )
        sub = WafEscalationSubscriber(config, mock_bus)

        import asyncio

        # IP A: 2 events (below threshold)
        for _ in range(2):
            event = _make_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="10.0.0.1",
            )
            asyncio.run(sub._on_event(event))

        # IP B: 3 events (meets threshold)
        for _ in range(3):
            event = _make_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="10.0.0.2",
            )
            asyncio.run(sub._on_event(event))

        assert len(sub._strikes.get("10.0.0.1", [])) == 2
        assert len(sub._strikes.get("10.0.0.2", [])) >= 3


# ---------------------------------------------------------------------------
# Task 5.4 — Dry-run mode
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberDryRun:
    """Dry-run logs, never calls AWS WAF API."""

    def test_dry_run_does_not_call_waf_client(self) -> None:
        """When dry_run is True, _escalate logs but does NOT call WafClient."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        mock_client = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            dry_run=True,
            multi_strike_count=1,
        )
        sub = WafEscalationSubscriber(config, mock_bus, waf_client=mock_client)

        import asyncio

        event = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4")
        asyncio.run(sub._on_event(event))

        # WafClient should not be called
        mock_client.update_ip_set.assert_not_called()
        mock_client.get_ip_set.assert_not_called()

    def test_non_dry_run_calls_waf_client(self) -> None:
        """When dry_run is False and threshold is met, WafClient IS called."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        mock_client = MagicMock()
        mock_client.get_ip_set = AsyncMock(return_value={
            "IPSet": {"Addresses": [], "LockToken": "lock-1"},
        })
        mock_client.update_ip_set = AsyncMock(return_value={"NextLockToken": "lock-2"})

        config = WafEscalationConfig(
            enabled=True,
            dry_run=False,
            multi_strike_count=1,
            ip_set_id="abc-123",
        )
        sub = WafEscalationSubscriber(config, mock_bus, waf_client=mock_client)

        import asyncio

        event = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4")
        asyncio.run(sub._on_event(event))

        # WafClient should be called
        mock_client.update_ip_set.assert_called_once()


# ---------------------------------------------------------------------------
# Task 5.4 — TTL eviction
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberTTLEviction:
    """Stale strikes beyond multi_strike_window_seconds must be evicted."""

    def test_stale_strikes_are_evicted(self) -> None:
        """Strikes older than the window are removed from the counter."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            multi_strike_count=3,
            multi_strike_window_seconds=1,  # Very short window
        )
        sub = WafEscalationSubscriber(config, mock_bus)
        mock_escalate = AsyncMock()
        sub._escalate = mock_escalate  # type: ignore[method-assign]

        import asyncio

        # Send 2 events
        for _ in range(2):
            event = _make_event(
                SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4",
            )
            asyncio.run(sub._on_event(event))

        assert len(sub._strikes["1.2.3.4"]) == 2

        # Simulate time passing by modifying timestamps to be old
        old_time = time.time() - 10  # 10 seconds ago, well past 1-second window
        sub._strikes["1.2.3.4"] = [old_time, old_time]

        # Send a 3rd event — stale strikes should be evicted first
        event3 = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4")
        asyncio.run(sub._on_event(event3))

        # After eviction, only the new strike remains — below threshold
        mock_escalate.assert_not_called()
        assert len(sub._strikes["1.2.3.4"]) == 1

    def test_fresh_strikes_persist(self) -> None:
        """Strikes within the window are kept."""
        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig(
            enabled=True,
            multi_strike_count=3,
            multi_strike_window_seconds=3600,  # Long window
        )
        sub = WafEscalationSubscriber(config, mock_bus)

        import asyncio

        event = _make_event(SecurityEventType.RATE_LIMIT_EXCEEDED, source_ip="1.2.3.4")
        asyncio.run(sub._on_event(event))

        # Single strike within a long window should persist
        assert len(sub._strikes["1.2.3.4"]) == 1


# ---------------------------------------------------------------------------
# Task 5.4 — Semaphore throttling
# ---------------------------------------------------------------------------


class TestWafEscalationSubscriberSemaphore:
    """AWS calls must be throttled via asyncio.Semaphore(1)."""

    def test_semaphore_is_created(self) -> None:
        """The subscriber must initialize an asyncio.Semaphore(1)."""
        import asyncio

        from araxys.waf.escalation import WafEscalationSubscriber

        mock_bus = MagicMock()
        config = WafEscalationConfig()
        sub = WafEscalationSubscriber(config, mock_bus)

        assert isinstance(sub._semaphore, asyncio.Semaphore)
