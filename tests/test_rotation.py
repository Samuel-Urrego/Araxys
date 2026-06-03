"""Tests for dynamic secrets rotation scheduler (v0.14).

Covers SecretsRotationScheduler lifecycle, rotation loop, error handling,
on-demand rotation, and stats.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest

from araxys.core.config import (
    SecretsRotationConfig,
)
from araxys.core.types import SecurityEventType
from araxys.db_security.manager import DatabaseSecurityManager
from araxys.db_security.pool import ConnectionPool

# =============================================================================
# Task 3.2 — Scheduler lifecycle tests (RED)
# =============================================================================


class TestSchedulerLifecycle:
    """SecretsRotationScheduler start/stop lifecycle."""

    @pytest.fixture
    def config(self) -> SecretsRotationConfig:
        return SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis"],
            fail_closed=False,
            emit_events=True,
        )

    @pytest.fixture
    def manager(self) -> MagicMock:
        mgr = MagicMock(spec=DatabaseSecurityManager)
        mgr.pool = MagicMock(spec=ConnectionPool)
        mgr.rotate_target = AsyncMock()
        # resolver property mock
        type(mgr).resolver = PropertyMock(return_value=AsyncMock())
        return mgr

    @pytest.fixture
    def event_bus(self) -> AsyncMock:
        return AsyncMock()

    # ── 3.2 test_scheduler_start_creates_task ─────────────────────────

    async def test_scheduler_start_creates_task(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """start() creates a background asyncio.Task for _run()."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(),
            config=config,
            event_bus=event_bus,
        )
        assert scheduler._task is None

        scheduler.start()
        assert scheduler._task is not None
        assert isinstance(scheduler._task, asyncio.Task)
        assert not scheduler._task.done()

        # Cleanup
        scheduler.stop()
        await asyncio.sleep(0.05)  # let cancellation propagate

    # ── 3.2 test_scheduler_stop_cancels_task ──────────────────────────

    async def test_scheduler_stop_cancels_task(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """stop() cancels the background task and waits for it."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(),
            config=config,
            event_bus=event_bus,
        )
        scheduler.start()
        assert scheduler._task is not None

        scheduler.stop()
        # After stop(), the task should be done (possibly cancelled)
        await asyncio.sleep(0.05)
        assert scheduler._task.done()
        # Either it completed cleanly or was cancelled — both are fine
        assert scheduler._task.cancelled() or scheduler._task.done()

    # ── 3.2 test_rotate_on_startup_fires_immediately ──────────────────

    async def test_rotate_on_startup_fires_immediately(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """On start(), the scheduler fires rotation immediately (not after
        the full interval)."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "redis://new:6379"
        type(manager).resolver = PropertyMock(return_value=resolver_mock)

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=config,
            event_bus=event_bus,
        )

        scheduler.start()
        # Give the async task a moment to run the first rotation
        await asyncio.sleep(0.1)

        # The scheduler should have attempted to rotate
        # We check that rotate_target was called at least once
        manager.rotate_target.assert_called()
        # And the event bus should have received at least SECRET_ROTATING
        event_bus.emit.assert_called()

        scheduler.stop()
        await asyncio.sleep(0.05)

    # ── 3.2 test_sleep_cancel_check_exits_on_stop ─────────────────────

    async def test_sleep_cancel_check_exits_on_stop(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """_sleep_with_cancel_check() exits early when stop() is called
        during sleep."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = None  # unchanged — skip rotation

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=SecretsRotationConfig(
                enabled=True,
                interval_seconds=999,  # long interval so we can interrupt
                targets=["redis"],
            ),
            event_bus=event_bus,
        )

        scheduler.start()
        await asyncio.sleep(0.05)  # let it start and enter sleep

        start_time = time.monotonic()
        scheduler.stop()
        elapsed = time.monotonic() - start_time

        # Should exit quickly, not wait 999 seconds
        assert elapsed < 2.0, f"stop() took {elapsed:.1f}s (expected < 2s)"
        await asyncio.sleep(0.02)


# =============================================================================
# Task 3.4 — Rotation loop behavior tests (RED)
# =============================================================================


class TestRotationLoop:
    """_run() rotation loop — credential comparison, error handling."""

    @pytest.fixture
    def config(self) -> SecretsRotationConfig:
        return SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis"],
            fail_closed=False,
            emit_events=True,
        )

    @pytest.fixture
    def manager(self) -> MagicMock:
        mgr = MagicMock(spec=DatabaseSecurityManager)
        mgr.rotate_target = AsyncMock()
        return mgr

    @pytest.fixture
    def event_bus(self) -> AsyncMock:
        return AsyncMock()

    # ── 3.4 test_credential_unchanged_skips_rotation ──────────────────

    async def test_credential_unchanged_skips_rotation(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """When the resolved credential matches the current value,
        rotate_target is NOT called."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = None

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=config,
            event_bus=event_bus,
        )

        scheduler.start()
        await asyncio.sleep(0.1)

        # No rotation should have happened — credential unchanged
        manager.rotate_target.assert_not_called()

        scheduler.stop()
        await asyncio.sleep(0.05)

    # ── 3.4 test_fail_soft_emits_event_and_continues ──────────────────

    async def test_fail_soft_emits_event_and_continues(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """When rotation fails (fail_closed=False), the scheduler emits
        SECRET_ROTATION_FAILED and continues to the next target."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "redis://new:6379"
        manager.rotate_target = AsyncMock(side_effect=RuntimeError("Boom"))

        multi_config = SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis", "postgres"],
            fail_closed=False,
            emit_events=True,
        )

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=multi_config,
            event_bus=event_bus,
        )

        scheduler.start()
        await asyncio.sleep(0.15)

        # Both targets should have been attempted
        assert manager.rotate_target.call_count == 2

        # A SECRET_ROTATION_FAILED event should have been emitted
        fail_events = [
            call for call in event_bus.emit.call_args_list
            if call[0][0].event_type == SecurityEventType.SECRET_ROTATION_FAILED
        ]
        assert len(fail_events) >= 1, (
            "Expected at least one SECRET_ROTATION_FAILED event"
        )

        # The scheduler should still be running (not crashed)
        assert scheduler._task is not None
        assert not scheduler._task.done()

        scheduler.stop()
        await asyncio.sleep(0.05)

    # ── 3.4 test_fail_closed_stops_scheduler ──────────────────────────

    async def test_fail_closed_stops_scheduler(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """When fail_closed=True and rotation fails, the scheduler stops."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "redis://new:6379"
        manager.rotate_target = AsyncMock(side_effect=RuntimeError("Fatal"))

        fail_closed_config = SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis"],
            fail_closed=True,
            emit_events=True,
        )

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=fail_closed_config,
            event_bus=event_bus,
        )

        scheduler.start()
        await asyncio.sleep(0.15)

        # The task should be done (stopped by fail_closed)
        assert scheduler._task is not None
        assert scheduler._task.done() or scheduler._task.cancelled()

        # A SECRET_ROTATION_FAILED event should have been emitted
        fail_events = [
            call for call in event_bus.emit.call_args_list
            if call[0][0].event_type == SecurityEventType.SECRET_ROTATION_FAILED
        ]
        assert len(fail_events) >= 1

        scheduler.stop()
        await asyncio.sleep(0.02)


# =============================================================================
# Task 3.9 — rotate_targets and stats (RED)
# =============================================================================


class TestRotateTargetsAndStats:
    """On-demand rotation (rotate_targets) and per-target stats."""

    @pytest.fixture
    def config(self) -> SecretsRotationConfig:
        return SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis", "postgres"],
            fail_closed=False,
            emit_events=True,
        )

    @pytest.fixture
    def manager(self) -> MagicMock:
        mgr = MagicMock(spec=DatabaseSecurityManager)
        mgr.rotate_target = AsyncMock()
        # resolver property
        type(mgr).resolver = PropertyMock(return_value=AsyncMock())
        return mgr

    @pytest.fixture
    def event_bus(self) -> AsyncMock:
        return AsyncMock()

    # ── 3.9 test_rotate_targets_specific_target ───────────────────────

    async def test_rotate_targets_specific_target(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """rotate_targets(['redis']) only rotates the specified target,
        not all targets in the config."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "redis://rotated:6379"

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=config,
            event_bus=event_bus,
        )

        await scheduler.rotate_targets(["redis"])

        # Only 'redis' should have been passed to rotate_target
        manager.rotate_target.assert_called_with("redis")
        assert manager.rotate_target.call_count == 1

    # ── 3.9 test_stats_tracks_success_and_failure ────────────────────

    async def test_stats_tracks_success_and_failure(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """stats() returns per-target timing and status information."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "redis://rotated:6379"

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=config,
            event_bus=event_bus,
        )

        # Successful rotation
        await scheduler.rotate_targets(["redis"])

        stats = scheduler.stats()
        assert "redis" in stats
        assert stats["redis"]["last_success"] is not None
        assert stats["redis"]["last_error"] is None

        # Failed rotation
        manager.rotate_target = AsyncMock(
            side_effect=RuntimeError("Rotation failed"),
        )
        await scheduler.rotate_targets(["postgres"])

        stats = scheduler.stats()
        assert "postgres" in stats
        assert stats["postgres"]["last_success"] is None
        assert stats["postgres"]["last_error"] is not None


# =============================================================================
# Task 3.10 — Error isolation (REFACTOR verify)
# =============================================================================


class TestErrorIsolation:
    """One target failure must not block other targets."""

    @pytest.fixture
    def config(self) -> SecretsRotationConfig:
        return SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis", "postgres", "vault"],
            fail_closed=False,
            emit_events=True,
        )

    @pytest.fixture
    def manager(self) -> MagicMock:
        mgr = MagicMock(spec=DatabaseSecurityManager)
        async def rotate(target: str) -> None:
            if target == "redis":
                raise RuntimeError("Redis rotation failed")
            # postgres and vault succeed silently
        mgr.rotate_target = AsyncMock(side_effect=rotate)
        type(mgr).resolver = PropertyMock(return_value=AsyncMock())
        return mgr

    @pytest.fixture
    def event_bus(self) -> AsyncMock:
        return AsyncMock()

    async def test_failure_does_not_block_other_targets(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """When one target fails (redis), the scheduler continues and
        processes the remaining targets (postgres, vault)."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        resolver_mock = AsyncMock()
        resolver_mock.resolve.return_value = "new://value"

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=resolver_mock,
            config=config,
            event_bus=event_bus,
        )

        await scheduler.rotate_targets(["redis", "postgres", "vault"])

        # All three targets should have been attempted
        assert manager.rotate_target.call_count == 3

        # Check that postgres and vault were called after redis failure
        calls = [call[0][0] for call in manager.rotate_target.call_args_list]
        assert "redis" in calls
        assert "postgres" in calls
        assert "vault" in calls


# =============================================================================
# TRIANGULATE — Additional test cases
# =============================================================================


class TestSchedulerTriangulation:
    """Additional test cases to triangulate logic."""

    @pytest.fixture
    def config(self) -> SecretsRotationConfig:
        return SecretsRotationConfig(
            enabled=True,
            interval_seconds=30,
            targets=["redis", "postgres"],
            fail_closed=False,
            emit_events=True,
        )

    @pytest.fixture
    def manager(self) -> MagicMock:
        mgr = MagicMock(spec=DatabaseSecurityManager)
        mgr.rotate_target = AsyncMock()
        type(mgr).resolver = PropertyMock(return_value=AsyncMock())
        return mgr

    @pytest.fixture
    def event_bus(self) -> AsyncMock:
        return AsyncMock()

    async def test_stats_initialized_for_all_targets(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """Stats dict is pre-populated with zeros/nulls for all configured
        targets on init."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(),
            config=config,
            event_bus=event_bus,
        )

        stats = scheduler.stats()
        assert "redis" in stats
        assert "postgres" in stats
        assert stats["redis"]["last_success"] is None
        assert stats["redis"]["last_error"] is None
        assert stats["redis"]["last_rotated"] is None
        assert stats["redis"]["rotations"] == 0
        assert stats["redis"]["failures"] == 0

    async def test_rotate_targets_multiple_targets(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """rotate_targets with multiple targets calls rotate_target for
        each one."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(return_value="new://url"),
            config=config,
            event_bus=event_bus,
        )

        await scheduler.rotate_targets(["redis", "postgres"])

        assert manager.rotate_target.call_count == 2
        calls = [call[0][0] for call in manager.rotate_target.call_args_list]
        assert calls == ["redis", "postgres"]

    async def test_no_event_bus_does_not_crash(
        self, manager: MagicMock, config: SecretsRotationConfig,
    ) -> None:
        """Scheduler works correctly when no event bus is provided."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(return_value="new://url"),
            config=config,
            event_bus=None,
        )

        # Should not raise
        await scheduler.rotate_targets(["redis"])
        manager.rotate_target.assert_called_with("redis")

    async def test_emits_rotating_event(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """SECRET_ROTATING event is emitted before the rotation attempt."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(return_value="new://url"),
            config=config,
            event_bus=event_bus,
        )

        await scheduler.rotate_targets(["redis"])

        # Find the SECRET_ROTATING event
        rotating_events = [
            call for call in event_bus.emit.call_args_list
            if call[0][0].event_type == SecurityEventType.SECRET_ROTATING
        ]
        assert len(rotating_events) == 1
        assert rotating_events[0][0][0].message == "Starting rotation for 'redis'"

    async def test_stats_independent_copy(
        self, manager: MagicMock, config: SecretsRotationConfig,
        event_bus: AsyncMock,
    ) -> None:
        """stats() returns a copy — mutating the returned dict does not
        affect the internal stats."""
        from araxys.db_security.rotation import SecretsRotationScheduler

        scheduler = SecretsRotationScheduler(
            manager=manager,
            resolver=AsyncMock(return_value="new://url"),
            config=config,
            event_bus=event_bus,
        )

        await scheduler.rotate_targets(["redis"])
        stats1 = scheduler.stats()
        # Mutate the returned dict
        stats1["redis"]["rotations"] = 999
        # Internal stats should be unaffected
        stats2 = scheduler.stats()
        assert stats2["redis"]["rotations"] == 1
        assert stats1["redis"]["rotations"] == 999
