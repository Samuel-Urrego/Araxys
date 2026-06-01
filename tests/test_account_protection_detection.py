"""Tests for EnumerationDetector — sliding-window 401 threshold tracker."""

from __future__ import annotations

import asyncio

from araxys.account_protection.detection import EnumerationDetector
from araxys.core.config import AccountProtectionConfig


def _make_config(**kwargs: object) -> AccountProtectionConfig:
    """Create an AccountProtectionConfig with the given overrides."""
    return AccountProtectionConfig(**kwargs)  # type: ignore[arg-type]


class TestEnumerationDetectorBasics:
    """Core behavior: threshold tracking and window expiry."""

    async def test_below_threshold_returns_false(self) -> None:
        """Fewer failures than the threshold should return False."""
        detector = EnumerationDetector(
            window_seconds=60, threshold=5
        )
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is False

    async def test_at_threshold_returns_true(self) -> None:
        """Exactly threshold failures should return True."""
        detector = EnumerationDetector(window_seconds=60, threshold=3)
        await detector.record_failure("alice", "10.0.0.1")
        await detector.record_failure("alice", "10.0.0.1")
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is True

    async def test_above_threshold_returns_true(self) -> None:
        """More than threshold failures should also return True."""
        detector = EnumerationDetector(window_seconds=60, threshold=3)
        for _ in range(5):
            await detector.record_failure("alice", "10.0.0.1")
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is True

    async def test_window_expiry_resets_count(self) -> None:
        """Failures outside the sliding window should not count."""
        detector = EnumerationDetector(window_seconds=1, threshold=2)
        # Record first failure, let it expire
        await detector.record_failure("alice", "10.0.0.1")
        await asyncio.sleep(1.1)
        # Only 1 within window now
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is False

    async def test_mixed_expired_and_fresh_entries(self) -> None:
        """Expired entries discarded, fresh ones counted correctly."""
        detector = EnumerationDetector(window_seconds=1, threshold=2)
        await detector.record_failure("alice", "10.0.0.1")  # will expire
        await asyncio.sleep(1.1)
        await detector.record_failure("alice", "10.0.0.1")  # fresh
        result = await detector.record_failure("alice", "10.0.0.1")  # fresh
        assert result is True  # 2 fresh within window


class TestEnumerationDetectorIsolation:
    """Different IPs and identifiers must be tracked independently."""

    async def test_different_ips_isolated(self) -> None:
        """Different IPs should have independent counters."""
        config = _make_config(enumeration_threshold=3, enumeration_window_seconds=60)
        detector = EnumerationDetector.from_config(config)
        for _ in range(3):
            await detector.record_failure("alice", "10.0.0.1")
        # Different IP, only 1 attempt
        result = await detector.record_failure("bob", "10.0.0.2")
        assert result is False

    async def test_identifiers_same_ip_accumulate(self) -> None:
        """Different identifiers from the same IP accumulate toward threshold."""
        config = _make_config(enumeration_threshold=3, enumeration_window_seconds=60)
        detector = EnumerationDetector.from_config(config)
        await detector.record_failure("alice", "10.0.0.1")
        await detector.record_failure("bob", "10.0.0.1")
        result = await detector.record_failure("charlie", "10.0.0.1")
        assert result is True

    async def test_no_identifier_still_counts(self) -> None:
        """record_failure with empty identifier still accumulates."""
        detector = EnumerationDetector(window_seconds=60, threshold=3)
        await detector.record_failure("", "10.0.0.1")
        await detector.record_failure("", "10.0.0.1")
        result = await detector.record_failure("", "10.0.0.1")
        assert result is True

    async def test_multiple_ips_independent_thresholds(self) -> None:
        """Multiple IPs each at separate thresholds."""
        detector = EnumerationDetector(window_seconds=60, threshold=3)
        # IP 1: 3 failures → detected
        for _ in range(3):
            await detector.record_failure("alice", "10.0.0.1")
        # IP 2: 2 failures → not detected
        for _ in range(2):
            await detector.record_failure("bob", "10.0.0.2")
        # IP 3: 1 failure → not detected
        await detector.record_failure("charlie", "10.0.0.3")

        result1 = await detector.record_failure("alice", "10.0.0.1")
        result2 = await detector.record_failure("bob", "10.0.0.2")
        result3 = await detector.record_failure("charlie", "10.0.0.3")
        assert result1 is True   # IP 1: 4 > threshold
        assert result2 is True   # IP 2: 3 >= threshold
        assert result3 is False  # IP 3: 2 < threshold


class TestEnumerationDetectorThreadSafety:
    """Concurrent access must be safe under asyncio."""

    async def test_concurrent_recordings_same_ip(self) -> None:
        """Multiple concurrent calls for the same IP must not corrupt state."""
        config = _make_config(enumeration_threshold=30, enumeration_window_seconds=60)
        detector = EnumerationDetector.from_config(config)

        async def record_ten() -> None:
            for _ in range(10):
                await detector.record_failure("alice", "10.0.0.1")

        await asyncio.gather(record_ten(), record_ten(), record_ten())

        # 3 tasks × 10 records each = 30 total
        # Trigger another record to check the lock didn't lose updates
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is True  # 31 >= 30 ✓

    async def test_concurrent_recordings_diff_ips(self) -> None:
        """Multiple IPs recorded concurrently should not interfere."""
        detector = EnumerationDetector(window_seconds=60, threshold=15)

        async def record_ip(ip: str) -> None:
            for _ in range(10):
                await detector.record_failure(ip, ip)

        await asyncio.gather(
            record_ip("10.0.0.1"),
            record_ip("10.0.0.2"),
            record_ip("10.0.0.3"),
        )

        # Each IP has exactly 10 failures (< threshold)
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            result = await detector.record_failure("test", ip)
            assert result is False  # 11 < 15

    async def test_concurrent_recording_preserves_count(self) -> None:
        """Total count after concurrent records must equal expected sum."""
        detector = EnumerationDetector(window_seconds=60, threshold=50)
        n_tasks = 5
        n_per_task = 10

        async def record_many() -> None:
            for _ in range(n_per_task):
                await detector.record_failure("alice", "10.0.0.1")

        await asyncio.gather(*[record_many() for _ in range(n_tasks)])

        # Total: 5 * 10 = 50, which is >= threshold
        result = await detector.record_failure("alice", "10.0.0.1")
        assert result is True


class TestEnumerationDetectorFromConfig:
    """Construction via from_config() or direct params."""

    def test_from_config_uses_enumeration_settings(self) -> None:
        """from_config should read enumeration_window and threshold from config."""
        config = _make_config(
            enumeration_window_seconds=120,
            enumeration_threshold=10,
        )
        detector = EnumerationDetector.from_config(config)
        assert detector._window_seconds == 120  # noqa: SLF001
        assert detector._threshold == 10  # noqa: SLF001

    def test_direct_params(self) -> None:
        """Direct constructor should use passed values."""
        detector = EnumerationDetector(window_seconds=300, threshold=20)
        assert detector._window_seconds == 300  # noqa: SLF001
        assert detector._threshold == 20  # noqa: SLF001
