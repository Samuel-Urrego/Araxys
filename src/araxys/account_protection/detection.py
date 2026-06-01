"""EnumerationDetector — sliding-window 401 threshold tracker.

Tracks failed authentication attempts per IP using a configurable
sliding time window. When the number of failures from a single IP
exceeds the threshold within the window, the detector signals that
enumeration is likely in progress.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import AccountProtectionConfig


class EnumerationDetector:
    """Tracks 401 failure patterns per IP to detect enumeration attempts.

    Maintains an in-memory sliding window of timestamps per IP address.
    When the number of recorded failures exceeds ``threshold`` within
    ``window_seconds``, :meth:`record_failure` returns ``True``.

    Thread-safe via ``asyncio.Lock`` for concurrent async access.
    """

    def __init__(self, window_seconds: int = 60, threshold: int = 5) -> None:
        self._window_seconds = window_seconds
        self._threshold = threshold
        self._lock = asyncio.Lock()
        # ip -> list[monotonic timestamp]
        self._attempts: dict[str, list[float]] = {}

    @classmethod
    def from_config(cls, config: AccountProtectionConfig) -> EnumerationDetector:
        """Create a detector from an ``AccountProtectionConfig``.

        Reads ``enumeration_window_seconds`` and ``enumeration_threshold``
        from the config.
        """
        return cls(
            window_seconds=config.enumeration_window_seconds,
            threshold=config.enumeration_threshold,
        )

    async def record_failure(self, identifier: str, ip: str) -> bool:
        """Record an auth failure and check if the threshold is exceeded.

        Args:
            identifier: The user identifier that was used (username, email,
                API key prefix, etc.).  May be empty for anonymous failures.
            ip: The client IP address.

        Returns:
            ``True`` if the number of failures from this IP within the
            sliding window equals or exceeds ``threshold``.
        """
        now = time.monotonic()
        async with self._lock:
            timestamps = self._attempts.get(ip, [])
            # Prune expired entries
            timestamps = [t for t in timestamps if now - t < self._window_seconds]
            timestamps.append(now)
            self._attempts[ip] = timestamps
            return len(timestamps) >= self._threshold
