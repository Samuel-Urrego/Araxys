"""File writer with optional async I/O and log rotation.

Provides a ``LogWriter`` that handles writing audit log entries to
disk, with support for:

- Synchronous or asynchronous (``aiofiles``) writes
- Size-based log file rotation
- Configurable backup count
"""

from __future__ import annotations

import asyncio
from pathlib import Path

_HAS_AIOFILES = True
try:
    import aiofiles  # noqa: F401
except ImportError:
    _HAS_AIOFILES = False


class LogWriter:
    """Thread-safe file writer with optional async I/O and log rotation.

    Parameters
    ----------
    log_file:
        Path to the audit log file.
    log_rotation_bytes:
        Maximum file size in bytes before rotation (0 = disabled).
    log_backup_count:
        Number of rotated backup files to keep.
    async_write:
        If True, use ``aiofiles`` for non-blocking writes. Falls back
        to synchronous writes if ``aiofiles`` is not installed.
    """

    def __init__(
        self,
        log_file: str,
        log_rotation_bytes: int = 0,
        log_backup_count: int = 5,
        async_write: bool = False,
    ) -> None:
        self._log_file = Path(log_file)
        self._log_rotation_bytes = log_rotation_bytes
        self._log_backup_count = log_backup_count
        self._async = async_write and _HAS_AIOFILES
        self._lock = asyncio.Lock()

        self._log_file.parent.mkdir(parents=True, exist_ok=True)

    async def write(self, line: str) -> None:
        """Write *line* to the log file, rotating if needed."""
        if self._async:
            await self._write_async(line)
        else:
            await self._write_sync(line)

    async def flush(self) -> None:
        """No-op — writes are unbuffered (immediate)."""
        pass  # Each write() call opens/closes the file immediately

    def close(self) -> None:
        """Cleanup resources. Currently a no-op."""
        pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _write_sync(self, line: str) -> None:
        async with self._lock:
            self._rotate_if_needed()
            with self._log_file.open("a", encoding="utf-8") as f:
                f.write(line)

    async def _write_async(self, line: str) -> None:
        async with self._lock:
            self._rotate_if_needed()
            async with aiofiles.open(
                self._log_file, "a", encoding="utf-8"
            ) as f:
                await f.write(line)

    def _rotate_if_needed(self) -> None:
        """Rotate the log file if it exceeds the size threshold."""
        if self._log_rotation_bytes <= 0:
            return
        if not self._log_file.exists():
            return
        if self._log_file.stat().st_size < self._log_rotation_bytes:
            return

        # Remove the oldest backup if it exists
        oldest = self._backup_path(self._log_backup_count)
        if oldest.exists():
            oldest.unlink()

        # Shift existing backups down (e.g. .1 → .2, .2 → .3, …)
        for i in range(self._log_backup_count - 1, 0, -1):
            src = self._backup_path(i)
            if src.exists():
                dst = self._backup_path(i + 1)
                src.rename(dst)

        # Rename current log → .1
        first_backup = self._backup_path(1)
        self._log_file.rename(first_backup)

    def _backup_path(self, index: int) -> Path:
        """Return the path for a backup file at the given *index*."""
        return self._log_file.with_suffix(f".log.{index}")
