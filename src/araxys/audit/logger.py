from __future__ import annotations

"""Structured audit logger with optional AES-256-GCM encryption.

Logs security events using ``structlog`` for structured output.
When encryption is enabled, log entries are encrypted before being
written, ensuring that sensitive data at rest is protected.
"""


import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import structlog

from araxys.audit.encryption import AuditEncryption
from araxys.core.config import AuditConfig
from araxys.core.types import AuditEntry

logger = structlog.get_logger("araxys.audit")


class AuditLogger:
    """Structured audit logger with optional encryption.

    Parameters
    ----------
    config:
        Audit logging configuration.
    secret_key:
        Master secret key for encryption (required if config.encrypt is True).
    """

    def __init__(self, config: AuditConfig, secret_key: str | None = None) -> None:
        self._config = config
        self._encryption: AuditEncryption | None = None

        if config.encrypt:
            if not secret_key:
                raise ValueError(
                    "secret_key is required when audit encryption is enabled"
                )
            self._encryption = AuditEncryption(secret_key)

        self._log_file: Path | None = None
        if config.log_file:
            self._log_file = Path(config.log_file)
            self._log_file.parent.mkdir(parents=True, exist_ok=True)

    async def log(self, entry: AuditEntry) -> None:
        """Log an audit entry.

        The entry is:
        1. Logged via structlog (always)
        2. Encrypted if configured
        3. Written to file if configured
        """
        # Always log via structlog for observability
        logger.info(
            "audit.event",
            event_type=entry.event_type.value,
            ip=entry.ip_address,
            user_id=entry.user_id,
            api_key=entry.api_key_prefix,
            resource=entry.resource,
            action=entry.action,
            detail=entry.detail,
        )

        # Write to file if configured
        if self._log_file:
            await self._write_to_file(entry)

    async def _write_to_file(self, entry: AuditEntry) -> None:
        """Write an entry to the audit log file."""
        if self._encryption:
            line = self._encryption.encrypt_entry(entry)
        else:
            data = asdict(entry)
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
            line = json.dumps(data, default=str)

        # Append to file (one entry per line)
        assert self._log_file is not None
        with self._log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def read_entries(self) -> list[dict]:  # type: ignore
        """Read and decrypt all entries from the audit log file.

        Returns a list of dicts, one per logged entry.
        """
        if not self._log_file or not self._log_file.exists():
            return []

        entries = []
        with self._log_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if self._encryption:
                    entries.append(self._encryption.decrypt_entry(line))
                else:
                    entries.append(json.loads(line))

        return entries
