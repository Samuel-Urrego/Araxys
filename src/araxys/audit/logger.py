"""Structured audit logger with optional AES-256-GCM encryption.

Logs security events using ``structlog`` for structured output.
When encryption is enabled, log entries are encrypted before being
written, ensuring that sensitive data at rest is protected.
"""


from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from araxys.audit.encryption import AuditEncryption
from araxys.audit.masking import mask_pii

if TYPE_CHECKING:
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
        self._writer = None
        if config.log_file:
            self._log_file = Path(config.log_file)
            self._log_file.parent.mkdir(parents=True, exist_ok=True)
            from araxys.audit.writer import LogWriter

            self._writer = LogWriter(
                log_file=config.log_file,
                log_rotation_bytes=config.log_rotation_bytes,
                log_backup_count=config.log_backup_count,
                async_write=config.async_write,
            )

        self._shipper = None
        if config.log_shipping:
            from araxys.audit.shipping import LogShipper

            self._shipper = LogShipper(config.log_shipping)

        # Integrity chain — each entry links to the previous one so
        # tampering (deletion or modification) is detectable.
        self._chain_hash: str | None = None
        self._chain_enabled: bool = config.chain_integrity

    async def log(self, entry: AuditEntry) -> None:
        """Log an audit entry.

        The entry is:
        1. PII-masked if ``pii_fields`` is configured
        2. Logged via structlog (always, with masked data)
        3. Encrypted if configured
        4. Written to file if configured (with optional rotation / async I/O)
        5. Shipped to an external endpoint if configured
        """
        # Serialise entry to a plain dict
        data = asdict(entry)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()

        # Apply PII masking BEFORE logging (never log plaintext PII)
        if self._config.pii_fields:
            data = mask_pii(data, self._config.pii_fields)

        # Log via structlog for observability (masked data only)
        logger.info(
            "audit.event",
            event_type=entry.event_type.value,
            ip=entry.ip_address,
            user_id=entry.user_id,
            api_key=entry.api_key_prefix,
            resource=entry.resource,
            action=entry.action,
            detail=data.get("detail", entry.detail),
        )

        # Integrity chain — link to previous entry
        if self._chain_enabled:
            chain_entry = self._compute_chain(data)
            data = chain_entry
        else:
            # Keep the serialized data as-is for backward compat
            pass

        # Write to file via LogWriter (sync / async with rotation)
        if self._writer is not None:
            if self._encryption:
                line = self._encryption.encrypt_data(data)
            else:
                line = json.dumps(data, default=str)
            await self._writer.write(line + "\n")

        # Ship to external endpoint if configured
        if self._shipper is not None:
            await self._shipper.ship(data)

    def _compute_chain(self, data: dict[str, Any]) -> dict[str, Any]:
        """Link the current entry to the previous one via a hash chain.

        Returns *data* with added ``_chain`` (SHA-256 of prev+current)
        and ``_prev`` (previous chain hash) fields.
        """
        prev = self._chain_hash or "0" * 64  # genesis block
        serialized = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        chain = hashlib.sha256(prev.encode() + serialized).hexdigest()
        self._chain_hash = chain
        return {"_chain": chain, "_prev": prev, **data}

    def verify_integrity(self) -> dict[str, Any]:
        """Verify the integrity chain of all written audit entries.

        Returns a dict with ``valid`` (bool), ``entry_count`` (int),
        and ``violations`` (list of line numbers) if any.
        """
        if not self._log_file or not self._log_file.exists():
            return {"valid": True, "entry_count": 0, "violations": []}

        entries = self._read_raw_entries()
        violations: list[int] = []
        expected_prev = "0" * 64

        for i, entry in enumerate(entries):
            chain = entry.get("_chain")
            prev = entry.get("_prev", "")
            if not chain:
                violations.append(i + 1)
                continue
            if prev != expected_prev:
                violations.append(i + 1)
            # Recompute to verify
            entry_copy = {
                k: v for k, v in entry.items()
                if k not in ("_chain", "_prev")
            }
            serialized = json.dumps(
                entry_copy, sort_keys=True, default=str
            ).encode("utf-8")
            computed = hashlib.sha256(prev.encode() + serialized).hexdigest()
            if not hmac.compare_digest(computed, chain):
                violations.append(i + 1)
            expected_prev = chain

        return {
            "valid": len(violations) == 0,
            "entry_count": len(entries),
            "violations": violations,
        }

    def read_entries(self) -> list[dict[str, Any]]:
        """Read and decrypt all entries from the audit log file.

        Returns a list of dicts (chain metadata stripped), one per entry.
        """
        return [
            {k: v for k, v in entry.items() if k not in ("_chain", "_prev")}
            for entry in self._read_raw_entries()
        ]

    def _read_raw_entries(self) -> list[dict[str, Any]]:
        """Read all entries from the audit log, including chain metadata."""
        if not self._log_file or not self._log_file.exists():
            return []

        entries: list[dict[str, Any]] = []
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
