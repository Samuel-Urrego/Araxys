"""API Key manager — creation, verification, and revocation.

Keys are generated with ``secrets.token_urlsafe``, stored as SHA-256
hashes, and looked up by their 8-character prefix.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import structlog

from araxys.api_keys.models import APIKeyRecord, APIKeyResponse
from araxys.api_keys.storage import APIKeyStorage
from araxys.core.exceptions import InvalidAPIKey
from araxys.core.types import AuditEntry, AuditEventType, Scope

logger = structlog.get_logger("araxys.api_keys")


class APIKeyManager:
    """Manages the lifecycle of API keys.

    Parameters
    ----------
    storage:
        Backend for persisting API key records.
    on_audit:
        Optional callback to emit audit events.
    """

    KEY_BYTES = 32  # 256 bits of entropy

    def __init__(
        self,
        storage: APIKeyStorage,
        on_audit: callable | None = None,
    ) -> None:
        self._storage = storage
        self._on_audit = on_audit

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        """Compute SHA-256 hash of a raw API key."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    async def create_key(
        self,
        owner: str,
        scopes: list[Scope] | None = None,
        ttl_days: int | None = None,
        label: str | None = None,
    ) -> APIKeyResponse:
        """Generate a new API key.

        Returns the raw key — this is the ONLY time it will be available.
        """
        raw_key = secrets.token_urlsafe(self.KEY_BYTES)
        prefix = raw_key[:8]
        key_hash = self._hash_key(raw_key)

        expires_at = None
        if ttl_days is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=ttl_days)

        record = APIKeyRecord(
            key_hash=key_hash,
            prefix=prefix,
            scopes=scopes or [],
            expires_at=expires_at,
            owner=owner,
            label=label,
        )

        await self._storage.store(record)

        logger.info("api_key.created", prefix=prefix, owner=owner, scopes=scopes)

        if self._on_audit:
            await self._on_audit(
                AuditEntry(
                    event_type=AuditEventType.API_KEY_CREATED,
                    api_key_prefix=prefix,
                    detail=f"Key created for {owner} with scopes {scopes}",
                )
            )

        return APIKeyResponse(
            raw_key=raw_key,
            prefix=prefix,
            scopes=record.scopes,
            expires_at=expires_at,
            owner=owner,
        )

    async def verify_key(
        self,
        raw_key: str,
        required_scopes: list[Scope] | None = None,
    ) -> APIKeyRecord:
        """Verify a raw API key and check its scopes.

        Parameters
        ----------
        raw_key:
            The full API key provided by the client.
        required_scopes:
            Scopes that the key must have. If None, no scope check is performed.

        Raises
        ------
        InvalidAPIKey
            If the key is invalid, expired, revoked, or lacks required scopes.
        """
        prefix = raw_key[:8]
        record = await self._storage.get_by_prefix(prefix)

        if record is None:
            logger.warning("api_key.not_found", prefix=prefix)
            if self._on_audit:
                await self._on_audit(
                    AuditEntry(
                        event_type=AuditEventType.API_KEY_REJECTED,
                        api_key_prefix=prefix,
                        detail="Key not found",
                    )
                )
            raise InvalidAPIKey("API key not found or expired")

        # Verify hash
        if record.key_hash != self._hash_key(raw_key):
            logger.warning("api_key.hash_mismatch", prefix=prefix)
            if self._on_audit:
                await self._on_audit(
                    AuditEntry(
                        event_type=AuditEventType.API_KEY_REJECTED,
                        api_key_prefix=prefix,
                        detail="Hash mismatch",
                    )
                )
            raise InvalidAPIKey("Invalid API key")

        # Check expiration
        if record.expires_at and record.expires_at < datetime.now(timezone.utc):
            logger.warning("api_key.expired", prefix=prefix)
            raise InvalidAPIKey("API key has expired")

        # Check scopes
        if required_scopes:
            missing = set(required_scopes) - set(record.scopes)
            if missing:
                logger.warning(
                    "api_key.insufficient_scopes",
                    prefix=prefix,
                    missing=list(missing),
                )
                raise InvalidAPIKey(f"Missing required scopes: {', '.join(missing)}")

        if self._on_audit:
            await self._on_audit(
                AuditEntry(
                    event_type=AuditEventType.API_KEY_VERIFIED,
                    api_key_prefix=prefix,
                    detail=f"Key verified for {record.owner}",
                )
            )

        return record

    async def revoke_key(self, prefix: str) -> bool:
        """Revoke an API key by its prefix.

        Returns True if the key was found and revoked.
        """
        success = await self._storage.revoke(prefix)
        if success:
            logger.info("api_key.revoked", prefix=prefix)
            if self._on_audit:
                await self._on_audit(
                    AuditEntry(
                        event_type=AuditEventType.API_KEY_REVOKED,
                        api_key_prefix=prefix,
                    )
                )
        return success

    async def list_keys(self, owner: str | None = None) -> list[APIKeyRecord]:
        """List active API keys, optionally filtered by owner."""
        return await self._storage.list_keys(owner)
