"""API Key manager — creation, verification, and revocation.

Keys are generated with ``secrets.token_urlsafe``, stored as SHA-256
hashes, and looked up by their 8-character prefix.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import typing
from datetime import UTC, datetime, timedelta
from typing import Literal

import structlog

from araxys.account_protection.helpers import simulate_hash_lookup
from araxys.api_keys.models import APIKeyRecord, APIKeyResponse
from araxys.core.exceptions import InvalidAPIKey
from araxys.core.types import AuditEntry, AuditEventType, Scope

if typing.TYPE_CHECKING:
    from araxys.api_keys.storage import APIKeyStorage
    from araxys.core.config import AccountProtectionConfig

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
        on_audit: typing.Callable | None = None,  # type: ignore
        protection_config: AccountProtectionConfig | None = None,
    ) -> None:
        self._storage = storage
        self._on_audit = on_audit
        self._protection_config = protection_config

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        """Compute SHA-256 hash of a raw API key."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def _ip_matches(ip: str, allowed: list[str]) -> bool:
        """Check if *ip* matches any CIDR or exact IP in *allowed*."""
        import ipaddress

        try:
            client = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in allowed:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                if ip == entry:
                    return True
                continue
            if client in net:
                return True
        return False

    async def create_key(
        self,
        owner: str,
        scopes: list[Scope] | None = None,
        ttl_days: int | None = None,
        label: str | None = None,
        key_type: Literal["secret", "public"] = "secret",
        allowed_ips: list[str] | None = None,
    ) -> APIKeyResponse:
        """Generate a new API key.

        Returns the raw key — this is the ONLY time it will be available.

        Parameters
        ----------
        key_type:
            ``"secret"`` keys (prefixed ``sk_``) have the configured scopes.
            ``"public"`` keys (prefixed ``pk_``) are read-only by default.
        """
        raw_random = secrets.token_urlsafe(self.KEY_BYTES)
        type_prefix = "sk_" if key_type == "secret" else "pk_"
        raw_key = f"{type_prefix}{raw_random}"
        prefix = raw_key[:8]
        key_hash = self._hash_key(raw_key)

        # Public keys get READ-only scopes unless explicitly overridden
        if key_type == "public" and scopes is None:
            scopes = [Scope.READ]

        expires_at = None
        if ttl_days is not None:
            expires_at = datetime.now(UTC) + timedelta(days=ttl_days)

        record = APIKeyRecord(
            key_hash=key_hash,
            prefix=prefix,
            scopes=scopes or [],
            expires_at=expires_at,
            owner=owner,
            label=label,
            key_type=key_type,
            allowed_ips=allowed_ips or [],
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
            key_type=key_type,
            scopes=record.scopes,
            expires_at=expires_at,
            owner=owner,
        )

    async def verify_key(
        self,
        raw_key: str,
        required_scopes: list[Scope] | None = None,
        client_ip: str | None = None,
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
            # When account protection is enabled, simulate hash lookup to
            # equalize timing with real key verification
            if (
                self._protection_config is not None
                and self._protection_config.enabled
            ):
                simulate_hash_lookup(prefix, self._protection_config)
            raise InvalidAPIKey("Invalid API key")

        # Verify hash (constant-time comparison to prevent timing attacks)
        if not hmac.compare_digest(record.key_hash, self._hash_key(raw_key)):
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
        if record.expires_at and record.expires_at < datetime.now(UTC):
            logger.warning("api_key.expired", prefix=prefix)
            raise InvalidAPIKey("Invalid API key")

        # Check scopes
        if required_scopes:
            missing = set(required_scopes) - set(record.scopes)
            if missing:
                logger.warning(
                    "api_key.insufficient_scopes",
                    prefix=prefix,
                    missing=list(missing),
                )
                raise InvalidAPIKey("Insufficient permissions")

        # Check IP restriction
        if (
            record.allowed_ips
            and client_ip
            and not self._ip_matches(client_ip, record.allowed_ips)
        ):
            logger.warning("api_key.ip_restricted", prefix=prefix, ip=client_ip)
            raise InvalidAPIKey("API key not allowed from this IP")

        if self._on_audit:
            await self._on_audit(
                AuditEntry(
                    event_type=AuditEventType.API_KEY_VERIFIED,
                    api_key_prefix=prefix,
                    detail=f"Key verified for {record.owner}",
                )
            )

        # Update last_used_at
        record = record.model_copy(
            update={"last_used_at": datetime.now(UTC)}
        )
        await self._storage.store(record)

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
