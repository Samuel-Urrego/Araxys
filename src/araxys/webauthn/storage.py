"""Credential storage backends for WebAuthn.

Provides a ``CredentialStore`` protocol and both in-memory and Redis
implementations for persisting WebAuthn credential records.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from araxys.webauthn.models import CredentialRecord


@runtime_checkable
class CredentialStore(Protocol):
    """Protocol for storing and retrieving WebAuthn credentials.

    Implementations must handle persistence of ``CredentialRecord``
    objects keyed by ``credential_id``.
    """

    async def save(self, record: CredentialRecord) -> None:
        """Persist a credential record.

        If a credential with the same ``credential_id`` already exists
        it SHOULD be replaced.
        """
        ...

    async def get(self, credential_id: bytes) -> CredentialRecord | None:
        """Retrieve a credential by its ID, or ``None`` if not found."""
        ...

    async def list_by_user(self, user_id: str) -> list[CredentialRecord]:
        """List all credentials belonging to the given user."""
        ...

    async def update_sign_count(
        self, credential_id: bytes, count: int
    ) -> None:
        """Update the sign count for a specific credential."""
        ...


class InMemoryCredentialStore:
    """In-memory implementation of ``CredentialStore``.

    .. warning::
        Not suitable for multi-worker deployments. Each worker has
        its own independent store.
    """

    def __init__(self) -> None:
        self._creds: dict[bytes, CredentialRecord] = {}
        self._user_index: dict[str, set[bytes]] = {}

    async def save(self, record: CredentialRecord) -> None:
        self._creds[record.credential_id] = record
        self._user_index.setdefault(record.user_id, set()).add(
            record.credential_id
        )

    async def get(self, credential_id: bytes) -> CredentialRecord | None:
        return self._creds.get(credential_id)

    async def list_by_user(self, user_id: str) -> list[CredentialRecord]:
        ids = self._user_index.get(user_id, set())
        return [self._creds[cid] for cid in ids if cid in self._creds]

    async def update_sign_count(
        self, credential_id: bytes, count: int
    ) -> None:
        if credential_id in self._creds:
            self._creds[credential_id].sign_count = count


_RECORD_FIELDS = [
    "credential_id",
    "user_id",
    "public_key_cbor",
    "sign_count",
    "alg",
    "created_at",
    "credential_type",
    "attestation_type",
]

_REDIS_KEY_PREFIX = "webauthn:credential:"


def _record_to_dict(record: CredentialRecord) -> dict[str, str]:
    """Serialize a CredentialRecord to a string dict for Redis HASH."""
    return {
        "credential_id": record.credential_id.hex(),
        "user_id": record.user_id,
        "public_key_cbor": record.public_key_cbor.hex(),
        "sign_count": str(record.sign_count),
        "alg": str(record.alg),
        "created_at": record.created_at.isoformat(),
        "credential_type": record.credential_type,
        "attestation_type": record.attestation_type,
    }


def _dict_to_record(data: dict[str, str]) -> CredentialRecord:
    """Deserialize a string dict from Redis HASH to a CredentialRecord."""
    created_at = datetime.fromisoformat(data["created_at"])
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return CredentialRecord(
        credential_id=bytes.fromhex(data["credential_id"]),
        user_id=data["user_id"],
        public_key_cbor=bytes.fromhex(data["public_key_cbor"]),
        sign_count=int(data["sign_count"]),
        alg=int(data["alg"]),
        created_at=created_at,
        credential_type=data.get("credential_type", "public-key"),
        attestation_type=data.get("attestation_type", "none"),
    )


class RedisCredentialStore:
    """Redis-backed implementation of ``CredentialStore``.

    Credentials are stored as Redis HASHes with the key
    ``webauthn:credential:<credential_id_hex>``.

    User indexes are maintained in a Redis SET with the key
    ``webauthn:user:<user_id>``.
    """

    def __init__(self, redis: Any) -> None:
        self._redis = redis

    async def save(self, record: CredentialRecord) -> None:
        key = _REDIS_KEY_PREFIX + record.credential_id.hex()
        data = _record_to_dict(record)
        await self._redis.hset(key, mapping=data)
        # Add to user index
        user_key = f"webauthn:user:{record.user_id}"
        await self._redis.sadd(user_key, record.credential_id.hex())

    async def get(self, credential_id: bytes) -> CredentialRecord | None:
        key = _REDIS_KEY_PREFIX + credential_id.hex()
        data = await self._redis.hgetall(key)
        if not data:
            return None
        # Redis returns bytes keys; decode them to str
        decoded = {k.decode(): v.decode() for k, v in data.items()}
        return _dict_to_record(decoded)

    async def list_by_user(self, user_id: str) -> list[CredentialRecord]:
        user_key = f"webauthn:user:{user_id}"
        ids = await self._redis.smembers(user_key)
        records: list[CredentialRecord] = []
        for cid_hex in ids:
            cid_hex_str = cid_hex.decode() if isinstance(cid_hex, bytes) else cid_hex
            key = _REDIS_KEY_PREFIX + cid_hex_str
            data = await self._redis.hgetall(key)
            if data:
                decoded = {k.decode(): v.decode() for k, v in data.items()}
                records.append(_dict_to_record(decoded))
        return records

    async def update_sign_count(
        self, credential_id: bytes, count: int
    ) -> None:
        key = _REDIS_KEY_PREFIX + credential_id.hex()
        await self._redis.hset(key, "sign_count", str(count))
