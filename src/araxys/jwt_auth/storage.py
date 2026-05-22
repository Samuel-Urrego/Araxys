"""JWT token storage protocol and implementations.

Token storage is used for refresh token revocation tracking via JTI
(JWT ID) — when a refresh token is rotated, the old JTI is blacklisted.

Also provides JWKS (JSON Web Key Set) support for public key discovery
and rotation as defined in RFC 7517.
"""


from __future__ import annotations

import base64
import time
import uuid
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from araxys.db_security.pool import ConnectionPool


@runtime_checkable
class TokenStorage(Protocol):
    """Interface for JWT refresh token state."""

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        """Add a JTI to the blacklist with a TTL matching the token expiry."""
        ...

    async def is_blacklisted(self, jti: str) -> bool:
        """Check if a JTI has been revoked."""
        ...

    async def try_blacklist_jti(self, jti: str, ttl_seconds: int) -> bool:
        """Atomically check-and-set a JTI in the blacklist.

        Returns ``True`` if the JTI was NOT previously blacklisted and
        was successfully added. Returns ``False`` if the JTI was already
        blacklisted (indicating a replay attempt).

        This eliminates the TOCTOU race between ``is_blacklisted()``
        and ``blacklist_jti()`` in token rotation.
        """
        ...

    async def blacklist_family(self, user_id: str, family_id: str) -> None:
        """Revoke all tokens in a refresh token family (theft detection)."""
        ...

    async def is_family_blacklisted(self, user_id: str, family_id: str) -> bool:
        """Return True if this refresh token family has been revoked."""
        ...


class InMemoryTokenStorage:
    """In-memory token storage for development and testing."""

    def __init__(self) -> None:
        # jti -> expires_at (monotonic)
        self._blacklist: dict[str, float] = {}
        # family blacklist: "user_id:family_id" key
        self._family_blacklist: set[str] = set()

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        self._blacklist[jti] = time.monotonic() + ttl_seconds

    async def is_blacklisted(self, jti: str) -> bool:
        if jti not in self._blacklist:
            return False
        if time.monotonic() >= self._blacklist[jti]:
            del self._blacklist[jti]
            return False
        return True

    async def try_blacklist_jti(self, jti: str, ttl_seconds: int) -> bool:
        # Atomic check-and-set (no await points — safe in single-threaded asyncio)
        if jti in self._blacklist and time.monotonic() < self._blacklist[jti]:
            return False  # Already blacklisted, still valid
        self._blacklist[jti] = time.monotonic() + ttl_seconds
        return True

    def _cleanup(self) -> None:
        """Remove expired entries (call periodically for long-running processes)."""
        now = time.monotonic()
        expired = [jti for jti, exp in self._blacklist.items() if now >= exp]
        for jti in expired:
            del self._blacklist[jti]

    async def blacklist_family(self, user_id: str, family_id: str) -> None:
        """Revoke all tokens in a refresh token family."""
        self._family_blacklist.add(f"{user_id}:{family_id}")

    async def is_family_blacklisted(self, user_id: str, family_id: str) -> bool:
        return f"{user_id}:{family_id}" in self._family_blacklist


class RedisTokenStorage:
    """Redis-backed token storage for production.

    Requires the ``redis`` extra: ``pip install araxys[redis]``.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        *,
        pool: ConnectionPool | None = None,
    ) -> None:
        self._pool = pool
        self._redis: Redis | None = None
        if pool is None and redis_url:
            try:
                from redis.asyncio import from_url
            except ImportError as exc:
                raise ImportError(
                    "RedisTokenStorage requires the 'redis' package. "
                    "Install it with: pip install araxys[redis]"
                ) from exc
            self._redis = from_url(redis_url, decode_responses=True)

    def _key(self, jti: str) -> str:
        return f"araxys:jti_blacklist:{jti}"

    async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
        key = self._key(jti)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                await conn.setex(key, ttl_seconds, "1")
                return
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        await self._redis.setex(key, ttl_seconds, "1")

    async def is_blacklisted(self, jti: str) -> bool:
        key = self._key(jti)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                result = await conn.exists(key)
                return bool(result)
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        result = await self._redis.exists(key)
        return bool(result)

    async def try_blacklist_jti(self, jti: str, ttl_seconds: int) -> bool:
        """Atomic check-and-set using SET NX — eliminates TOCTOU race."""
        key = self._key(jti)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                result = await conn.set(key, "1", ex=ttl_seconds, nx=True)
                return result is not None
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        result = await self._redis.set(key, "1", ex=ttl_seconds, nx=True)
        return result is not None

    def _family_key(self, user_id: str, family_id: str) -> str:
        return f"araxys:family_blacklist:{user_id}:{family_id}"

    async def blacklist_family(self, user_id: str, family_id: str) -> None:
        """Revoke all tokens in a refresh token family."""
        key = self._family_key(user_id, family_id)
        # Blacklist for 7 days (max refresh token lifetime)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                await conn.setex(key, 604800, "1")
                return
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        await self._redis.setex(key, 604800, "1")

    async def is_family_blacklisted(self, user_id: str, family_id: str) -> bool:
        key = self._family_key(user_id, family_id)
        if self._pool:
            conn = await self._pool.acquire()
            try:
                result = await conn.exists(key)
                return bool(result)
            finally:
                await self._pool.release(conn)
        assert self._redis is not None
        result = await self._redis.exists(key)
        return bool(result)


def _base64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pem_to_jwk_kid(pem_key: str) -> str:
    """Generate a stable kid from a PEM public key thumbprint."""
    key = load_pem_public_key(pem_key.encode("utf-8"))
    if isinstance(key, rsa.RSAPublicKey):
        rsa_numbers = key.public_numbers()
        # Use modulus as thumbprint material
        n_bytes = rsa_numbers.n.to_bytes((rsa_numbers.n.bit_length() + 7) // 8, "big")
        return _base64url_encode(n_bytes[:16])
    if isinstance(key, ec.EllipticCurvePublicKey):
        ec_numbers = key.public_numbers()
        key_size_bytes = (key.curve.key_size + 7) // 8
        x_bytes = ec_numbers.x.to_bytes(key_size_bytes, "big")
        return _base64url_encode(x_bytes[:16])
    return uuid.uuid4().hex


def _public_key_pem_to_jwk(pem_key: str, kid: str, algorithm: str) -> dict[str, Any]:
    """Convert a PEM-encoded public key to a JWK dictionary (RFC 7517)."""
    key = load_pem_public_key(pem_key.encode("utf-8"))

    jwk: dict[str, Any] = {
        "kid": kid,
        "alg": algorithm,
        "use": "sig",
    }

    if isinstance(key, rsa.RSAPublicKey):
        rsa_numbers = key.public_numbers()
        n_bytes = rsa_numbers.n.to_bytes((rsa_numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = rsa_numbers.e.to_bytes((rsa_numbers.e.bit_length() + 7) // 8, "big")
        jwk["kty"] = "RSA"
        jwk["n"] = _base64url_encode(n_bytes)
        jwk["e"] = _base64url_encode(e_bytes)

    elif isinstance(key, ec.EllipticCurvePublicKey):
        ec_numbers = key.public_numbers()
        key_size_bytes = (key.curve.key_size + 7) // 8
        x_bytes = ec_numbers.x.to_bytes(key_size_bytes, "big")
        y_bytes = ec_numbers.y.to_bytes(key_size_bytes, "big")

        jwk["kty"] = "EC"
        jwk["x"] = _base64url_encode(x_bytes)
        jwk["y"] = _base64url_encode(y_bytes)

        if isinstance(key.curve, ec.SECP256R1):
            jwk["crv"] = "P-256"
        elif isinstance(key.curve, ec.SECP384R1):
            jwk["crv"] = "P-384"
        elif isinstance(key.curve, ec.SECP521R1):
            jwk["crv"] = "P-521"
        else:
            jwk["crv"] = "P-256"

    return jwk


@runtime_checkable
class JWKSStore(Protocol):
    """Protocol for JSON Web Key Set (JWKS) storage.

    Implementations manage multiple public keys for key discovery and rotation.
    """

    async def get_jwks(self) -> dict[str, Any]:
        """Return the full JWKS dict with a ``keys`` array (RFC 7517)."""
        ...

    async def get_signing_key_id(self) -> str | None:
        """Return the ``kid`` of the currently active signing key, or ``None``."""
        ...

    async def get_signing_key(self) -> str | None:
        """Return the PEM of the currently active signing key, or ``None``."""
        ...

    def add_key(
        self,
        kid: str,
        public_key_pem: str,
        is_active: bool = False,
        algorithm: str = "RS256",
    ) -> None:
        """Register a public key under the given ``kid``.

        Parameters
        ----------
        kid:
            Key identifier (used in JWT header as the ``kid`` claim).
        public_key_pem:
            PEM-encoded public key.
        is_active:
            If ``True``, this key is used for signing.
        algorithm:
            The JWT algorithm this key is used for (e.g. ``RS256``, ``ES256``).
        """
        ...


class InMemoryJWKSStore:
    """In-memory JWKS store for development and testing.

    Stores public keys in memory and generates JWKS on demand.
    Supports key rotation via ``add_key()`` with ``is_active`` flag.
    """

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}
        self._active_kid: str | None = None

    async def get_jwks(self) -> dict[str, Any]:
        """Return the full JWKS dict with all stored keys."""
        return {"keys": list(self._keys.values())}

    async def get_signing_key_id(self) -> str | None:
        return self._active_kid

    async def get_signing_key(self) -> str | None:
        if self._active_kid is None:
            return None
        entry = self._keys.get(self._active_kid)
        return entry.get("_pem") if entry else None

    def add_key(
        self,
        kid: str,
        public_key_pem: str,
        is_active: bool = False,
        algorithm: str = "RS256",
    ) -> None:
        """Register a public key. Activates it if ``is_active=True``."""
        jwk = _public_key_pem_to_jwk(public_key_pem, kid, algorithm)
        jwk["_pem"] = public_key_pem  # store PEM for later retrieval
        self._keys[kid] = jwk
        if is_active:
            self._active_kid = kid
