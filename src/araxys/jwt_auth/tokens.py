"""JWT token creation, verification, and rotation.

Implements the full OAuth2 access + refresh token flow with:
- Configurable TTLs per token type
- JTI-based refresh token revocation
- Automatic token rotation (old refresh token is blacklisted)
- Scope embedding in token claims
"""

from __future__ import annotations

import hashlib
import typing
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import structlog
from pydantic import BaseModel

from araxys.core.exceptions import TokenExpired, TokenInvalid, TokenRevoked
from araxys.core.types import AuditEntry, AuditEventType, Scope

if typing.TYPE_CHECKING:
    from araxys.core.config import JWTConfig
    from araxys.jwt_auth.storage import JWKSStore, TokenStorage

logger = structlog.get_logger("araxys.jwt")


def compute_bind_hash(ip: str, user_agent: str) -> str:
    """Compute a client fingerprint for token binding.

    Returns the first 16 hex chars of ``SHA-256(ip + user_agent_prefix)``.
    Embed this in the ``bind`` JWT claim to prevent token theft — a
    stolen token cannot be used from a different IP or browser.
    """
    ua_fragment = user_agent[:128] if user_agent else ""
    raw = f"{ip}|{ua_fragment}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class TokenPair(BaseModel):
    """Access + Refresh token pair returned after authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access token expires


class TokenPayload(BaseModel):
    """Decoded JWT token payload."""

    sub: str  # subject (user ID)
    scopes: list[str] = []
    exp: datetime
    iat: datetime
    jti: str
    token_type: str  # "access" or "refresh"
    iss: str | None = None
    aud: str | None = None
    family: str | None = None  # refresh token family for chain tracking


class JWTManager:
    """Manages JWT access and refresh tokens with rotation.

    Parameters
    ----------
    config:
        JWT configuration (algorithm, TTLs, issuer, audience).
    secret_key:
        The master secret key for signing tokens.
    storage:
        Token storage backend for JTI blacklisting.
    on_audit:
        Optional callback to emit audit events.
    jwks_store:
        Optional JWKS store for public key discovery and rotation.
    """

    def __init__(
        self,
        config: JWTConfig,
        secret_key: str,
        storage: TokenStorage,
        on_audit: typing.Callable | None = None,  # type: ignore
        jwks_store: JWKSStore | None = None,
    ) -> None:
        self._config = config
        self._secret_key = secret_key
        self._storage = storage
        self._on_audit = on_audit
        self._jwks_store = jwks_store

    def _get_signing_key(self) -> str:
        """Return the key to use for token signing based on the algorithm.

        For symmetric algorithms (HS256), returns the ``secret_key``.
        For asymmetric algorithms (RS256, ES256), returns the ``private_key``
        from config.
        """
        algorithm = self._config.algorithm
        if algorithm in ("RS256", "ES256"):
            private_key = self._config.private_key
            if private_key:
                return private_key
            raise ValueError(
                f"private_key required in JWTConfig for {algorithm} signing"
            )
        return self._secret_key

    def _get_verification_key(self) -> str:
        """Return the key to use for token verification based on the algorithm.

        For symmetric algorithms (HS256), returns the ``secret_key``.
        For asymmetric algorithms (RS256, ES256), returns the ``public_key``
        from config, falling back to ``private_key`` if no separate public key
        is provided.
        """
        algorithm = self._config.algorithm
        if algorithm in ("RS256", "ES256"):
            if self._config.public_key:
                return self._config.public_key
            if self._config.private_key:
                # Derive public key from private key
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_private_key,
                )

                private_key = load_pem_private_key(
                    self._config.private_key.encode("utf-8"), password=None
                )
                public_key = private_key.public_key()
                from cryptography.hazmat.primitives.serialization import (
                    Encoding,
                    PublicFormat,
                )

                return public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                ).decode()
            return self._secret_key
        return self._secret_key

    def _create_token(
        self,
        subject: str,
        token_type: str,
        ttl: timedelta,
        scopes: list[Scope] | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Create a signed JWT token. Returns (encoded_token, jti)."""
        now = datetime.now(UTC)
        jti = uuid.uuid4().hex

        payload: dict[str, Any] = {
            "sub": subject,
            "token_type": token_type,
            "scopes": [s.value for s in (scopes or [])],
            "exp": now + ttl,
            "iat": now,
            "nbf": now,  # valid immediately
            "jti": jti,
        }

        if self._config.issuer:
            payload["iss"] = self._config.issuer
        if self._config.audience:
            payload["aud"] = self._config.audience
        if extra_claims:
            # Forbid overriding built-in claims — an attacker who controls
            # extra_claims could otherwise extend the token lifetime or
            # change the token type.
            protected = {"sub", "token_type", "scopes", "exp", "iat", "nbf", "jti"}
            if self._config.issuer:
                protected.add("iss")
            if self._config.audience:
                protected.add("aud")
            forbidden = set(extra_claims) & protected
            if forbidden:
                raise ValueError(
                    f"extra_claims must not override built-in claims: "
                    f"{', '.join(sorted(forbidden))}"
                )
            payload.update(extra_claims)

        signing_key = self._get_signing_key()
        token = jwt.encode(payload, signing_key, algorithm=self._config.algorithm)
        return token, jti

    async def create_token_pair(
        self,
        subject: str,
        scopes: list[Scope] | None = None,
        extra_claims: dict[str, Any] | None = None,
        bind_ip: str | None = None,
        bind_user_agent: str | None = None,
    ) -> TokenPair:
        """Generate an access + refresh token pair.

        Parameters
        ----------
        subject:
            The user identifier (e.g. user ID or username).
        scopes:
            Permissions embedded in the access token.
        extra_claims:
            Additional claims to include in the access token.
        bind_ip:
            Client IP address for token binding.  Only used when
            ``token_binding`` is enabled in config.
        bind_user_agent:
            Client User-Agent for token binding.
        """
        access_ttl = timedelta(minutes=self._config.access_token_ttl_minutes)
        refresh_ttl = timedelta(days=self._config.refresh_token_ttl_days)

        # Compute token binding hash if enabled
        if self._config.token_binding and bind_ip:
            bind_hash = compute_bind_hash(
                bind_ip, bind_user_agent or ""
            )
            if extra_claims is None:
                extra_claims = {}
            extra_claims = {**extra_claims, "bind": bind_hash}

        access_token, _ = self._create_token(
            subject, "access", access_ttl, scopes, extra_claims
        )
        # Refresh tokens get a family_id for chain tracking
        family_id = uuid.uuid4().hex
        refresh_token, _ = self._create_token(
            subject, "refresh", refresh_ttl, extra_claims={"family": family_id}
        )

        logger.info("jwt.token_pair_created", subject=subject, scopes=scopes)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_ttl.total_seconds()),
        )

    def decode_token(self, token: str, expected_type: str = "access") -> TokenPayload:
        """Decode and validate a JWT token.

        Parameters
        ----------
        token:
            The encoded JWT string.
        expected_type:
            Expected token type ("access" or "refresh").

        Raises
        ------
        TokenExpired
            If the token has expired.
        TokenInvalid
            If the token is malformed, has wrong type, or invalid signature.
        """
        try:
            # Only allow the configured algorithm for verification.
            # Never pass a broad algorithm list (e.g. ["RS256", "ES256", "HS256"])
            # because RS256/ES256 public keys are served via the JWKS endpoint and
            # an attacker can forge HS256 tokens using a known public key as the
            # HMAC secret — the classic JWT algorithm confusion attack.
            algorithms = [self._config.algorithm]

            kwargs: dict[str, Any] = {"algorithms": algorithms}
            if self._config.audience:
                kwargs["audience"] = self._config.audience
            if self._config.issuer:
                kwargs["issuer"] = self._config.issuer
            if self._config.leeway_seconds:
                kwargs["leeway"] = self._config.leeway_seconds

            verification_key = self._get_verification_key()
            payload = jwt.decode(token, verification_key, **kwargs)

        except jwt.ExpiredSignatureError:
            raise TokenExpired(expected_type) from None
        except jwt.InvalidTokenError as exc:
            raise TokenInvalid(str(exc)) from exc

        if payload.get("token_type") != expected_type:
            raise TokenInvalid(
                f"Expected {expected_type} token, got {payload.get('token_type')}"
            )

        return TokenPayload(**payload)

    async def rotate_tokens(
        self,
        refresh_token: str,
        scopes: list[Scope] | None = None,
    ) -> TokenPair:
        """Rotate tokens: verify the refresh token, blacklist it, and issue a new pair.

        This is the secure way to "refresh" an access token.

        Raises
        ------
        TokenRevoked
            If the refresh token's JTI is already blacklisted (potential theft).
        TokenExpired
            If the refresh token has expired.
        TokenInvalid
            If the refresh token is malformed.
        """
        payload = self.decode_token(refresh_token, expected_type="refresh")

        # Check if the refresh token's family has been revoked
        if (
            payload.family
            and hasattr(self._storage, "_family_blacklist")
            and f"{payload.sub}:{payload.family}" in self._storage._family_blacklist
        ):
            logger.critical(
                "jwt.family_revoked",
                subject=payload.sub,
                family=payload.family,
            )
            raise TokenRevoked()

        # Check if this refresh token has already been used (replay attack)
        if await self._storage.is_blacklisted(payload.jti):
            logger.critical(
                "jwt.token_reuse_detected",
                subject=payload.sub,
                jti=payload.jti,
            )
            if self._on_audit:
                await self._on_audit(
                    AuditEntry(
                        event_type=AuditEventType.TOKEN_REVOKED,
                        user_id=payload.sub,
                        detail="Refresh token reuse detected — possible theft",
                    )
                )
            # Revoke the entire token FAMILY on detected theft
            if hasattr(self._storage, "blacklist_family") and payload.family:
                await self._storage.blacklist_family(
                    payload.sub, payload.family
                )
            raise TokenRevoked()

        # Blacklist the old refresh token's JTI
        remaining_ttl = int((payload.exp - datetime.now(UTC)).total_seconds())
        await self._storage.blacklist_jti(payload.jti, max(remaining_ttl, 1))

        # Issue a new pair
        new_pair = await self.create_token_pair(
            subject=payload.sub,
            scopes=scopes or [Scope(s) for s in payload.scopes],
        )

        logger.info("jwt.tokens_rotated", subject=payload.sub)

        if self._on_audit:
            await self._on_audit(
                AuditEntry(
                    event_type=AuditEventType.TOKEN_ROTATED,
                    user_id=payload.sub,
                    detail="Token pair rotated successfully",
                )
            )

        return new_pair

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        """Explicitly revoke a refresh token (e.g. on logout)."""
        payload = self.decode_token(refresh_token, expected_type="refresh")
        remaining_ttl = int((payload.exp - datetime.now(UTC)).total_seconds())
        await self._storage.blacklist_jti(payload.jti, max(remaining_ttl, 1))

        logger.info("jwt.refresh_token_revoked", subject=payload.sub, jti=payload.jti)

    async def introspect_token(self, token: str) -> dict[str, Any]:
        """Introspect a token following RFC 7662.

        Parameters
        ----------
        token:
            The encoded JWT string to introspect.

        Returns
        -------
        dict[str, Any]
            A dictionary with at least the ``active`` key, plus claims
            if the token is valid (even if revoked).
        """
        try:
            # Try as an access token first
            payload = self.decode_token(token, expected_type="access")
        except TokenExpired:
            return {"active": False}
        except TokenInvalid:
            try:
                # Try as a refresh token
                payload = self.decode_token(token, expected_type="refresh")
            except (TokenExpired, TokenInvalid):
                return {"active": False}

        # Check revocation status
        is_revoked = await self._storage.is_blacklisted(payload.jti)

        result: dict[str, Any] = {
            "active": not is_revoked,
            "sub": payload.sub,
            "exp": int(payload.exp.timestamp()),
            "iat": int(payload.iat.timestamp()),
            "jti": payload.jti,
            "token_type": payload.token_type,
            "scope": " ".join(payload.scopes) if payload.scopes else "",
            "iss": payload.iss,
            "aud": payload.aud,
        }

        logger.info("jwt.token_introspected", sub=payload.sub, active=result["active"])
        return result

    async def get_jwks(self) -> dict[str, Any]:
        """Return the JWKS (JSON Web Key Set) for public key discovery.

        Requires that ``jwks_enabled`` is ``True`` in config and a
        ``jwks_store`` was provided.

        Raises
        ------
        RuntimeError
            If JWKS is not configured or not enabled.
        """
        if not self._config.jwks_enabled or self._jwks_store is None:
            raise RuntimeError(
                "JWKS not configured. Set jwks_enabled=True and provide a jwks_store."
            )
        return await self._jwks_store.get_jwks()
