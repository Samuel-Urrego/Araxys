from __future__ import annotations
import typing

"""JWT token creation, verification, and rotation.

Implements the full OAuth2 access + refresh token flow with:
- Configurable TTLs per token type
- JTI-based refresh token revocation
- Automatic token rotation (old refresh token is blacklisted)
- Scope embedding in token claims
"""


import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import structlog
from pydantic import BaseModel

from araxys.core.config import JWTConfig
from araxys.core.exceptions import TokenExpired, TokenInvalid, TokenRevoked
from araxys.core.types import AuditEntry, AuditEventType, Scope
from araxys.jwt_auth.storage import TokenStorage

logger = structlog.get_logger("araxys.jwt")


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
    """

    def __init__(
        self,
        config: JWTConfig,
        secret_key: str,
        storage: TokenStorage,
        on_audit: typing.Callable | None = None,  # type: ignore
    ) -> None:
        self._config = config
        self._secret_key = secret_key
        self._storage = storage
        self._on_audit = on_audit

    def _create_token(
        self,
        subject: str,
        token_type: str,
        ttl: timedelta,
        scopes: list[Scope] | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Create a signed JWT token. Returns (encoded_token, jti)."""
        now = datetime.now(timezone.utc)
        jti = uuid.uuid4().hex

        payload: dict[str, Any] = {
            "sub": subject,
            "token_type": token_type,
            "scopes": [s.value for s in (scopes or [])],
            "exp": now + ttl,
            "iat": now,
            "jti": jti,
        }

        if self._config.issuer:
            payload["iss"] = self._config.issuer
        if self._config.audience:
            payload["aud"] = self._config.audience
        if extra_claims:
            payload.update(extra_claims)

        token = jwt.encode(payload, self._secret_key, algorithm=self._config.algorithm)
        return token, jti

    async def create_token_pair(
        self,
        subject: str,
        scopes: list[Scope] | None = None,
        extra_claims: dict[str, Any] | None = None,
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
        """
        access_ttl = timedelta(minutes=self._config.access_token_ttl_minutes)
        refresh_ttl = timedelta(days=self._config.refresh_token_ttl_days)

        access_token, _ = self._create_token(
            subject, "access", access_ttl, scopes, extra_claims
        )
        refresh_token, _ = self._create_token(subject, "refresh", refresh_ttl)

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
            decode_options: dict[str, Any] = {}
            algorithms = [self._config.algorithm]

            kwargs: dict[str, Any] = {"algorithms": algorithms}
            if self._config.audience:
                kwargs["audience"] = self._config.audience
            if self._config.issuer:
                kwargs["issuer"] = self._config.issuer

            payload = jwt.decode(token, self._secret_key, **kwargs)

        except jwt.ExpiredSignatureError:
            raise TokenExpired(expected_type)
        except jwt.InvalidTokenError as exc:
            raise TokenInvalid(str(exc))

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
            raise TokenRevoked()

        # Blacklist the old refresh token's JTI
        remaining_ttl = int((payload.exp - datetime.now(timezone.utc)).total_seconds())
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
        remaining_ttl = int((payload.exp - datetime.now(timezone.utc)).total_seconds())
        await self._storage.blacklist_jti(payload.jti, max(remaining_ttl, 1))

        logger.info("jwt.refresh_token_revoked", subject=payload.sub, jti=payload.jti)
