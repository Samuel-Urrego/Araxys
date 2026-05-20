"""FastAPI dependencies for JWT authentication.

Provides ``require_jwt()`` — a dependency factory that extracts
the bearer token from the ``Authorization`` header, decodes it,
and enforces scope requirements.

Also provides ``create_jwks_router()`` — a factory that creates a
FastAPI router with a JWKS endpoint for public key discovery.

Usage::

    from araxys.jwt_auth.dependencies import require_jwt

    @app.get("/protected")
    async def protected(user: TokenPayload = Depends(require_jwt(Scope.READ))):
        return {"user_id": user.sub}

    # JWKS endpoint (optional):
    from araxys.jwt_auth.dependencies import create_jwks_router
    app.include_router(create_jwks_router(jwt_manager))
"""


from __future__ import annotations

import hmac
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Request, Security, status
from fastapi.security import OAuth2PasswordBearer

from araxys.core.exceptions import TokenExpired, TokenInvalid
from araxys.jwt_auth.tokens import compute_bind_hash

if TYPE_CHECKING:
    from collections.abc import Callable

    from araxys.core.types import Scope
    from araxys.jwt_auth.tokens import JWTManager, TokenPayload

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


def require_jwt(
    *scopes: Scope,
    jwt_manager: JWTManager | None = None,
) -> Callable[..., TokenPayload]:
    """Create a FastAPI dependency that validates JWT access tokens.

    Parameters
    ----------
    *scopes:
        Required scopes for the endpoint.
    jwt_manager:
        The JWT manager instance. Typically set by AraxysShield.
    """

    async def _dependency(
        token: str | None = Security(_oauth2_scheme),
        request: Request | None = None,
    ) -> TokenPayload:
        if jwt_manager is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT manager not configured",
            )
        if token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            payload = jwt_manager.decode_token(token, expected_type="access")
        except TokenExpired:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except TokenInvalid as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc.reason}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        # Check token binding (if enabled in JWT config)
        if jwt_manager._config.token_binding and "bind" in payload.model_dump():
            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token binding requires request context",
                )
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "")
            expected_bind = compute_bind_hash(client_ip, user_agent)
            token_bind = payload.model_dump().get("bind", "")
            if not hmac.compare_digest(token_bind, expected_bind):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token is bound to a different client",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # Check scopes
        if scopes:
            token_scopes = set(payload.scopes)
            required = {s.value for s in scopes}
            missing = required - token_scopes
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient scopes. Missing: {', '.join(missing)}",
                )

        return payload

    return _dependency  # type: ignore


def create_jwks_router(jwt_manager: JWTManager | None = None) -> APIRouter:
    """Create a FastAPI router with a JWKS endpoint for public key discovery.

    The endpoint is mounted at ``/.well-known/jwks.json``.

    Parameters
    ----------
    jwt_manager:
        The JWT manager instance. Must have ``jwks_enabled=True`` and a
        ``jwks_store`` configured. If ``None`` or JWKS is not enabled,
        the endpoint returns 404.

    Returns
    -------
    APIRouter
        A FastAPI router with the JWKS endpoint registered.
    """
    router = APIRouter()

    @router.get("/.well-known/jwks.json", include_in_schema=False)
    async def jwks_endpoint() -> dict[str, Any]:
        if jwt_manager is None or not jwt_manager._config.jwks_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="JWKS endpoint not enabled",
            )
        try:
            return await jwt_manager.get_jwks()
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

    return router
