"""FastAPI dependencies for JWT authentication.

Provides ``require_jwt()`` — a dependency factory that extracts
the bearer token from the ``Authorization`` header, decodes it,
and enforces scope requirements.

Usage::

    from araxys.jwt_auth.dependencies import require_jwt

    @app.get("/protected")
    async def protected(user: TokenPayload = Depends(require_jwt(Scope.READ))):
        return {"user_id": user.sub}
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer

from araxys.core.exceptions import TokenExpired, TokenInvalid
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
            )
        except TokenInvalid as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc.reason}",
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

    return _dependency
