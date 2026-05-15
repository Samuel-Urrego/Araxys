"""FastAPI dependencies for API key authentication.

Provides ``require_api_key()`` — a dependency factory that extracts
the key from the ``X-API-Key`` header and verifies it.

Usage::

    from araxys.api_keys.dependencies import require_api_key

    @app.get("/data")
    async def get_data(key: APIKeyRecord = Depends(require_api_key(Scope.READ))):
        return {"owner": key.owner}
"""



from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from araxys.core.exceptions import InvalidAPIKey

if TYPE_CHECKING:
    from collections.abc import Callable

    from araxys.api_keys.manager import APIKeyManager
    from araxys.api_keys.models import APIKeyRecord
    from araxys.core.types import Scope

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(
    *scopes: Scope,
    manager: APIKeyManager | None = None,
) -> Callable[..., APIKeyRecord]:
    """Create a FastAPI dependency that validates API keys.

    Parameters
    ----------
    *scopes:
        Required scopes for the endpoint.
    manager:
        The API key manager instance. Typically set by AraxysShield.
    """

    async def _dependency(
        raw_key: str | None = Security(_api_key_header),
    ) -> APIKeyRecord:
        if manager is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="API key manager not configured",
            )
        if raw_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key — provide it in the X-API-Key header",
            )
        try:
            return await manager.verify_key(raw_key, list(scopes) if scopes else None)
        except InvalidAPIKey as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=exc.reason,
            ) from exc

    return _dependency  # type: ignore
