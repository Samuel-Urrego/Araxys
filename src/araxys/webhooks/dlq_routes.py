"""DLQ Admin API — inspection and management endpoints.

Provides a FastAPI router factory that exposes dead-letter queue
inspection, replay, and purge operations.

Usage::

    from araxys.webhooks.dlq_routes import create_dlq_router

    app.include_router(create_dlq_router(shield))
"""

# mypy: disable-error-code="attr-defined,union-attr"
# The DLQ router uses runtime attribute access on the shield —
# static type checking on dynamic attributes is not useful here.

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer

from araxys.core.types import Scope

if TYPE_CHECKING:
    from collections.abc import Callable

    from araxys.api_keys.manager import APIKeyManager
    from araxys.jwt_auth.tokens import JWTManager
    from araxys.shield import AraxysShield

_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_dlq_admin(
    jwt_manager: JWTManager | None = None,
    api_key_manager: APIKeyManager | None = None,
) -> Callable[..., None]:
    """Composite auth dependency: JWT admin scope OR API key admin scope."""

    async def _dependency(
        request: Request,
        token: str | None = Security(_oauth2_scheme),
        raw_key: str | None = Security(_api_key_header),
    ) -> None:
        if jwt_manager is None and api_key_manager is None:
            warnings.warn(
                "DLQ router registered without auth guard — "
                "all DLQ endpoints are publicly accessible.",
                RuntimeWarning,
                stacklevel=3,
            )
            return

        # Try JWT first
        if token is not None and jwt_manager is not None:
            from araxys.core.exceptions import TokenExpired, TokenInvalid

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

            token_scopes = set(payload.scopes)
            if Scope.ADMIN.value in token_scopes:
                return

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient scopes. Missing: admin",
            )

        # Try API key
        if raw_key is not None and api_key_manager is not None:
            from araxys.core.exceptions import InvalidAPIKey

            try:
                await api_key_manager.verify_key(raw_key, [Scope.ADMIN])
            except InvalidAPIKey as exc:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=exc.reason,
                ) from exc
            return

        # Neither credential provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Authentication required — "
                "provide JWT bearer token or X-API-Key header"
            ),
        )

    return _dependency  # type: ignore


def create_dlq_router(
    shield: AraxysShield,
    *,
    prefix: str = "/admin/webhooks",
) -> APIRouter:
    """Create a FastAPI router with DLQ management endpoints.

    All endpoints require the DLQ backend to be available.
    Returns 503 when the backend is unavailable.

    Parameters
    ----------
    shield:
        The ``AraxysShield`` instance.
    prefix:
        URL prefix for DLQ routes (default ``/admin/webhooks``).

    Routes
    ------
    ``GET /admin/webhooks/dlq`` — List pending events (optional ``?status=dead``)
    ``GET /admin/webhooks/dlq/dead`` — List dead events
    ``GET /admin/webhooks/dlq/{event_id}`` — Inspect a single event
    ``POST /admin/webhooks/dlq/{event_id}/replay`` — Re-enqueue a dead event
    ``DELETE /admin/webhooks/dlq`` — Purge all or by ``?url=``
    """
    jwt_manager = getattr(shield, "jwt_manager", None)
    api_key_manager = getattr(shield, "api_key_manager", None)
    _auth = _require_dlq_admin(jwt_manager, api_key_manager)
    router = APIRouter(prefix=prefix, tags=["dlq"], dependencies=[Depends(_auth)])

    def _get_backend() -> Any:
        """Get the DLQ backend from the shield, or raise 503."""
        backend = getattr(shield, "dlq_backend", None)
        if backend is None:
            raise HTTPException(
                503, detail="DLQ backend not available"
            )
        return backend

    # ── List pending ────────────────────────────────────────────

    @router.get("/dlq")
    async def list_pending(
        status: str = Query(default="pending", pattern="^(pending|dead)$"),
    ) -> dict[str, Any]:
        """List DLQ events by status (pending or dead)."""
        backend = _get_backend()
        try:
            if status == "dead":
                events = await backend.list_dead()
            else:
                events = await backend.list_pending()
        except (ConnectionError, OSError):
            raise HTTPException(503, detail="Redis unavailable") from None

        return {
            "status": status,
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "url": e.url,
                    "attempt_count": e.attempt_count,
                    "next_retry_at": e.next_retry_at,
                    "age_seconds": e.age_seconds,
                    "status": e.status,
                }
                for e in events
            ],
        }

    # ── List dead ───────────────────────────────────────────────

    @router.get("/dlq/dead")
    async def list_dead() -> dict[str, Any]:
        """List dead DLQ events."""
        backend = _get_backend()
        try:
            events = await backend.list_dead()
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        return {
            "status": "dead",
            "events": [
                {
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "url": e.url,
                    "attempt_count": e.attempt_count,
                    "next_retry_at": e.next_retry_at,
                    "age_seconds": e.age_seconds,
                    "status": e.status,
                }
                for e in events
            ],
        }

    # ── Inspect ─────────────────────────────────────────────────

    @router.get("/dlq/{event_id}")
    async def inspect_event(event_id: str) -> dict[str, Any]:
        """Return full event details by event_id."""
        backend = _get_backend()
        try:
            event = await backend.inspect(event_id)
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        if event is None:
            raise HTTPException(404, detail="Event not found")

        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "payload": event.payload,
            "url": event.url,
            "attempt_count": event.attempt_count,
            "last_error": event.last_error,
            "next_retry_at": event.next_retry_at,
            "original_timestamp": event.original_timestamp,
            "status": event.status,
            "created_at": event.created_at,
        }

    # ── Replay ──────────────────────────────────────────────────

    @router.post("/dlq/{event_id}/replay")
    async def replay_event(event_id: str) -> dict[str, str]:
        """Re-enqueue a dead event back to pending."""
        backend = _get_backend()
        try:
            event = await backend.inspect(event_id)
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        if event is None:
            raise HTTPException(404, detail="Event not found")

        # Move from dead to pending with reset attempt count
        try:
            await backend.replay(event_id)
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        return {"status": "replayed", "event_id": event_id}

    # ── Purge ───────────────────────────────────────────────────

    @router.delete("/dlq")
    async def purge(
        url: str | None = Query(default=None),
    ) -> dict[str, Any]:
        """Purge DLQ events.

        If ``url`` is provided, only events matching that URL are
        purged.  Otherwise all events are purged.
        """
        backend = _get_backend()
        try:
            if url:
                deleted = await backend.purge_by_url(url)
            else:
                deleted = await backend.purge_all()
        except ConnectionError:
            raise HTTPException(503, detail="Redis unavailable") from None

        return {"deleted": deleted}

    return router
