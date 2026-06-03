"""Admin API — inspection and management endpoints.

Provides a FastAPI router factory that exposes session management,
IP ban control, API key listing/rotation, rate limit stats, and
health checks. Protected by ADMIN scope.

Usage::

    from araxys.admin import create_admin_router

    app.include_router(create_admin_router(shield))
"""

# mypy: disable-error-code="attr-defined,union-attr"
# The admin router uses runtime inspection of backend internals —
# static type checking on private/dynamic attributes is not useful here.

from __future__ import annotations

import time
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


def _require_admin(
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
                "Admin router registered without auth guard — "
                "all admin endpoints are publicly accessible.",
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


def create_admin_router(
    shield: AraxysShield,
    *,
    prefix: str = "/admin",
) -> APIRouter:
    """Create a FastAPI router with admin inspection endpoints.

    All endpoints require an ADMIN-scoped API key or JWT.
    The caller must apply authentication middleware before
    this router.

    Parameters
    ----------
    shield:
        The ``AraxysShield`` instance.
    prefix:
        URL prefix for admin routes (default ``/admin``).

    Routes
    ------
    ``GET /admin/health`` — Module health status
    ``GET /admin/sessions`` — List sessions (optional ?user_id=)
    ``DELETE /admin/sessions/{session_id}`` — Revoke a session
    ``GET /admin/ips/blocked`` — List banned IPs
    ``DELETE /admin/ips/blocked/{ip}`` — Unban an IP
    ``GET /admin/api-keys`` — List API keys (?owner=)
    ``POST /admin/api-keys/{prefix}/rotate`` — Rotate an API key
    ``GET /admin/rate-limit/stats`` — Rate limit statistics
    """
    jwt_manager = getattr(shield, "jwt_manager", None)
    api_key_manager = getattr(shield, "api_key_manager", None)
    _auth = _require_admin(jwt_manager, api_key_manager)
    router = APIRouter(prefix=prefix, tags=["admin"], dependencies=[Depends(_auth)])

    # ── Health ──────────────────────────────────────────────────

    @router.get("/health")
    async def health() -> dict[str, Any]:
        """Return the status of all enabled security modules."""
        return {
            "status": "ok",
            "modules": {
                "rate_limit": _bool(shield.rate_backend),
                "session": _bool(shield.session_manager),
                "audit": _bool(shield.audit_logger),
                "db_security": _bool(shield.db_pool),
                "mfa": _bool(shield.mfa_manager),
                "csrf": _bool(shield.csrf_handler),
                "password_policy": _bool(shield.password_policy),
                "jwt": True,
                "api_keys": True,
            },
            "timestamp": int(time.time()),
        }

    # ── Sessions ────────────────────────────────────────────────

    @router.get("/sessions")
    async def list_sessions(
        user_id: str | None = Query(default=None),
    ) -> dict[str, Any]:
        """List active sessions, optionally filtered by user_id."""
        if not shield.session_manager:
            raise HTTPException(404, "Session manager not enabled")

        if user_id:
            sessions = await shield.session_manager.list(user_id)
        else:
            sessions = []
            # No global list — user_id is required
            raise HTTPException(
                400, "user_id query parameter is required"
            )

        return {"sessions": sessions, "count": len(sessions)}

    @router.delete("/sessions/{session_id}")
    async def revoke_session(session_id: str) -> dict[str, str]:
        """Revoke a session by ID."""
        if not shield.session_manager:
            raise HTTPException(404, "Session manager not enabled")

        ok = await shield.session_manager.revoke(session_id)
        if not ok:
            raise HTTPException(404, "Session not found")

        return {"status": "revoked", "session_id": session_id}

    # ── IP Management ───────────────────────────────────────────

    @router.get("/ips/blocked")
    async def list_blocked_ips() -> dict[str, Any]:
        """Return currently blocked IPs (from rate limit / honeypot bans)."""
        backend = shield.rate_backend
        if backend is None:
            raise HTTPException(404, "Rate limit backend not available")

        # We can only inspect the InMemory backend
        if hasattr(backend, "_bans"):
            banned = {
                ip: {
                    "remaining_seconds": max(
                        0, int(expiry - time.monotonic())
                    ),
                }
                for ip, expiry in backend._bans.items()
                if time.monotonic() < expiry
            }
            return {"blocked_ips": banned, "count": len(banned)}

        return {"blocked_ips": {}, "count": 0, "note": "Redis backend — use Redis CLI"}

    @router.delete("/ips/blocked/{ip}")
    async def unban_ip(ip: str) -> dict[str, str]:
        """Remove an IP from the ban list."""
        backend = shield.rate_backend
        if backend is None:
            raise HTTPException(404, "Rate limit backend not available")

        if hasattr(backend, "_bans") and ip in backend._bans:
            del backend._bans[ip]
            return {"status": "unbanned", "ip": ip}

        raise HTTPException(404, "IP not found in ban list")

    # ── API Keys ────────────────────────────────────────────────

    @router.get("/api-keys")
    async def list_api_keys(
        owner: str | None = Query(default=None),
    ) -> dict[str, Any]:
        """List active API keys, optionally filtered by owner."""
        keys = await shield.api_key_manager.list_keys(owner)
        return {
            "keys": [
                {
                    "prefix": k.prefix,
                    "owner": k.owner,
                    "scopes": [s.value for s in k.scopes],
                    "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                    "created_at": k.created_at.isoformat(),
                    "last_used_at": (
                        k.last_used_at.isoformat()
                        if k.last_used_at else None
                    ),
                    "key_type": k.key_type,
                }
                for k in keys
            ],
            "count": len(keys),
        }

    @router.post("/api-keys/{prefix}/rotate")
    async def rotate_api_key(prefix: str) -> dict[str, Any]:
        """Rotate an API key: revoke old, create new with same params."""
        manager = shield.api_key_manager
        keys = await manager.list_keys()
        old = next((k for k in keys if k.prefix == prefix), None)
        if old is None:
            raise HTTPException(404, "API key not found")

        # Revoke old
        await manager.revoke_key(prefix)

        # Create new with same params
        new = await manager.create_key(
            owner=old.owner,
            scopes=old.scopes,
            label=old.label,
            key_type=old.key_type,
            allowed_ips=old.allowed_ips,
        )
        return {
            "status": "rotated",
            "old_prefix": prefix,
            "new_prefix": new.prefix,
            "new_key": new.raw_key,
        }

    # ── Rate Limit Stats ────────────────────────────────────────

    @router.get("/rate-limit/stats")
    async def rate_limit_stats() -> dict[str, Any]:
        """Return current rate limit counters (InMemory backend only)."""
        backend = shield.rate_backend
        if backend is None:
            raise HTTPException(404, "Rate limit backend not available")

        stats: dict[str, Any] = {"backend": type(backend).__name__}

        if hasattr(backend, "_counters"):
            now = time.monotonic()
            active: dict[str, dict[str, int]] = {}
            for key, (count, window_start) in list(backend._counters.items()):
                window = backend._window_sizes.get(key, 60)
                if now - window_start < window:
                    active[key] = {"count": count, "elapsed": int(now - window_start)}
            stats["active_counters"] = len(active)
            stats["counters"] = active

        return stats

    # ── v0.14 — Secrets Rotation ─────────────────────────────────

    @router.post("/secrets/rotate")
    async def secrets_rotate(body: dict[str, Any]) -> dict[str, Any]:
        """Manually trigger secrets rotation for one or more targets.

        Request body: ``{"targets": ["redis", "postgres"]}``
        """
        scheduler = getattr(shield, "_rotation_scheduler", None)
        if scheduler is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "Secrets rotation is not enabled — configure rotation in AraxysConfig",
            )

        targets: list[str] = body.get("targets", [])
        if not targets:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "Missing required field: targets",
            )

        # Execute rotation for each target, collecting results
        results: dict[str, str] = {}
        for target in targets:
            try:
                await scheduler.rotate_targets([target])
                results[target] = "ok"
            except Exception:
                results[target] = "error"

        return {
            "status": "completed",
            "results": results,
        }

    @router.get("/secrets/status")
    async def secrets_status() -> dict[str, Any]:
        """Return secrets rotation configuration and per-target stats."""
        scheduler = getattr(shield, "_rotation_scheduler", None)
        if scheduler is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "Secrets rotation is not enabled — configure rotation in AraxysConfig",
            )

        target_stats = scheduler.stats()
        return {
            "enabled": True,
            "interval_seconds": scheduler._config.interval_seconds,  # noqa: SLF001
            "targets": list(target_stats.keys()),
            "per_target": target_stats,
        }

    return router


def _bool(val: Any) -> str:
    """Return 'enabled' or 'disabled' for a nullable value."""
    return "enabled" if val is not None else "disabled"
