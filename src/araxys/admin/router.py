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
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Query

if TYPE_CHECKING:
    from araxys.shield import AraxysShield


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
    router = APIRouter(prefix=prefix, tags=["admin"])

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

    return router


def _bool(val: Any) -> str:
    """Return 'enabled' or 'disabled' for a nullable value."""
    return "enabled" if val is not None else "disabled"
