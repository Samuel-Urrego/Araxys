"""FastAPI dependencies for RBAC permission enforcement.

Usage::

    from fastapi import Depends
    from araxys.rbac import RBACEngine, require_permission

    engine = RBACEngine()
    engine.add_role("editor", permissions=["articles:*"])

    @app.get("/articles")
    async def list_articles(
        _: None = Depends(
            require_permission(engine, "articles:read", get_roles=...)
        ),
    ):
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from collections.abc import Callable

    from araxys.rbac.engine import RBACEngine


def require_permission(
    engine: RBACEngine,
    permission: str,
    *,
    get_roles: Callable[..., list[str]] | None = None,
) -> Any:
    """FastAPI dependency that enforces a single permission.

    Parameters
    ----------
    engine:
        The RBAC engine instance.
    permission:
        Required permission (e.g. ``"users:read"``).
    get_roles:
        Callable that returns the current user's role names.
        Typically reads from the JWT token payload or database.
    """

    async def dependency() -> None:
        if get_roles is None:
            return  # passthrough when not configured

        roles = get_roles()
        if not engine.has_permission(roles, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}",
            )

    return dependency


def require_any_permission(
    engine: RBACEngine,
    permissions: list[str],
    *,
    get_roles: Callable[..., list[str]] | None = None,
) -> Any:
    """FastAPI dependency that requires *any* of the given permissions."""

    async def dependency() -> None:
        if get_roles is None:
            return

        roles = get_roles()
        if not engine.has_any_permission(roles, permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission (need any of: {permissions})",
            )

    return dependency


def require_all_permissions(
    engine: RBACEngine,
    permissions: list[str],
    *,
    get_roles: Callable[..., list[str]] | None = None,
) -> Any:
    """FastAPI dependency that requires *all* given permissions."""

    async def dependency() -> None:
        if get_roles is None:
            return

        roles = get_roles()
        if not engine.has_all_permissions(roles, permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions (need all: {permissions})",
            )

    return dependency
