"""FastAPI dependency injection for db_security module.

Provides FastAPI dependencies that inject ConnectionPool and QueryAuditor
into route handlers. These use app.state to access the DatabaseSecurityManager.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request  # noqa: TC002 — required at runtime for FastAPI DI

if TYPE_CHECKING:
    from araxys.db_security.audit import QueryAuditor
    from araxys.db_security.pool import ConnectionPool

from araxys.db_security.manager import DatabaseSecurityManager


async def get_db_pool(request: Request) -> ConnectionPool:
    """FastAPI dependency: get the shared connection pool.

    Requires DatabaseSecurityManager to be stored in app.state.db_security.
    Raises RuntimeError if db_security is not initialized.
    """
    db_security = getattr(request.app.state, "db_security", None)
    if not isinstance(db_security, DatabaseSecurityManager):
        raise RuntimeError(
            "DatabaseSecurityManager not initialized. "
            "Ensure app.state.db_security is set "
            "with a DatabaseSecurityManager instance.",
        )
    return db_security.pool


async def get_query_auditor(request: Request) -> QueryAuditor | None:
    """FastAPI dependency: get the query auditor.

    Returns None if query auditing is not enabled.
    """
    db_security = getattr(request.app.state, "db_security", None)
    if not isinstance(db_security, DatabaseSecurityManager):
        return None
    return db_security.auditor
