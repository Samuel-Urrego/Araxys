"""FastAPI dependencies for CSRF token validation.

Provides ``csrf_protected`` as a per-route FastAPI dependency and
``set_csrf_cookie`` as a utility to set the CSRF cookie on responses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException
from starlette.requests import (
    Request,  # noqa: TC002 — needed at runtime for FastAPI injection
)
from starlette.responses import Response  # noqa: TC002 — used at runtime as param type

from araxys.csrf.tokens import CSRFHandler

if TYPE_CHECKING:
    from araxys.core.config import CSRFConfig


def csrf_protected(config: CSRFConfig) -> Any:
    """FastAPI dependency that enforces CSRF double-submit cookie validation.

    Usage::

        from fastapi import Depends
        from araxys.csrf.dependencies import csrf_protected

        @app.post("/transfer")
        async def transfer(
            _: None = Depends(csrf_protected(csrf_config)),
            ...
        ):
            ...

    Parameters
    ----------
    config:
        The CSRF configuration determining cookie/header names.
    """

    async def dependency(request: Request) -> None:
        """Inner dependency: extract tokens and validate."""
        header_token = request.headers.get(config.header_name)
        cookie_token = request.cookies.get(config.cookie_name)

        if not header_token or not cookie_token:
            raise HTTPException(status_code=403, detail="CSRF token missing")

        if not CSRFHandler.validate_token(header_token, cookie_token):
            raise HTTPException(status_code=403, detail="CSRF token mismatch")

    return dependency


def set_csrf_cookie(
    response: Response,
    handler: CSRFHandler,
    config: CSRFConfig,
) -> None:
    """Set the CSRF cookie on a response (typically after login).

    Generates a fresh CSRF token, creates the ``Set-Cookie`` header,
    and appends it to the response.

    Parameters
    ----------
    response:
        The response to attach the cookie to.
    handler:
        The CSRF handler for token generation.
    config:
        The CSRF configuration.
    """
    token = handler.generate_token(expiry_seconds=config.token_expiry_seconds)
    cookie_value = handler.create_cookie(token, config)
    response.headers.append("Set-Cookie", cookie_value)
