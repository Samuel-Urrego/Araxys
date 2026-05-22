"""FastAPI dependency injection for WebAuthn.

Provides a ``WebAuthnDependency`` class that can be used with
FastAPI's ``Depends`` to inject the configured ``WebAuthnManager``
into route handlers.
"""

from fastapi import Request

from araxys.webauthn.manager import WebAuthnManager


class WebAuthnDependency:
    """FastAPI dependency that provides the ``WebAuthnManager`` instance.

    Usage::

        from araxys.webauthn.dependencies import WebAuthnDependency
        from fastapi import Depends

        @router.post("/register/begin")
        async def begin_registration(
            webauthn: WebAuthnManager = Depends(WebAuthnDependency()),
        ):
            ...
    """

    async def __call__(self, request: Request) -> WebAuthnManager:
        manager: WebAuthnManager | None = getattr(
            request.app.state, "webauthn_manager", None
        )
        if manager is None:
            from araxys.webauthn.exceptions import WebAuthnError

            raise WebAuthnError(
                "WebAuthnManager not configured on app.state"
            )
        return manager
