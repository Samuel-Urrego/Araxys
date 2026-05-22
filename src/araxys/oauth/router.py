"""FastAPI router factory for OAuth2 callback handling.

Uses an in-memory state store with TTL to securely associate PKCE
verifiers with authorization states.

Usage::

    from araxys.oauth import OAuth2Flow, google, create_oauth_router

    flow = OAuth2Flow(google(client_id="...", client_secret="..."), secret_key)
    app.include_router(create_oauth_router({"google": flow}))
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse

if TYPE_CHECKING:
    from araxys.oauth.flow import OAuth2Flow


# ── In-Memory State Store ─────────────────────────────────────────


class _StateStore:
    """Thread-safe in-memory store for OAuth2 state ↔ PKCE verifier + redirect_uri."""

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._store: dict[str, tuple[str, str, float]] = {}
        self._ttl = ttl_seconds

    def put(self, state: str, verifier: str, redirect_uri: str = "") -> None:
        self._cleanup()
        self._store[state] = (verifier, redirect_uri, time.time() + self._ttl)

    def pop(self, state: str) -> tuple[str | None, str]:
        self._cleanup()
        entry = self._store.pop(state, None)
        if entry is None:
            return None, ""
        verifier, redirect_uri, expires = entry
        if time.time() > expires:
            return None, ""
        return verifier, redirect_uri

    def _cleanup(self) -> None:
        now = time.time()
        expired = [s for s, (_, _, e) in self._store.items() if now > e]
        for s in expired:
            self._store.pop(s, None)


# ── Router Factory ────────────────────────────────────────────────


def create_oauth_router(
    flows: dict[str, OAuth2Flow],
    *,
    prefix: str = "/oauth",
    on_login: Any = None,
) -> APIRouter:
    """Create a FastAPI router with OAuth2 login/callback routes.

    Parameters
    ----------
    flows:
        Mapping of provider name → ``OAuth2Flow`` instance.
    prefix:
        URL prefix for the router (default ``/oauth``).
    on_login:
        Optional async callback ``(provider, tokens, userinfo) -> Response``
        called after successful authentication.
    """
    router = APIRouter(prefix=prefix)
    state_store = _StateStore()

    @router.get("/login/{provider}")
    async def login(
        provider: str,
        redirect_uri: str = Query(
            default="/oauth/callback",
            description="Post-login redirect URI",
        ),
    ) -> RedirectResponse:
        """Redirect the user to the OAuth2 provider."""
        flow = flows.get(provider)
        if flow is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown provider: {provider}",
            )

        url, state, verifier = flow.authorization_url(redirect_uri)
        state_store.put(state, verifier, redirect_uri)

        return RedirectResponse(url=url, status_code=302)

    @router.get("/callback/{provider}")
    async def callback(
        provider: str,
        code: str = Query(...),
        state: str = Query(...),
    ) -> Any:
        """Handle the OAuth2 callback."""
        flow = flows.get(provider)
        if flow is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown provider: {provider}",
            )

        verifier, stored_redirect = state_store.pop(state)
        if verifier is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OAuth state",
            )

        # Use the redirect_uri that was originally passed to login(),
        # or derive it from the request's base URL as fallback.
        redirect_uri = stored_redirect or (
            str(router.prefix or "") + f"/callback/{provider}"
        )

        try:
            tokens = await flow.exchange_code(code, redirect_uri, verifier)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Token exchange failed: {exc}",
            ) from exc

        try:
            user = await flow.userinfo(tokens.access_token)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"UserInfo fetch failed: {exc}",
            ) from exc

        if on_login:
            return await on_login(provider, tokens, user)

        return {"provider": provider, "user": user}

    return router
