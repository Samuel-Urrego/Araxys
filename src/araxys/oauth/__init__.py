"""OAuth2 / OIDC — Authorization Code flow with PKCE.

Zero external OAuth dependencies.  Uses ``httpx`` for HTTP calls.

Provides:
- ``OAuth2Provider`` — provider configuration (endpoints, credentials)
- ``OAuth2Flow`` — PKCE flow (authorize, exchange, refresh, userinfo)
- ``create_oauth_router()`` — FastAPI router with login/callback routes
- Pre-configured providers: ``google()``, ``github()``, ``microsoft()``
"""

from araxys.oauth.flow import OAuth2Flow, OAuth2Provider, OAuth2Tokens
from araxys.oauth.providers import github, google, microsoft
from araxys.oauth.router import create_oauth_router

__all__ = [
    "OAuth2Flow",
    "OAuth2Provider",
    "OAuth2Tokens",
    "create_oauth_router",
    "google",
    "github",
    "microsoft",
]
