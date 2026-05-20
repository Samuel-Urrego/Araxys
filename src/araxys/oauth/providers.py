"""Pre-configured OAuth2 / OIDC providers.

Each provider is a factory function that returns an ``OAuth2Provider``
with the correct endpoints.  Only ``client_id`` and ``client_secret``
are required — everything else is pre-configured.

Usage::

    from araxys.oauth.providers import google

    provider = google(
        client_id="...apps.googleusercontent.com",
        client_secret="GOCSPX-...",
    )
"""

from __future__ import annotations

from araxys.oauth.flow import OAuth2Provider


def google(
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
) -> OAuth2Provider:
    """Google OAuth2 / OIDC provider.

    Requires a Google Cloud project with the OAuth2 consent screen
    configured.  ``redirect_uri`` must match exactly.
    """
    return OAuth2Provider(
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes or ["openid", "email", "profile"],
        name="google",
    )


def github(
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
) -> OAuth2Provider:
    """GitHub OAuth2 provider.

    Register a GitHub OAuth App at:
    https://github.com/settings/developers

    GitHub does NOT support OIDC (no ``openid`` scope).  The UserInfo
    response follows GitHub's REST API format.

    The ``userinfo()`` call returns the GitHub ``/user`` endpoint
    response.  To get the user's email, include ``user:email`` scope
    and call ``/user/emails`` separately.
    """
    return OAuth2Provider(
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        userinfo_endpoint="https://api.github.com/user",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes or ["read:user", "user:email"],
        name="github",
    )


def microsoft(
    client_id: str,
    client_secret: str,
    *,
    tenant: str = "common",
    scopes: list[str] | None = None,
) -> OAuth2Provider:
    """Microsoft Entra ID (Azure AD) OIDC provider.

    Set *tenant* to ``"common"`` for multi-tenant, ``"organizations"``
    for work/school accounts, ``"consumers"`` for personal accounts,
    or a specific tenant ID.

    Register an app at: https://portal.azure.com → App registrations
    """
    base = f"https://login.microsoftonline.com/{tenant}"
    return OAuth2Provider(
        authorization_endpoint=f"{base}/oauth2/v2.0/authorize",
        token_endpoint=f"{base}/oauth2/v2.0/token",
        userinfo_endpoint="https://graph.microsoft.com/oidc/userinfo",
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes or ["openid", "email", "profile"],
        name="microsoft",
    )
