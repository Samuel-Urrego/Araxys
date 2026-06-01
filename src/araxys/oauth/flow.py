"""OAuth2 / OIDC — Authorization Code flow with PKCE.

Zero external dependencies — uses only stdlib + ``httpx`` (optional,
for token/userinfo HTTP calls).

Supports:
- Authorization Code + PKCE (RFC 7636) — always enabled
- State parameter with HMAC-SHA256 for CSRF protection
- Token exchange (authorization_code → access_token + refresh_token)
- UserInfo endpoint (OIDC standard)
- Pre-configured providers: Google, GitHub, Microsoft

Usage::

    from araxys.oauth import OAuth2Flow, GoogleProvider

    flow = OAuth2Flow(GoogleProvider(client_id="...", client_secret="..."))

    # Step 1: Redirect to authorization URL
    url, state, pkce_verifier = flow.authorization_url(
        redirect_uri="https://app.example.com/callback"
    )

    # Step 2: Handle callback — exchange code for tokens
    tokens = await flow.exchange_code(
        code="...",
        redirect_uri="...",
        pkce_verifier=pkce_verifier,
    )

    # Step 3: Fetch user info
    user = await flow.userinfo(tokens.access_token)

    # Verify state to prevent CSRF
    flow.verify_state(received_state, expected_state)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

# ── Data Classes ──────────────────────────────────────────────────


@dataclass
class OAuth2Tokens:
    """Tokens returned by the token endpoint."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None  # JWT for OIDC
    scope: str = ""


@dataclass
class OAuth2Provider:
    """Configuration for an OAuth2 / OIDC provider.

    Pre-configured instances are available as ``GoogleProvider()``,
    ``GitHubProvider()``, and ``MicrosoftProvider()``.
    """

    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    client_id: str
    client_secret: str = field(repr=False)
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    name: str = "oauth2"

    @property
    def default_scopes(self) -> str:
        return " ".join(self.scopes)

    @classmethod
    async def from_issuer(
        cls,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        *,
        scopes: list[str] | None = None,
        name: str = "oidc",
    ) -> OAuth2Provider:
        """Create an :class:`OAuth2Provider` from an OIDC issuer URL.

        Uses :class:`~araxys.oidc.client.OIDCDiscoveryClient` to fetch
        ``.well-known/openid-configuration`` and auto-populates
        ``authorization_endpoint``, ``token_endpoint``, and
        ``userinfo_endpoint`` from the discovery document.

        Parameters
        ----------
        issuer_url:
            OIDC provider issuer URL.
        client_id:
            OAuth2 client identifier.
        client_secret:
            OAuth2 client secret (stored with ``repr=False``).
        scopes:
            OAuth2 scopes to request (defaults to ``["openid", "email",
            "profile"]``).
        name:
            Provider name identifier (defaults to ``"oidc"``).

        Returns
        -------
        OAuth2Provider
            Configured provider instance.

        Raises
        ------
        OIDCDiscoveryError
            If discovery fails (network, timeout, or invalid metadata).
        """
        from araxys.oidc.client import OIDCDiscoveryClient

        client = OIDCDiscoveryClient()
        metadata = await client.discover(issuer_url)

        return cls(
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            userinfo_endpoint=metadata.userinfo_endpoint or "",
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes if scopes is not None else ["openid", "email", "profile"],
            name=name,
        )


# ── OAuth2 Flow ───────────────────────────────────────────────────


class OAuth2Flow:
    """OAuth2 Authorization Code flow with PKCE (always enabled).

    Parameters
    ----------
    provider:
        OAuth2 provider configuration.
    secret_key:
        Master secret key for HMAC state signing.
    """

    def __init__(self, provider: OAuth2Provider, secret_key: str) -> None:
        self._provider = provider
        self._key = secret_key.encode("utf-8")

    # ── Step 1: Authorization URL ──────────────────────────────

    def authorization_url(
        self,
        redirect_uri: str,
        *,
        state: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[str, str, str]:
        """Build the authorization URL and return PKCE parameters.

        Returns ``(url, state, code_verifier)``.  Store ``state`` and
        ``code_verifier`` to verify/use in the callback.
        """
        code_verifier = self._generate_code_verifier()
        code_challenge = self._compute_code_challenge(code_verifier)

        if state is None:
            state = secrets.token_urlsafe(32)

        params = {
            "response_type": "code",
            "client_id": self._provider.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes) if scopes else self._provider.default_scopes,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        base_url = self._provider.authorization_endpoint
        url = f"{base_url}?{urllib.parse.urlencode(params)}"
        return url, state, code_verifier

    # ── Step 2: Token Exchange ─────────────────────────────────

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuth2Tokens:
        """Exchange authorization code for tokens."""
        import httpx

        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._provider.client_id,
            "client_secret": self._provider.client_secret,
            "code_verifier": code_verifier,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._provider.token_endpoint,
                data=payload,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuth2Tokens(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope", ""),
        )

    # ── Refresh Token ──────────────────────────────────────────

    async def refresh_access_token(
        self, refresh_token: str, scopes: list[str] | None = None
    ) -> OAuth2Tokens:
        """Use a refresh token to obtain new tokens."""
        import httpx

        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._provider.client_id,
            "client_secret": self._provider.client_secret,
        }
        if scopes:
            payload["scope"] = " ".join(scopes)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._provider.token_endpoint,
                data=payload,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuth2Tokens(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token", refresh_token),
            scope=data.get("scope", ""),
        )

    # ── Step 3: UserInfo ───────────────────────────────────────

    async def userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch user info from the provider's UserInfo endpoint."""
        import httpx

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._provider.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data

    # ── State Verification (CSRF protection) ────────────────────

    def sign_state(self, data: str) -> str:
        """Sign auxiliary state data with HMAC-SHA256.

        Returns ``data.hmac_hex`` so the state can be verified in
        the callback.
        """
        sig = hmac.new(self._key, data.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{data}.{sig}"

    def verify_state(self, state: str, expected_data: str) -> bool:
        """Verify that *state* was signed for *expected_data*."""
        if "." not in state:
            return False
        data, sig = state.rsplit(".", 1)
        expected = hmac.new(
            self._key, expected_data.encode(), hashlib.sha256
        ).hexdigest()[:16]
        return hmac.compare_digest(data, expected_data) and hmac.compare_digest(
            sig, expected
        )

    # ── Internal: PKCE ─────────────────────────────────────────

    @staticmethod
    def _generate_code_verifier() -> str:
        """RFC 7636: 43-128 char URL-safe random string."""
        return secrets.token_urlsafe(32)  # 43 chars

    @staticmethod
    def _compute_code_challenge(verifier: str) -> str:
        """RFC 7636 S256: base64url(sha256(ascii(verifier)))."""
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
