"""Tests for the OAuth2/OIDC module."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from araxys.oauth.flow import OAuth2Flow, OAuth2Provider


class TestOAuth2Flow:
    """Tests for the OAuth2 PKCE flow."""

    def test_authorization_url_returns_pkce_params(self) -> None:
        """authorization_url should return URL, state, and verifier."""
        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")

        url, state, verifier = flow.authorization_url("https://app.example.com/cb")
        assert "https://example.com/auth" in url
        assert "response_type=code" in url
        assert "code_challenge_method=S256" in url
        assert "code_challenge=" in url
        assert len(state) > 20
        assert len(verifier) == 43  # token_urlsafe(32)

    def test_authorization_url_custom_scopes(self) -> None:
        """Custom scopes should override provider defaults."""
        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        url, _, _ = flow.authorization_url(
            "https://app.example.com/cb", scopes=["custom", "scopes"]
        )
        assert "scope=custom+scopes" in url

    def test_pkce_verifiers_are_unique(self) -> None:
        """Each call should produce different verifiers."""
        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, v1 = flow.authorization_url("https://a.example.com/cb")
        _, _, v2 = flow.authorization_url("https://a.example.com/cb")
        assert v1 != v2

    def test_code_challenge_is_base64url_sha256(self) -> None:
        """code_challenge should be base64url(sha256(verifier))."""
        import base64
        import hashlib

        verifier = "test-verifier-string-for-pkce"
        challenge = OAuth2Flow._compute_code_challenge(verifier)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert challenge == expected

    @patch("httpx.AsyncClient")
    async def test_exchange_code(self, mock_client_cls: MagicMock) -> None:
        """Token exchange should return OAuth2Tokens."""
        mock_resp = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "access_token": "at-123",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "rt-456",
            "scope": "openid email",
        })
        mock_resp.raise_for_status = MagicMock()
        mock_resp.is_success = True
        mock_resp.status_code = 200

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        _, _, verifier = flow.authorization_url("https://app.example.com/cb")

        tokens = await flow.exchange_code(
            "auth-code", "https://app.example.com/cb", verifier
        )
        assert tokens.access_token == "at-123"
        assert tokens.refresh_token == "rt-456"

    @patch("httpx.AsyncClient")
    async def test_userinfo(self, mock_client_cls: MagicMock) -> None:
        """userinfo should return parsed JSON."""
        mock_resp = MagicMock()
        mock_resp.json = MagicMock(
            return_value={"sub": "123", "email": "alice@example.com"}
        )
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        user = await flow.userinfo("at-123")
        assert user["email"] == "alice@example.com"

    def test_sign_and_verify_state(self) -> None:
        """Signed state should be verifiable."""
        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        signed = flow.sign_state("my-data")
        assert "." in signed
        assert flow.verify_state(signed, "my-data")

    def test_verify_state_tampered(self) -> None:
        """Tampered state should fail verification."""
        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        signed = flow.sign_state("my-data")
        assert not flow.verify_state(signed, "wrong-data")
        assert not flow.verify_state(signed + "x", "my-data")

    @patch("httpx.AsyncClient")
    async def test_refresh_access_token(self, mock_client_cls: MagicMock) -> None:
        """Refresh should return new tokens."""
        mock_resp = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "access_token": "new-at-789",
            "token_type": "bearer",
            "expires_in": 3600,
        })
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        provider = OAuth2Provider(
            authorization_endpoint="https://example.com/auth",
            token_endpoint="https://example.com/token",
            userinfo_endpoint="https://example.com/userinfo",
            client_id="test-client",
            client_secret="test-secret",
        )
        flow = OAuth2Flow(provider, secret_key="test-key-32-chars-long!!!!!!!!!!!!")
        tokens = await flow.refresh_access_token("rt-old")
        assert tokens.access_token == "new-at-789"


class TestProviders:
    """Tests for pre-configured providers."""

    def test_google_provider(self) -> None:
        from araxys.oauth.providers import google

        p = google(client_id="cid", client_secret="csec")
        assert "accounts.google.com" in p.authorization_endpoint
        assert "googleapis" in p.token_endpoint
        assert "openid" in p.scopes

    def test_github_provider(self) -> None:
        from araxys.oauth.providers import github

        p = github(client_id="cid", client_secret="csec")
        assert "github.com" in p.authorization_endpoint
        assert "api.github.com" in p.userinfo_endpoint

    def test_microsoft_provider(self) -> None:
        from araxys.oauth.providers import microsoft

        p = microsoft(client_id="cid", client_secret="csec")
        assert "login.microsoftonline.com" in p.authorization_endpoint
        assert p.name == "microsoft"

    def test_microsoft_custom_tenant(self) -> None:
        from araxys.oauth.providers import microsoft

        p = microsoft(client_id="cid", client_secret="csec", tenant="my-tenant-id")
        assert "my-tenant-id" in p.authorization_endpoint


# ═══════════════════════════════════════════════════════════════════
# Task 2.3 — OAuth2Provider.from_issuer() (async classmethod)
# ═══════════════════════════════════════════════════════════════════


class TestOAuth2ProviderFromIssuer:
    """OAuth2Provider.from_issuer() — auto-populate from OIDC discovery."""

    @staticmethod
    def _mock_metadata() -> tuple[Any, Any]:
        """Build mock OIDCProviderMetadata + patch for discover()."""
        from unittest.mock import AsyncMock, patch

        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://accounts.example.com",
            authorization_endpoint="https://accounts.example.com/authorize",
            token_endpoint="https://accounts.example.com/token",
            jwks_uri="https://accounts.example.com/jwks",
            userinfo_endpoint="https://accounts.example.com/userinfo",
        )
        patcher = patch(
            "araxys.oidc.client.OIDCDiscoveryClient.discover",
            new_callable=AsyncMock,
            return_value=meta,
        )
        return meta, patcher

    async def test_from_issuer_populates_endpoints(self) -> None:
        """from_issuer() should discover and populate all endpoints."""
        from araxys.oauth.flow import OAuth2Provider

        meta, patcher = self._mock_metadata()
        patcher.start()

        try:
            provider = await OAuth2Provider.from_issuer(
                issuer_url="https://accounts.example.com",
                client_id="test-client-id",
                client_secret="test-client-secret",
            )
        finally:
            patcher.stop()

        assert provider.authorization_endpoint == meta.authorization_endpoint
        assert provider.token_endpoint == meta.token_endpoint
        assert provider.userinfo_endpoint == meta.userinfo_endpoint
        assert provider.client_id == "test-client-id"
        assert provider.client_secret == "test-client-secret"

    async def test_from_issuer_custom_scopes_and_name(self) -> None:
        """Custom scopes and name should override defaults."""
        from araxys.oauth.flow import OAuth2Provider

        _, patcher = self._mock_metadata()
        patcher.start()

        try:
            provider = await OAuth2Provider.from_issuer(
                issuer_url="https://accounts.example.com",
                client_id="cid",
                client_secret="csec",
                scopes=["custom", "scopes"],
                name="my-provider",
            )
        finally:
            patcher.stop()

        assert provider.scopes == ["custom", "scopes"]
        assert provider.name == "my-provider"

    async def test_from_issuer_default_scopes_and_name(self) -> None:
        """Default scopes and name should be used when not provided."""
        from araxys.oauth.flow import OAuth2Provider

        _, patcher = self._mock_metadata()
        patcher.start()

        try:
            provider = await OAuth2Provider.from_issuer(
                issuer_url="https://accounts.example.com",
                client_id="cid",
                client_secret="csec",
            )
        finally:
            patcher.stop()

        assert provider.scopes == ["openid", "email", "profile"]
        assert provider.name == "oidc"

    async def test_from_issuer_propagates_discovery_error(self) -> None:
        """Discovery errors must propagate as OIDCDiscoveryError."""
        from unittest.mock import AsyncMock, patch

        import pytest

        from araxys.core.exceptions import OIDCDiscoveryError
        from araxys.oauth.flow import OAuth2Provider

        patcher = patch(
            "araxys.oidc.client.OIDCDiscoveryClient.discover",
            new_callable=AsyncMock,
            side_effect=OIDCDiscoveryError(
                issuer_url="https://bad.example.com",
                detail="Connection refused",
            ),
        )
        patcher.start()

        try:
            with pytest.raises(OIDCDiscoveryError, match="Connection refused"):
                await OAuth2Provider.from_issuer(
                    issuer_url="https://bad.example.com",
                    client_id="cid",
                    client_secret="csec",
                )
        finally:
            patcher.stop()

    async def test_from_issuer_passes_issuer_url_to_discovery(self) -> None:
        """The issuer_url must be forwarded to the discovery client."""
        from unittest.mock import AsyncMock, patch

        from araxys.oauth.flow import OAuth2Provider
        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://my-idp.example.com",
            authorization_endpoint="https://my-idp.example.com/authorize",
            token_endpoint="https://my-idp.example.com/token",
            jwks_uri="https://my-idp.example.com/jwks",
            userinfo_endpoint="https://my-idp.example.com/userinfo",
        )
        mock_discover = AsyncMock(return_value=meta)
        patcher = patch(
            "araxys.oidc.client.OIDCDiscoveryClient.discover",
            new=mock_discover,
        )
        patcher.start()

        try:
            await OAuth2Provider.from_issuer(
                issuer_url="https://my-idp.example.com",
                client_id="cid",
                client_secret="csec",
            )
        finally:
            patcher.stop()

        mock_discover.assert_awaited_once_with("https://my-idp.example.com")

    # ── Triangulation: userinfo_endpoint None fallback ──────────────

    async def test_from_issuer_userinfo_none_fallback(self) -> None:
        """When metadata has userinfo_endpoint=None, it must fall back to ''."""
        from unittest.mock import AsyncMock, patch

        from araxys.oauth.flow import OAuth2Provider
        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://x.com",
            authorization_endpoint="https://x.com/authorize",
            token_endpoint="https://x.com/token",
            jwks_uri="https://x.com/jwks",
            # userinfo_endpoint defaults to None
        )
        patcher = patch(
            "araxys.oidc.client.OIDCDiscoveryClient.discover",
            new_callable=AsyncMock,
            return_value=meta,
        )
        patcher.start()

        try:
            provider = await OAuth2Provider.from_issuer(
                issuer_url="https://x.com",
                client_id="cid",
                client_secret="csec",
            )
        finally:
            patcher.stop()

        assert provider.userinfo_endpoint == ""
        assert provider.authorization_endpoint == "https://x.com/authorize"
        assert provider.token_endpoint == "https://x.com/token"
