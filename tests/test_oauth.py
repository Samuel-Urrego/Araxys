"""Tests for the OAuth2/OIDC module."""

from __future__ import annotations

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
