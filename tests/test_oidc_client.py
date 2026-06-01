"""Tests for OIDCDiscoveryClient (Task 2.1)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from araxys.core.config import OIDCDiscoveryConfig
from araxys.core.exceptions import OIDCDiscoveryError
from araxys.oidc.models import OIDCProviderMetadata


# Fixture: valid discovery JSON response
VALID_DISCOVERY_RESPONSE = {
    "issuer": "https://accounts.example.com",
    "authorization_endpoint": "https://accounts.example.com/authorize",
    "token_endpoint": "https://accounts.example.com/token",
    "jwks_uri": "https://accounts.example.com/jwks",
    "userinfo_endpoint": "https://accounts.example.com/userinfo",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code", "id_token"],
}


def _make_mock_httpx_response(
    json_data: dict | str | None = None,
    status_code: int = 200,
) -> MagicMock:
    """Build a mock httpx.Response with the given JSON body and status."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    mock_resp.is_success = status_code < 400
    if isinstance(json_data, dict):
        mock_resp.json = MagicMock(return_value=json_data)
    elif isinstance(json_data, str):
        mock_resp.json = MagicMock(side_effect=ValueError(json_data))
    else:
        mock_resp.json = MagicMock(return_value={})
    mock_resp.raise_for_status = MagicMock()
    if status_code >= 400:
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=mock_resp
        )
    return mock_resp


def _patch_async_client(mock_resp: MagicMock) -> MagicMock:
    """Patch httpx.AsyncClient to return the given mock response for GET."""
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ═══════════════════════════════════════════════════════════════════
# RED tests — written BEFORE implementation (Task 2.1)
# ═══════════════════════════════════════════════════════════════════


class TestOIDCDiscoveryClient:
    """OIDCDiscoveryClient — fetch + cache + validate discovery documents."""

    # ── Happy path ────────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_returns_metadata(self, mock_client_cls: MagicMock) -> None:
        """discover() should return OIDCProviderMetadata from valid JSON."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        meta = await client.discover("https://accounts.example.com")

        assert isinstance(meta, OIDCProviderMetadata)
        assert meta.issuer == "https://accounts.example.com"
        assert (
            meta.authorization_endpoint
            == "https://accounts.example.com/authorize"
        )
        assert meta.token_endpoint == "https://accounts.example.com/token"
        assert meta.jwks_uri == "https://accounts.example.com/jwks"
        assert meta.userinfo_endpoint == "https://accounts.example.com/userinfo"
        assert meta.scopes_supported == ["openid", "profile", "email"]

    # ── Trailing slash ────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_strips_trailing_slash(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Issuer with trailing slash should be normalized before fetch."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        await client.discover("https://accounts.example.com/")

        # Verify the GET was called with a normalized URL (no double slash)
        call_args = mock_client.get.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        assert "//.well-known" not in url
        assert url == "https://accounts.example.com/.well-known/openid-configuration"

    # ── Cache hit ─────────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_cache_hit_within_ttl(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Second call within TTL should return cached result without HTTP."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(cache_ttl_seconds=300)
        )
        meta1 = await client.discover("https://accounts.example.com")
        meta2 = await client.discover("https://accounts.example.com")

        # Only one HTTP call should have been made
        assert mock_client.get.call_count == 1
        # Same object returned (reference equality for Pydantic model)
        assert meta2.issuer == meta1.issuer

    # ── Cache expiry ──────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    @patch("time.time")
    async def test_cache_expiry_makes_fresh_request(
        self, mock_time: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        """Cache miss after TTL expiry should trigger a new HTTP request."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        # First call at t=100
        mock_time.return_value = 100.0
        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(cache_ttl_seconds=300)
        )
        await client.discover("https://accounts.example.com")
        assert mock_client.get.call_count == 1

        # Second call at t=500 (> 100 + 300)
        mock_time.return_value = 500.0
        await client.discover("https://accounts.example.com")
        assert mock_client.get.call_count == 2

    # ── HTTP error ────────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_http_404_raises(
        self, mock_client_cls: MagicMock
    ) -> None:
        """404 from well-known endpoint should raise OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(status_code=404)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="discovery"):
            await client.discover("https://accounts.example.com")

    # ── Non-JSON response ─────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_non_json_raises(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Non-JSON body from well-known should raise OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(
            json_data="<html>Not Found</html>", status_code=200
        )
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="discovery"):
            await client.discover("https://accounts.example.com")

    # ── Timeout ───────────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_timeout_raises(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Network timeout should raise OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="Timeout"):
            await client.discover("https://accounts.example.com")

    # ── Custom config ─────────────────────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_discover_default_config(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Client with no config should use sensible defaults."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        meta = await client.discover("https://accounts.example.com")
        assert meta.issuer == "https://accounts.example.com"

        # Verify httpx.AsyncClient was created with defaults
        args, kwargs = mock_client_cls.call_args
        assert kwargs.get("verify", True) is True  # default verify_ssl=True

    # ── Triangulation: different issuers cached separately ────────

    @patch("httpx.AsyncClient")
    async def test_different_issuers_cached_independently(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Two different issuer URLs must each trigger a fetch + separate cache."""
        from araxys.oidc.client import OIDCDiscoveryClient

        issuer_a = VALID_DISCOVERY_RESPONSE
        issuer_b = {
            **VALID_DISCOVERY_RESPONSE,
            "issuer": "https://other.example.com",
            "authorization_endpoint": "https://other.example.com/authorize",
            "token_endpoint": "https://other.example.com/token",
            "jwks_uri": "https://other.example.com/jwks",
        }

        mock_resp_a = _make_mock_httpx_response(issuer_a)
        mock_resp_b = _make_mock_httpx_response(issuer_b)

        # Use two separate mock clients for precise call tracking
        mock_client_a = _patch_async_client(mock_resp_a)
        mock_client_b = _patch_async_client(mock_resp_b)
        mock_client_cls.side_effect = [mock_client_a, mock_client_b]

        client = OIDCDiscoveryClient()
        meta1 = await client.discover("https://accounts.example.com")
        meta2 = await client.discover("https://other.example.com")

        assert meta1.issuer == "https://accounts.example.com"
        assert meta2.issuer == "https://other.example.com"
        # Both clients were used exactly once
        assert mock_client_a.get.call_count == 1
        assert mock_client_b.get.call_count == 1

    # ── Triangulation: custom config with SSL disabled ─────────────

    @patch("httpx.AsyncClient")
    async def test_custom_config_verify_ssl_false(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Config with verify_ssl=False should pass verify=False to httpx."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(verify_ssl=False)
        )
        await client.discover("https://accounts.example.com")

        _, kwargs = mock_client_cls.call_args
        assert kwargs.get("verify") is False

    # ── Triangulation: custom timeout ──────────────────────────────

    @patch("httpx.AsyncClient")
    async def test_custom_config_timeout(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Config with custom timeout should be passed to httpx."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(timeout_seconds=5)
        )
        await client.discover("https://accounts.example.com")

        _, kwargs = mock_client_cls.call_args
        assert kwargs.get("timeout") == 5

    # ── Triangulation: trailing-slash cache normalization ───────────

    @patch("httpx.AsyncClient")
    @patch("time.time")
    async def test_trailing_slash_cache_normalization(
        self, mock_time: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        """Issuer with trailing slash should share cache with normalized form."""
        from araxys.oidc.client import OIDCDiscoveryClient

        mock_resp = _make_mock_httpx_response(VALID_DISCOVERY_RESPONSE)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        mock_time.return_value = 100.0
        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(cache_ttl_seconds=300)
        )
        # First call with trailing slash
        meta1 = await client.discover("https://accounts.example.com/")
        assert mock_client.get.call_count == 1

        # Second call without trailing slash — should be cache HIT
        meta2 = await client.discover("https://accounts.example.com")
        assert mock_client.get.call_count == 1  # still 1 — no new HTTP
        assert meta1.issuer == meta2.issuer


# ═══════════════════════════════════════════════════════════════════
# Task 3.1 — Missing required fields → OIDCDiscoveryError via client
# ═══════════════════════════════════════════════════════════════════


class TestOIDCProviderMetadataValidation:
    """Client must raise OIDCDiscoveryError when JSON response is
    missing required fields (issuer, jwks_uri, etc.)."""

    @patch("httpx.AsyncClient")
    async def test_discover_missing_issuer_raises_discovery_error(
        self, mock_client_cls: MagicMock
    ) -> None:
        """JSON response without 'issuer' must raise OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        missing_issuer = {
            "authorization_endpoint": "https://x.com/authorize",
            "token_endpoint": "https://x.com/token",
            "jwks_uri": "https://x.com/jwks",
        }
        mock_resp = _make_mock_httpx_response(missing_issuer)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="Invalid metadata"):
            await client.discover("https://accounts.example.com")

    @patch("httpx.AsyncClient")
    async def test_discover_missing_jwks_uri_raises_discovery_error(
        self, mock_client_cls: MagicMock
    ) -> None:
        """JSON response without 'jwks_uri' must raise OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        missing_jwks = {
            "issuer": "https://x.com",
            "authorization_endpoint": "https://x.com/authorize",
            "token_endpoint": "https://x.com/token",
        }
        mock_resp = _make_mock_httpx_response(missing_jwks)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="jwks_uri"):
            await client.discover("https://accounts.example.com")

    @patch("httpx.AsyncClient")
    async def test_discover_missing_authorization_endpoint_raises_discovery_error(
        self, mock_client_cls: MagicMock
    ) -> None:
        """JSON response without 'authorization_endpoint' must raise
        OIDCDiscoveryError."""
        from araxys.oidc.client import OIDCDiscoveryClient

        missing_auth = {
            "issuer": "https://x.com",
            "token_endpoint": "https://x.com/token",
            "jwks_uri": "https://x.com/jwks",
        }
        mock_resp = _make_mock_httpx_response(missing_auth)
        mock_client = _patch_async_client(mock_resp)
        mock_client_cls.return_value = mock_client

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="authorization_endpoint"):
            await client.discover("https://accounts.example.com")


# ═══════════════════════════════════════════════════════════════════
# Task 2.2 — araxys.oidc exports
# ═══════════════════════════════════════════════════════════════════


class TestOIDCInitExports:
    """Verify OIDC module exports from araxys.oidc."""

    def test_oidc_discovery_client_exported(self) -> None:
        """OIDCDiscoveryClient must be importable from araxys.oidc."""
        from araxys.oidc import OIDCDiscoveryClient  # noqa: F811
        assert OIDCDiscoveryClient is not None

    def test_oidc_provider_metadata_exported(self) -> None:
        """OIDCProviderMetadata must be importable from araxys.oidc."""
        from araxys.oidc import OIDCProviderMetadata
        assert OIDCProviderMetadata is not None
