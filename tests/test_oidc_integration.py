"""Integration tests for OIDC Discovery (Task 3.3).

Uses ``respx`` to mock HTTP at the transport layer, so the real
``httpx.AsyncClient`` is exercised through its actual call stack.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from araxys.core.config import OIDCDiscoveryConfig
from araxys.core.exceptions import OIDCDiscoveryError
from araxys.oidc.client import OIDCDiscoveryClient
from araxys.oidc.models import OIDCProviderMetadata

VALID_METADATA = {
    "issuer": "https://accounts.example.com",
    "authorization_endpoint": "https://accounts.example.com/authorize",
    "token_endpoint": "https://accounts.example.com/token",
    "jwks_uri": "https://accounts.example.com/jwks",
    "userinfo_endpoint": "https://accounts.example.com/userinfo",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code", "id_token"],
}


class TestOIDCDiscoveryIntegration:
    """Integration tests — respx intercepts HTTP at the transport."""

    @respx.mock
    async def test_discover_valid_metadata(self) -> None:
        """End-to-end discover() returns OIDCProviderMetadata from mocked API."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        respx.get(well_known_url).mock(
            return_value=httpx.Response(200, json=VALID_METADATA)
        )

        client = OIDCDiscoveryClient()
        meta = await client.discover("https://accounts.example.com")

        assert isinstance(meta, OIDCProviderMetadata)
        assert meta.issuer == "https://accounts.example.com"
        assert meta.authorization_endpoint == "https://accounts.example.com/authorize"
        assert meta.token_endpoint == "https://accounts.example.com/token"
        assert meta.jwks_uri == "https://accounts.example.com/jwks"
        assert meta.userinfo_endpoint == "https://accounts.example.com/userinfo"
        assert meta.scopes_supported == ["openid", "profile", "email"]

    @respx.mock
    async def test_discover_with_trailing_slash(self) -> None:
        """Trailing slash in issuer URL must be normalized before fetch."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        # Register the normalized URL
        respx.get(well_known_url).mock(
            return_value=httpx.Response(200, json=VALID_METADATA)
        )

        client = OIDCDiscoveryClient()
        meta = await client.discover("https://accounts.example.com/")

        assert meta.issuer == "https://accounts.example.com"
        # The trailing-slash variant must not be registered
        assert respx.calls.call_count == 1

    @respx.mock
    async def test_discover_http_404_raises(self) -> None:
        """404 from well-known endpoint must raise OIDCDiscoveryError."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        respx.get(well_known_url).mock(return_value=httpx.Response(404))

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="HTTP 404"):
            await client.discover("https://accounts.example.com")

    @respx.mock
    async def test_discover_non_json_body_raises(self) -> None:
        """Non-JSON body (text/html) must raise OIDCDiscoveryError."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        respx.get(well_known_url).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>Internal Server Error</html>",
                headers={"content-type": "text/html"},
            )
        )

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="discovery"):
            await client.discover("https://accounts.example.com")

    @respx.mock
    async def test_discover_timeout_raises(self) -> None:
        """Network timeout must raise OIDCDiscoveryError."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        respx.get(well_known_url).mock(side_effect=httpx.TimeoutException("timeout"))

        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(timeout_seconds=1)
        )
        with pytest.raises(OIDCDiscoveryError, match="Timeout"):
            await client.discover("https://accounts.example.com")

    @respx.mock
    async def test_discover_connection_refused_raises(self) -> None:
        """Connection refused must raise OIDCDiscoveryError."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        respx.get(well_known_url).mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="Connection refused"):
            await client.discover("https://accounts.example.com")

    @respx.mock
    async def test_cache_hit_integration(self) -> None:
        """Second call within TTL must return cached result (0 HTTP calls)."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        route = respx.get(well_known_url).mock(
            return_value=httpx.Response(200, json=VALID_METADATA)
        )

        client = OIDCDiscoveryClient(
            OIDCDiscoveryConfig(cache_ttl_seconds=300)
        )
        meta1 = await client.discover("https://accounts.example.com")
        assert route.call_count == 1

        meta2 = await client.discover("https://accounts.example.com")
        assert route.call_count == 1  # cached — no second HTTP call

        assert meta1.issuer == meta2.issuer
        assert meta1.authorization_endpoint == meta2.authorization_endpoint

    @respx.mock
    async def test_missing_required_field_in_json_raises(self) -> None:
        """JSON response missing a required field must raise
        OIDCDiscoveryError."""
        well_known_url = (
            "https://accounts.example.com/.well-known/openid-configuration"
        )
        missing_jwks = {
            "issuer": "https://accounts.example.com",
            "authorization_endpoint": "https://accounts.example.com/authorize",
            "token_endpoint": "https://accounts.example.com/token",
            # jwks_uri intentionally missing
        }
        respx.get(well_known_url).mock(
            return_value=httpx.Response(200, json=missing_jwks)
        )

        client = OIDCDiscoveryClient()
        with pytest.raises(OIDCDiscoveryError, match="jwks_uri"):
            await client.discover("https://accounts.example.com")
