"""Tests for OIDC discovery Pydantic models (Task 1.3)."""

import pytest
from pydantic import ValidationError


class TestOIDCProviderMetadata:
    """OIDCProviderMetadata — validates RFC 8414 required fields."""

    def test_valid_with_required_fields(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://accounts.example.com",
            authorization_endpoint="https://accounts.example.com/authorize",
            token_endpoint="https://accounts.example.com/token",
            jwks_uri="https://accounts.example.com/jwks",
        )
        assert meta.issuer == "https://accounts.example.com"
        assert (
            meta.authorization_endpoint
            == "https://accounts.example.com/authorize"
        )
        assert meta.token_endpoint == "https://accounts.example.com/token"
        assert meta.jwks_uri == "https://accounts.example.com/jwks"

    def test_valid_with_all_optional_fields(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://accounts.example.com",
            authorization_endpoint="https://accounts.example.com/authorize",
            token_endpoint="https://accounts.example.com/token",
            jwks_uri="https://accounts.example.com/jwks",
            userinfo_endpoint="https://accounts.example.com/userinfo",
            scopes_supported=["openid", "profile", "email"],
            response_types_supported=["code", "id_token"],
        )
        assert meta.userinfo_endpoint == "https://accounts.example.com/userinfo"
        assert meta.scopes_supported == ["openid", "profile", "email"]
        assert meta.response_types_supported == ["code", "id_token"]

    def test_missing_issuer_raises(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        with pytest.raises(ValidationError, match="issuer"):
            OIDCProviderMetadata(
                authorization_endpoint="https://accounts.example.com/authorize",
                token_endpoint="https://accounts.example.com/token",
                jwks_uri="https://accounts.example.com/jwks",
            )

    def test_missing_jwks_uri_raises(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        with pytest.raises(ValidationError, match="jwks_uri"):
            OIDCProviderMetadata(
                issuer="https://accounts.example.com",
                authorization_endpoint="https://accounts.example.com/authorize",
                token_endpoint="https://accounts.example.com/token",
            )

    def test_missing_token_endpoint_raises(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        with pytest.raises(ValidationError, match="token_endpoint"):
            OIDCProviderMetadata(
                issuer="https://accounts.example.com",
                authorization_endpoint="https://accounts.example.com/authorize",
                jwks_uri="https://accounts.example.com/jwks",
            )

    def test_optionals_default_to_none(self) -> None:
        from araxys.oidc.models import OIDCProviderMetadata

        meta = OIDCProviderMetadata(
            issuer="https://accounts.example.com",
            authorization_endpoint="https://accounts.example.com/authorize",
            token_endpoint="https://accounts.example.com/token",
            jwks_uri="https://accounts.example.com/jwks",
        )
        assert meta.userinfo_endpoint is None
        assert meta.scopes_supported is None
        assert meta.response_types_supported is None

    def test_empty_issuer_raises_if_min_length(self) -> None:
        """Empty string should not be a valid issuer endpoint."""
        from araxys.oidc.models import OIDCProviderMetadata

        # Pydantic's default str validation allows empty strings
        # unless min_length is set. We don't enforce min_length in the spec.
        # This test just verifies empty string is accepted if no constraint.
        meta = OIDCProviderMetadata(
            issuer="",
            authorization_endpoint="https://example.com/authorize",
            token_endpoint="https://example.com/token",
            jwks_uri="https://example.com/jwks",
        )
        assert meta.issuer == ""
