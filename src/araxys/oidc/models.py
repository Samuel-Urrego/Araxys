"""Pydantic models for OIDC Discovery (RFC 8414)."""

from __future__ import annotations

from pydantic import BaseModel


class OIDCProviderMetadata(BaseModel):
    """Validated OIDC provider metadata from a discovery document.

    Required fields per RFC 8414 §2:
    - issuer
    - authorization_endpoint
    - token_endpoint
    - jwks_uri

    Optional fields include userinfo_endpoint, scopes_supported,
    and response_types_supported.
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] | None = None
