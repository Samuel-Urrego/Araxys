"""OIDC Discovery module (RFC 8414)."""

from __future__ import annotations

from araxys.oidc.client import OIDCDiscoveryClient
from araxys.oidc.models import OIDCProviderMetadata

__all__ = [
    "OIDCDiscoveryClient",
    "OIDCProviderMetadata",
]
