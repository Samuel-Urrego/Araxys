"""OIDC Discovery client (RFC 8414) — fetch and cache provider metadata."""

from __future__ import annotations

import time

import httpx

from araxys.core.config import OIDCDiscoveryConfig
from araxys.core.exceptions import OIDCDiscoveryError
from araxys.oidc.models import OIDCProviderMetadata


class OIDCDiscoveryClient:
    """OIDC Discovery client with in-memory TTL cache.

    Fetches ``{issuer}/.well-known/openid-configuration``, validates
    against :class:`OIDCProviderMetadata`, and caches results in memory
    for the configured TTL.

    Parameters
    ----------
    config:
        Optional configuration. Defaults via :class:`OIDCDiscoveryConfig`
        when ``None``.
    """

    def __init__(self, config: OIDCDiscoveryConfig | None = None) -> None:
        self._config = config or OIDCDiscoveryConfig()
        # cache: normalized_issuer → (metadata, wall_clock_timestamp)
        self._cache: dict[str, tuple[OIDCProviderMetadata, float]] = {}

    async def discover(self, issuer_url: str) -> OIDCProviderMetadata:
        """Discover OIDC provider metadata for *issuer_url*.

        Strips trailing slash, checks the in-memory TTL cache, fetches
        ``.well-known/openid-configuration`` over HTTPS, parses the JSON
        response into :class:`OIDCProviderMetadata`, and caches the result.

        Raises :exc:`OIDCDiscoveryError` on network, timeout, or parse
        failures.
        """
        # Normalize: strip trailing slash
        normalized = issuer_url.rstrip("/")

        # Check in-memory cache (wall-clock TTL)
        entry = self._cache.get(normalized)
        if entry is not None:
            metadata, timestamp = entry
            if time.time() - timestamp < self._config.cache_ttl_seconds:
                return metadata

        # Fetch from well-known endpoint
        well_known_url = f"{normalized}/.well-known/openid-configuration"

        try:
            async with httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                verify=self._config.verify_ssl,
            ) as client:
                resp = await client.get(well_known_url)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as exc:
            raise OIDCDiscoveryError(
                issuer_url=issuer_url,
                detail="Timeout fetching discovery document",
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OIDCDiscoveryError(
                issuer_url=issuer_url,
                detail=f"HTTP {exc.response.status_code}",
            ) from exc
        except (httpx.RequestError, ValueError) as exc:
            raise OIDCDiscoveryError(
                issuer_url=issuer_url,
                detail=str(exc),
            ) from exc

        # Parse and validate
        try:
            metadata = OIDCProviderMetadata(**data)
        except Exception as exc:
            raise OIDCDiscoveryError(
                issuer_url=issuer_url,
                detail=f"Invalid metadata: {exc}",
            ) from exc

        # Cache with current timestamp
        self._cache[normalized] = (metadata, time.time())
        return metadata
