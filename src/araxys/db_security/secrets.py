"""Connection string resolvers for database security.

Provides a ``ConnectionStringResolver`` Protocol with implementations
that read from environment variables, HashiCorp Vault, and AWS Secrets
Manager. A ``ChainedResolver`` composes multiple resolvers with
first-non-None-wins semantics.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("araxys.secrets")


@runtime_checkable
class ConnectionStringResolver(Protocol):
    """Resolve a connection string by name.

    Implementations look up the named secret (e.g. ``REDIS_URL``) from
    a backend and return the value or ``None`` if not found.
    """

    async def resolve(self, name: str) -> str | None:
        """Return the connection string for *name*, or ``None``."""
        ...


class EnvVarResolver:
    """Read connection strings from environment variables.

    The effective variable name is ``{prefix}{name}``.
    Default prefix is ``ARAXYS_DB__``, yielding keys like
    ``ARAXYS_DB__REDIS_URL``.
    """

    def __init__(self, prefix: str = "ARAXYS_DB__") -> None:
        self._prefix = prefix

    async def resolve(self, name: str) -> str | None:
        return os.environ.get(f"{self._prefix}{name}")


class VaultResolver:
    """Read connection strings from HashiCorp Vault KV v2 secrets engine.

    Requires the ``hvac`` package (install via ``araxys[vault]``).

    The secret is read from ``{mount_path}/data/{name}``.  All
    exceptions are caught silently and return ``None`` (fail-soft).
    """

    def __init__(
        self,
        url: str,
        token: str,
        mount_path: str = "araxys",
        fail_closed: bool = False,
    ) -> None:
        import hvac

        self._mount_path = mount_path
        self._client = hvac.Client(url=url, token=token)
        self._fail_closed = fail_closed

    async def resolve(self, name: str) -> str | None:
        try:
            secret = await asyncio.to_thread(
                self._client.secrets.kv.v2.read_secret_version,
                path=name,
                mount_point=self._mount_path,
            )
            data: dict[str, Any] = secret.get("data", {}).get("data", {})
            return data.get(name)
        except Exception:
            if self._fail_closed:
                raise
            logger.warning(
                "VaultResolver failed to resolve '%s' (mount=%s)",
                name,
                self._mount_path,
                exc_info=True,
            )
            return None


# ---------------------------------------------------------------------------
# AWSSecretsResolver
# ---------------------------------------------------------------------------


class AWSSecretsResolver:
    """Read connection strings from AWS Secrets Manager.

    Requires the ``boto3`` package (install via ``araxys[aws_secrets]``).

    The secret is looked up under ``{secret_prefix}{name}`` (default
    ``araxys/{name}``).  All exceptions are caught silently and return
    ``None`` (fail-soft).
    """

    def __init__(
        self,
        secret_prefix: str = "araxys/",
        region_name: str | None = None,
        fail_closed: bool = False,
    ) -> None:
        import boto3

        self._secret_prefix = secret_prefix
        self._client = boto3.client("secretsmanager", region_name=region_name)
        self._fail_closed = fail_closed

    async def resolve(self, name: str) -> str | None:
        try:
            response = await asyncio.to_thread(
                self._client.get_secret_value,
                SecretId=f"{self._secret_prefix}{name}",
            )
            return response.get("SecretString")  # type: ignore[no-any-return]
        except Exception:
            if self._fail_closed:
                raise
            logger.warning(
                "AWSSecretsResolver failed to resolve '%s' (prefix=%s, region=%s)",
                name,
                self._secret_prefix,
                self._client.meta.region_name,
                exc_info=True,
            )
            return None


class ChainedResolver:
    """Composite resolver that tries resolvers in order.

    Returns the first non-``None`` result.  If all resolvers return
    ``None``, returns ``None``.
    """

    def __init__(
        self, resolvers: list[ConnectionStringResolver], fail_closed: bool = False
    ) -> None:
        self._resolvers = resolvers
        self._fail_closed = fail_closed

    async def resolve(self, name: str) -> str | None:
        for i, resolver in enumerate(self._resolvers):
            try:
                value = await resolver.resolve(name)
                if value is not None:
                    return value
            except Exception:
                if self._fail_closed:
                    raise
            logger.debug(
                "ChainedResolver: resolver %d (%s) returned None for '%s'",
                i,
                type(resolver).__name__,
                name,
            )
        return None
