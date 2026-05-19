"""Database Security Module (v0.5).

Provides connection pooling, secret resolution, TLS configuration,
query auditing, and a DatabaseSecurityManager to orchestrate them.
"""

from __future__ import annotations

from araxys.db_security.pool import ConnectionPool, InMemoryPool, RedisPool
from araxys.db_security.secrets import (
    AWSSecretsResolver,
    ChainedResolver,
    ConnectionStringResolver,
    EnvVarResolver,
    VaultResolver,
)

__all__: list[str] = [
    # Pool
    "ConnectionPool",
    "InMemoryPool",
    "RedisPool",
    # Secrets
    "ConnectionStringResolver",
    "EnvVarResolver",
    "VaultResolver",
    "AWSSecretsResolver",
    "ChainedResolver",
]
