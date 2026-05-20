"""Database Security Module (v0.5).

Provides connection pooling, secret resolution, TLS configuration,
query auditing, and a DatabaseSecurityManager to orchestrate them.
"""

from __future__ import annotations

from araxys.db_security.audit import QueryAuditor, QueryEvent
from araxys.db_security.dependencies import get_db_pool, get_query_auditor
from araxys.db_security.manager import DatabaseSecurityManager
from araxys.db_security.pool import ConnectionPool, InMemoryPool, RedisPool
from araxys.db_security.query_validator import QueryValidationResult, QueryValidator
from araxys.db_security.secrets import (
    AWSSecretsResolver,
    ChainedResolver,
    ConnectionStringResolver,
    EnvVarResolver,
    VaultResolver,
)
from araxys.db_security.tls import build_ssl_context

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
    # TLS
    "build_ssl_context",
    # Audit
    "QueryEvent",
    "QueryAuditor",
    # Manager
    "DatabaseSecurityManager",
    # Dependencies
    "get_db_pool",
    "get_query_auditor",
    # Query validation (v0.7)
    "QueryValidationResult",
    "QueryValidator",
]
