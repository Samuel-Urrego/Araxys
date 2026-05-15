"""Brute Force Protection and Password Policy.

Provides attempt tracking with lockout, pluggable backends, and a
configurable password validation policy with optional HIBP integration.
"""

from araxys.brute_force.config import BruteForceConfig
from araxys.brute_force.limiter import (
    BruteForceBackend,
    BruteForceMiddleware,
    InMemoryBruteForceBackend,
    RedisBruteForceBackend,
)
from araxys.brute_force.password_policy import (
    PasswordPolicy,
    PasswordPolicyConfig,
    check_hibp,
    password_policy_dependency,
)

__all__ = [
    "BruteForceBackend",
    "BruteForceConfig",
    "BruteForceMiddleware",
    "InMemoryBruteForceBackend",
    "PasswordPolicy",
    "PasswordPolicyConfig",
    "RedisBruteForceBackend",
    "check_hibp",
    "password_policy_dependency",
]
