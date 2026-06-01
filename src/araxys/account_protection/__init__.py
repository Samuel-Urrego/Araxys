"""Account Enumeration Prevention.

Provides config-driven protection against account enumeration attacks by
normalizing auth error messages and response timing across all auth paths.
"""

from araxys.account_protection.config import AccountProtectionConfig
from araxys.account_protection.detection import EnumerationDetector
from araxys.account_protection.helpers import (
    apply_rate_limit_presets,
    constant_time_compare,
    normalize_error_message,
    simulate_hash_lookup,
    simulate_verification_work,
)
from araxys.account_protection.middleware import AccountProtectionMiddleware

__all__ = [
    "AccountProtectionConfig",
    "AccountProtectionMiddleware",
    "EnumerationDetector",
    "apply_rate_limit_presets",
    "constant_time_compare",
    "normalize_error_message",
    "simulate_hash_lookup",
    "simulate_verification_work",
]
