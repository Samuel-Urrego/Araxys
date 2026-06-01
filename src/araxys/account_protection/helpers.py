"""Helper functions for account enumeration prevention.

Provides constant-time comparison, timing equalization via CPU-bound work,
and error message normalization — all designed to prevent attackers from
inferring whether a user/identifier exists through timing or message differences.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import AccountProtectionConfig


def simulate_hash_lookup(
    prefix: str,
    config: AccountProtectionConfig,
) -> None:
    """Simulate hash computation and comparison for a missing key prefix.

    When an API key prefix is not found in storage, this function
    equalizes timing by computing a fake SHA-256 hash from the prefix
    and comparing it against itself using constant-time comparison.
    This ensures that missing and existing prefixes take approximately
    the same time to process.

    Args:
        prefix: The API key prefix (8 characters) used as fake input.
        config: Account protection config controlling work factor.

    Returns:
        ``None`` — purely a timing side-effect function.
    """
    if not config.enabled:
        return

    # Compute a fake hash using SHA-256 (same algorithm as APIKeyManager._hash_key)
    fake_input = f"fake_{prefix}"
    fake_hash = hashlib.sha256(fake_input.encode()).hexdigest()

    # Constant-time compare the fake hash with itself (true match, same byte count)
    hmac.compare_digest(fake_hash, fake_hash)

    # Optionally run CPU-bound work to match bcrypt/scrypt verification cost
    if config.fake_hash_work_factor > 0:
        simulate_verification_work(config.fake_hash_work_factor)


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """Compare two strings or bytes in constant time.

    Wraps :func:`hmac.compare_digest` with type coercion so that
    ``str`` vs ``bytes`` comparisons with identical ASCII content
    still match.

    Args:
        a: First value to compare.
        b: Second value to compare.

    Returns:
        ``True`` if the values are equal, ``False`` otherwise.

    Raises:
        TypeError: If either argument is ``None``.
    """
    if isinstance(a, bytes) and isinstance(b, str):
        b = b.encode()
    elif isinstance(a, str) and isinstance(b, bytes):
        a = a.encode()
    return hmac.compare_digest(a, b)


def simulate_verification_work(work_factor: int = 12) -> None:
    """Perform a CPU-bound computation to equalize auth response timing.

    Uses :func:`hashlib.scrypt` with ``N=2**work_factor`` iterations,
    approximating the cost of bcrypt verification. Periodically yields
    the event loop via ``asyncio.sleep(0)`` to avoid blocking.

    Args:
        work_factor: Exponent for scrypt N parameter (``N = 2**work_factor``).
            Set to ``0`` to skip work entirely.
    """
    if work_factor <= 0:
        return

    n = 2**work_factor
    salt = os.urandom(16)
    key = os.urandom(32)
    # Process in chunks, yielding event loop every 64 iterations
    chunk_size = 64
    iterations = max(1, n // 2**14)  # Scale iterations to approximate bcrypt cost

    for i in range(iterations):
        hashlib.scrypt(
            password=key,
            salt=salt,
            n=n,
            r=8,
            p=1,
            dklen=32,
        )
        if i > 0 and i % chunk_size == 0:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.call_soon(lambda: None)
            except RuntimeError:
                pass


def apply_rate_limit_presets() -> dict[str, dict[str, int]]:
    """Return recommended rate limit presets for common auth paths.

    These presets help prevent brute-force and enumeration attacks by
    limiting the number of requests to auth-sensitive endpoints.

    Returns
    -------
    dict[str, dict[str, int]]
        A mapping of path pattern to rate limit configuration with
        ``max_requests`` and ``window_seconds`` keys.

    Example::

        presets = apply_rate_limit_presets()
        # Use presets to configure Araxys RateLimitConfig.paths
    """
    return {
        "/auth/*": {
            "max_requests": 20,
            "window_seconds": 300,  # 5 minutes
        },
        "/login": {
            "max_requests": 10,
            "window_seconds": 300,  # 5 minutes
        },
        "/register": {
            "max_requests": 5,
            "window_seconds": 3600,  # 1 hour
        },
        "/api/login": {
            "max_requests": 10,
            "window_seconds": 300,  # 5 minutes
        },
    }


def normalize_error_message(category: str, config: AccountProtectionConfig) -> str:
    """Map an error category to the appropriate generic error message.

    Args:
        category: The error category (e.g. ``"login"``, ``"api_key"``,
            ``"mfa"``, ``"recovery"``).
        config: The :class:`AccountProtectionConfig` instance containing
            the generic message templates.

    Returns:
        The appropriate generic error message for the given category.
    """
    if category in ("login", "api_key", ""):
        return config.generic_unauthorized_message
    if category in ("mfa", "recovery", "verification"):
        return config.generic_verification_message
    # Default to unauthorized message for unknown categories
    return config.generic_unauthorized_message
