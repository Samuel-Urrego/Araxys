from __future__ import annotations

"""Dynamic rate limiter with sliding window and automatic escalation.

The limiter tracks requests per IP+endpoint and applies escalating
bans when violations accumulate.
"""


import structlog

from araxys.core.config import RateLimitConfig
from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.backends import RateLimitBackend

logger = structlog.get_logger("araxys.rate_limit")


class RateLimiter:
    """Dynamic rate limiter with escalating ban durations.

    Parameters
    ----------
    backend:
        Storage backend (in-memory or Redis).
    config:
        Rate limiting configuration.
    """

    def __init__(self, backend: RateLimitBackend, config: RateLimitConfig) -> None:
        self._backend = backend
        self._config = config

    def _make_key(self, ip: str, endpoint: str) -> str:
        """Build a unique key for the IP+endpoint combination."""
        return f"{ip}:{endpoint}"

    async def check(self, ip: str, endpoint: str) -> dict[str, int]:
        """Check if the request is allowed.

        Returns a dict with rate limit headers to include in the response.

        Raises
        ------
        RateLimitExceeded
            If the IP has exceeded its rate limit or is temporarily banned.
        """
        # Check if IP is banned first
        if await self._backend.is_banned(ip):
            retry_after = await self._backend.get_ban_expiry(ip)
            logger.warning("rate_limit.banned_request", ip=ip, retry_after=retry_after)
            raise RateLimitExceeded(ip_address=ip, retry_after=retry_after)

        key = self._make_key(ip, endpoint)
        count = await self._backend.increment(key, self._config.window_seconds)

        remaining = max(0, self._config.max_requests - count)

        if count > self._config.max_requests:
            violations = await self._backend.increment_violations(ip)

            # Escalating ban: base * multiplier^(violations - 1)
            ban_duration = int(
                self._config.ban_duration_seconds
                * (self._config.escalation_multiplier ** (violations - 1))
            )

            if violations >= self._config.ban_threshold:
                await self._backend.ban(ip, ban_duration)
                logger.warning(
                    "rate_limit.ip_banned",
                    ip=ip,
                    violations=violations,
                    ban_duration=ban_duration,
                )

            logger.info(
                "rate_limit.exceeded",
                ip=ip,
                endpoint=endpoint,
                count=count,
                limit=self._config.max_requests,
                violations=violations,
            )
            raise RateLimitExceeded(ip_address=ip, retry_after=ban_duration)

        return {
            "X-RateLimit-Limit": self._config.max_requests,
            "X-RateLimit-Remaining": remaining,
            "X-RateLimit-Window": self._config.window_seconds,
        }

    async def is_path_excluded(self, path: str) -> bool:
        """Check if a path is excluded from rate limiting."""
        return path in self._config.exclude_paths
