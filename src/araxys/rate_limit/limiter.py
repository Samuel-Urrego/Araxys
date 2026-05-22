"""Dynamic rate limiter with sliding window and automatic escalation.

The limiter tracks requests per IP+endpoint and applies escalating
bans when violations accumulate.

Supports optional per-user, per-API-key, and per-endpoint (path-based)
rate limiting — all configurable via :class:`~araxys.core.config.RateLimitConfig`.
"""


from __future__ import annotations

import fnmatch
import time
from typing import TYPE_CHECKING

import structlog

from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.path_matcher import find_best_match

if TYPE_CHECKING:
    from araxys.core.config import RateLimitConfig
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

    # ── Key builders ──────────────────────────────────────────────────────

    def _make_ip_key(self, ip: str, endpoint: str) -> str:
        """Build a key for the IP+endpoint combination."""
        return f"{ip}:{endpoint}"

    def _make_user_key(self, user_id: str, endpoint: str) -> str:
        """Build a key for the user+endpoint combination."""
        return f"user:{user_id}:{endpoint}"

    def _make_api_key_key(self, api_key: str, endpoint: str) -> str:
        """Build a key for the API-key+endpoint combination."""
        return f"apikey:{api_key}:{endpoint}"

    # ── Path config resolution ────────────────────────────────────────────

    def _resolve_config(self, endpoint: str) -> RateLimitConfig:
        """Return the effective config for *endpoint* (path override or global)."""
        _pattern, override = find_best_match(endpoint, self._config.path_limits)
        return override or self._config

    # ── Core check ────────────────────────────────────────────────────────

    async def check(
        self,
        ip: str,
        endpoint: str,
        user_id: str | None = None,
        api_key: str | None = None,
    ) -> dict[str, int]:
        """Check if the request is allowed.

        Parameters
        ----------
        ip:
            Client IP address.
        endpoint:
            URL path being requested.
        user_id:
            Authenticated user identifier (from JWT ``sub`` claim etc.).
            Only checked when the effective config has ``per_user=True``.
        api_key:
            API key identifier.  Only checked when the effective config
            has ``per_api_key=True``.

        Returns a dict with rate limit headers to include in the response.

        Raises
        ------
        RateLimitExceeded
            If the IP has exceeded its rate limit or is temporarily banned.
        """
        cfg = self._resolve_config(endpoint)

        # Check if IP is banned first
        if await self._backend.is_banned(ip):
            retry_after = await self._backend.get_ban_expiry(ip)
            logger.warning("rate_limit.banned_request", ip=ip, retry_after=retry_after)
            raise RateLimitExceeded(ip_address=ip, retry_after=retry_after)

        # Always increment IP-based counter (for ban tracking)
        ip_key = self._make_ip_key(ip, endpoint)
        ip_count = await self._backend.increment(ip_key, cfg.window_seconds)

        # User-based counter (if enabled and user_id provided)
        user_count = 0
        if cfg.per_user and user_id:
            user_key = self._make_user_key(user_id, endpoint)
            user_count = await self._backend.increment(user_key, cfg.window_seconds)

        # API-key-based counter (if enabled and api_key provided)
        key_count = 0
        if cfg.per_api_key and api_key:
            key_key = self._make_api_key_key(api_key, endpoint)
            key_count = await self._backend.increment(key_key, cfg.window_seconds)

        # Resolve effective counts — use sliding window if configured
        if cfg.algorithm == "sliding" and hasattr(self._backend, "get_sliding_count"):
            ip_eff = await self._backend.get_sliding_count(ip_key)
            user_eff = (
                await self._backend.get_sliding_count(user_key)
                if cfg.per_user and user_id
                else 0.0
            )
            key_eff = (
                await self._backend.get_sliding_count(key_key)
                if cfg.per_api_key and api_key
                else 0.0
            )
        else:
            ip_eff = float(ip_count)
            user_eff = float(user_count)
            key_eff = float(key_count)

        limit = cfg.max_requests
        ip_remaining = max(0, limit - int(ip_eff))

        user_remaining = limit
        if cfg.per_user and user_id:
            user_remaining = max(0, limit - int(user_eff))

        api_key_remaining = limit
        if cfg.per_api_key and api_key:
            api_key_remaining = max(0, limit - int(key_eff))

        # Effective remaining = the lowest across all active dimensions
        remaining = min(ip_remaining, user_remaining, api_key_remaining)

        ip_ok = ip_eff <= limit
        user_ok = not (cfg.per_user and user_id) or user_eff <= limit
        key_ok = not (cfg.per_api_key and api_key) or key_eff <= limit

        if not (ip_ok and user_ok and key_ok):
            violations = await self._backend.increment_violations(ip)

            # Clean up stale violation entries on the in-memory backend
            if hasattr(self._backend, "_cleanup_violations"):
                max_ban = getattr(
                    cfg, "max_ban_duration_seconds", 3600
                )
                ttl = max(cfg.ban_duration_seconds, max_ban)
                self._backend._cleanup_violations(ttl)

            # Escalating ban: base * multiplier^(violations - 1), capped
            ban_duration = int(
                cfg.ban_duration_seconds
                * (cfg.escalation_multiplier ** (violations - 1))
            )
            if hasattr(cfg, "max_ban_duration_seconds"):
                ban_duration = min(ban_duration, cfg.max_ban_duration_seconds)

            if violations >= cfg.ban_threshold:
                await self._backend.ban(ip, ban_duration)
                logger.warning(
                    "rate_limit.ip_banned",
                    ip=ip,
                    violations=violations,
                    ban_duration=ban_duration,
                )

            # Log the dimensions that exceeded
            dims = []
            if not ip_ok:
                dims.append(f"ip={int(ip_eff)}")
            if not user_ok:
                dims.append(f"user={int(user_eff)}")
            if not key_ok:
                dims.append(f"key={int(key_eff)}")

            logger.info(
                "rate_limit.exceeded",
                ip=ip,
                endpoint=endpoint,
                count=int(ip_eff),
                limit=limit,
                violations=violations,
                dimensions=", ".join(dims),
            )
            raise RateLimitExceeded(ip_address=ip, retry_after=ban_duration)

        return {
            "X-RateLimit-Limit": limit,
            "X-RateLimit-Remaining": remaining,
            "X-RateLimit-Reset": int(time.time()) + cfg.window_seconds,
            "X-RateLimit-Window": cfg.window_seconds,
        }

    async def is_path_excluded(self, path: str) -> bool:
        """Check if a path is excluded from rate limiting.

        Uses fnmatch glob matching, consistent with path_limits resolution.
        """
        return any(
            fnmatch.fnmatch(path, pattern)
            for pattern in self._config.exclude_paths
        )
