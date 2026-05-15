"""Tests for the rate limiting module."""

import pytest

from araxys.core.config import RateLimitConfig
from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.backends import InMemoryBackend
from araxys.rate_limit.limiter import RateLimiter


@pytest.fixture
def backend() -> InMemoryBackend:
    return InMemoryBackend()


@pytest.fixture
def config() -> RateLimitConfig:
    return RateLimitConfig(
        max_requests=3,
        window_seconds=60,
        ban_threshold=2,
        ban_duration_seconds=10,
        escalation_multiplier=2.0,
    )


@pytest.fixture
def limiter(backend: InMemoryBackend, config: RateLimitConfig) -> RateLimiter:
    return RateLimiter(backend=backend, config=config)


class TestInMemoryBackend:
    async def test_increment_and_get(self, backend: InMemoryBackend) -> None:
        count = await backend.increment("key1", 60)
        assert count == 1
        count = await backend.increment("key1", 60)
        assert count == 2
        assert await backend.get_count("key1") == 2

    async def test_ban_and_check(self, backend: InMemoryBackend) -> None:
        assert not await backend.is_banned("1.2.3.4")
        await backend.ban("1.2.3.4", 10)
        assert await backend.is_banned("1.2.3.4")

    async def test_ban_expiry(self, backend: InMemoryBackend) -> None:
        assert await backend.get_ban_expiry("1.2.3.4") == 0
        await backend.ban("1.2.3.4", 100)
        expiry = await backend.get_ban_expiry("1.2.3.4")
        assert expiry > 0

    async def test_violation_tracking(self, backend: InMemoryBackend) -> None:
        assert await backend.get_violation_count("1.2.3.4") == 0
        v1 = await backend.increment_violations("1.2.3.4")
        assert v1 == 1
        v2 = await backend.increment_violations("1.2.3.4")
        assert v2 == 2


class TestRateLimiter:
    async def test_allows_requests_within_limit(self, limiter: RateLimiter) -> None:
        for _ in range(3):
            headers = await limiter.check("1.2.3.4", "/api/data")
            assert headers["X-RateLimit-Remaining"] >= 0

    async def test_blocks_requests_over_limit(self, limiter: RateLimiter) -> None:
        for _ in range(3):
            await limiter.check("1.2.3.4", "/api/data")

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check("1.2.3.4", "/api/data")
        assert exc_info.value.retry_after > 0

    async def test_different_ips_independent(self, limiter: RateLimiter) -> None:
        for _ in range(3):
            await limiter.check("1.1.1.1", "/api/data")

        # Different IP should still be allowed
        headers = await limiter.check("2.2.2.2", "/api/data")
        assert headers["X-RateLimit-Remaining"] == 2

    async def test_excluded_paths(self, limiter: RateLimiter) -> None:
        assert await limiter.is_path_excluded("/docs")
        assert not await limiter.is_path_excluded("/api/data")
