"""Tests for the rate limiting module."""

from __future__ import annotations

import pytest
from starlette.requests import Request

from araxys.core.config import RateLimitConfig
from araxys.core.exceptions import RateLimitExceeded
from araxys.rate_limit.backends import InMemoryBackend
from araxys.rate_limit.identity import extract_api_key, extract_user_id
from araxys.rate_limit.limiter import RateLimiter
from araxys.rate_limit.path_matcher import find_best_match, match_path

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_request(headers: dict[str, str]) -> Request:
    """Build a minimal Starlette Request with the given headers."""
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope: dict[str, object] = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": raw,
        "http_version": "1.1",
        "scheme": "http",
        "client": ("127.0.0.1", 50000),
        "server": ("test", 80),
        "query_string": b"",
        "extensions": {},
    }
    return Request(scope)


def _make_jwt_token(payload: dict[str, object]) -> str:
    """Create an unsigned JWT for testing identity extraction."""
    import jwt

    return jwt.encode(payload, key="", algorithm="none")  # no security — tests only


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def backend() -> InMemoryBackend:
    return InMemoryBackend()


@pytest.fixture
def default_config() -> RateLimitConfig:
    return RateLimitConfig(
        max_requests=3,
        window_seconds=60,
        ban_threshold=2,
        ban_duration_seconds=10,
        escalation_multiplier=2.0,
    )


@pytest.fixture
def limiter(
    backend: InMemoryBackend, default_config: RateLimitConfig
) -> RateLimiter:
    return RateLimiter(backend=backend, config=default_config)


@pytest.fixture
def user_limiter(
    backend: InMemoryBackend, default_config: RateLimitConfig
) -> RateLimiter:
    return RateLimiter(
        backend=backend,
        config=default_config.model_copy(update={"per_user": True}),
    )


@pytest.fixture
def api_key_limiter(
    backend: InMemoryBackend, default_config: RateLimitConfig
) -> RateLimiter:
    return RateLimiter(
        backend=backend,
        config=default_config.model_copy(update={"per_api_key": True}),
    )


# ── Existing Backend Tests ───────────────────────────────────────────────────

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


# ── Existing RateLimiter Tests ───────────────────────────────────────────────

class TestRateLimiter:
    async def test_allows_requests_within_limit(
        self, limiter: RateLimiter
    ) -> None:
        for _ in range(3):
            headers = await limiter.check("1.2.3.4", "/api/data")
            assert headers["X-RateLimit-Remaining"] >= 0

    async def test_blocks_requests_over_limit(
        self, limiter: RateLimiter
    ) -> None:
        for _ in range(3):
            await limiter.check("1.2.3.4", "/api/data")

        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.check("1.2.3.4", "/api/data")
        assert exc_info.value.retry_after > 0

    async def test_different_ips_independent(
        self, limiter: RateLimiter
    ) -> None:
        for _ in range(3):
            await limiter.check("1.1.1.1", "/api/data")

        headers = await limiter.check("2.2.2.2", "/api/data")
        assert headers["X-RateLimit-Remaining"] == 2

    async def test_excluded_paths(self, limiter: RateLimiter) -> None:
        assert await limiter.is_path_excluded("/docs")
        assert not await limiter.is_path_excluded("/api/data")


# ── 3.1 Identity Extraction Tests ─────────────────────────────────────────────

class TestIdentityExtraction:
    def test_extract_user_id_returns_stable_hash(self) -> None:
        """extract_user_id returns a 16-char hex hash of the raw Bearer token."""
        token = _make_jwt_token({"sub": "user-123", "role": "admin"})
        request = _make_request({"authorization": f"Bearer {token}"})
        result = extract_user_id(request)
        assert isinstance(result, str)
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_extract_user_id_same_token_same_hash(self) -> None:
        """The same raw token always maps to the same identifier."""
        token = _make_jwt_token({"sub": "user-123"})
        r1 = _make_request({"authorization": f"Bearer {token}"})
        r2 = _make_request({"authorization": f"Bearer {token}"})
        assert extract_user_id(r1) == extract_user_id(r2)

    def test_extract_user_id_different_tokens_different_hash(self) -> None:
        """Different raw tokens produce different identifiers."""
        t1 = _make_jwt_token({"sub": "user-a"})
        t2 = _make_jwt_token({"sub": "user-b"})
        id1 = extract_user_id(_make_request({"authorization": f"Bearer {t1}"}))
        id2 = extract_user_id(_make_request({"authorization": f"Bearer {t2}"}))
        assert id1 != id2

    def test_extract_user_id_attacker_cannot_spoof(self) -> None:
        """An attacker forging a JWT with sub='victim' gets a *different*
        identifier than the victim's real token because the raw token
        strings differ."""
        import jwt as _jwt
        # Victim's real token (signed with HS256)
        victim_token = _jwt.encode(
            {"sub": "victim"}, key="real-secret-at-least-32-chars!!!", algorithm="HS256"
        )
        # Attacker's unsigned token (forges the same sub)
        attacker_token = _jwt.encode(
            {"sub": "victim"}, key="", algorithm="none"
        )
        vid = extract_user_id(_make_request({"authorization": f"Bearer {victim_token}"}))
        aid = extract_user_id(_make_request({"authorization": f"Bearer {attacker_token}"}))
        assert vid is not None and aid is not None
        assert vid != aid  # different raw tokens → different IDs

    def test_extract_user_id_no_auth_header(self) -> None:
        request = _make_request({"content-type": "application/json"})
        assert extract_user_id(request) is None

    def test_extract_user_id_not_bearer(self) -> None:
        request = _make_request({"authorization": "Basic dGVzdDpwYXNz"})
        assert extract_user_id(request) is None

    def test_extract_api_key_from_header(self) -> None:
        request = _make_request({"x-api-key": "ak-test-abc123"})
        assert extract_api_key(request) == "ak-test-abc123"

    def test_extract_api_key_no_header(self) -> None:
        request = _make_request({"content-type": "application/json"})
        assert extract_api_key(request) is None


# ── 3.2 Path Matcher Tests ────────────────────────────────────────────────────

class TestPathMatcher:
    def test_exact_match(self) -> None:
        assert match_path("/api/data", "/api/data") is True

    def test_wildcard_match(self) -> None:
        assert match_path("/api/auth/login", "/api/auth/*") is True

    def test_wildcard_no_match(self) -> None:
        assert match_path("/api/data", "/api/auth/*") is False

    def test_trailing_wildcard(self) -> None:
        assert match_path("/api/public/static/file.js", "/api/public/*") is True

    @pytest.mark.parametrize(
        ("path", "pattern", "expected"),
        [
            ("/api/data", "/api/*", True),
            ("/api/auth/login", "/api/auth/*", True),
            ("/api/auth/login", "/api/*", True),
            ("/healthz", "/api/*", False),
            ("/api/v2/users", "/api/v1/*", False),
        ],
    )
    def test_various_patterns(
        self, path: str, pattern: str, expected: bool
    ) -> None:
        assert match_path(path, pattern) == expected

    def test_find_best_match_exact_over_wildcard(self) -> None:
        patterns = {
            "/api/auth/*": RateLimitConfig(max_requests=5),
            "/api/auth/login": RateLimitConfig(max_requests=2),
        }
        pattern, config = find_best_match("/api/auth/login", patterns)
        assert pattern == "/api/auth/login"
        assert config is not None
        assert config.max_requests == 2

    def test_find_best_match_most_specific_wildcard(self) -> None:
        patterns = {
            "/api/*": RateLimitConfig(max_requests=100),
            "/api/auth/*": RateLimitConfig(max_requests=5),
        }
        pattern, config = find_best_match("/api/auth/login", patterns)
        assert pattern == "/api/auth/*"
        assert config is not None
        assert config.max_requests == 5

    def test_find_best_match_no_match(self) -> None:
        patterns = {"/api/auth/*": RateLimitConfig(max_requests=5)}
        pattern, config = find_best_match("/healthz", patterns)
        assert pattern is None
        assert config is None

    def test_find_best_match_empty_patterns(self) -> None:
        pattern, config = find_best_match("/api/data", {})
        assert pattern is None
        assert config is None


# ── 3.3 Per-User Rate Limiting Tests ─────────────────────────────────────────

class TestPerUserRateLimiting:
    @pytest.fixture
    def high_limit_user_config(self) -> RateLimitConfig:
        return RateLimitConfig(
            max_requests=10,
            window_seconds=60,
            ban_threshold=5,
            ban_duration_seconds=10,
            escalation_multiplier=2.0,
            per_user=True,
        )

    @pytest.fixture
    def high_limit_user_limiter(
        self, backend: InMemoryBackend, high_limit_user_config: RateLimitConfig
    ) -> RateLimiter:
        return RateLimiter(backend=backend, config=high_limit_user_config)

    async def test_user_tracks_across_different_ips(
        self, high_limit_user_limiter: RateLimiter
    ) -> None:
        """Same user from different IPs shares the user-level counter."""
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="alice"
        )
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="alice"
        )

        # Alice from IP 2: IP counter is fresh (1), Alice counter is 3
        headers = await high_limit_user_limiter.check(
            "5.6.7.8", "/api/data", user_id="alice"
        )
        # IP remaining = 10 - 1 = 9, Alice remaining = 10 - 3 = 7
        # Effective remaining = min(9, 7) = 7
        assert headers["X-RateLimit-Remaining"] == 7

    async def test_different_users_from_same_ip(
        self, high_limit_user_limiter: RateLimiter
    ) -> None:
        """Different users behind the same IP have independent user counters."""
        # Alice makes 2 requests
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="alice"
        )
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="alice"
        )

        # Bob makes 3 requests
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="bob"
        )
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="bob"
        )
        await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="bob"
        )

        # IP counter = 5, Alice = 2, Bob = 3
        headers = await high_limit_user_limiter.check(
            "1.2.3.4", "/api/data", user_id="charlie"
        )
        # IP remaining = 10 - 6 = 4, Charlie remaining = 10 - 1 = 9
        assert headers["X-RateLimit-Remaining"] == 4

    async def test_user_exceeds_limit_gets_blocked(
        self, user_limiter: RateLimiter
    ) -> None:
        for _ in range(3):
            await user_limiter.check(
                "1.2.3.4", "/api/data", user_id="alice"
            )

        with pytest.raises(RateLimitExceeded):
            await user_limiter.check(
                "1.2.3.4", "/api/data", user_id="alice"
            )

    async def test_user_fallback_to_ip_when_no_user_id(
        self, user_limiter: RateLimiter
    ) -> None:
        """When per_user is True but no user_id, fall back to IP-based tracking."""
        for _ in range(3):
            await user_limiter.check("1.2.3.4", "/api/data")

        with pytest.raises(RateLimitExceeded):
            await user_limiter.check("1.2.3.4", "/api/data")

    async def test_user_limit_disabled_when_per_user_false(
        self, limiter: RateLimiter
    ) -> None:
        """When per_user is False, user_id parameter is ignored."""
        for _ in range(3):
            await limiter.check("1.2.3.4", "/api/data", user_id="alice")

        with pytest.raises(RateLimitExceeded):
            await limiter.check("1.2.3.4", "/api/data", user_id="alice")

    async def test_user_tracking_different_endpoints_independent(
        self, user_limiter: RateLimiter
    ) -> None:
        """User counters should be per-endpoint (both IP and user counters)."""
        await user_limiter.check("1.2.3.4", "/api/data", user_id="alice")
        await user_limiter.check("1.2.3.4", "/api/data", user_id="alice")

        # Different endpoint: both IP and user counters are fresh (1 each)
        headers = await user_limiter.check(
            "1.2.3.4", "/api/other", user_id="alice"
        )
        assert headers["X-RateLimit-Remaining"] == 2


# ── 3.4 Per-API-Key Rate Limiting Tests ───────────────────────────────────────

class TestPerApiKeyRateLimiting:
    @pytest.fixture
    def high_limit_key_config(self) -> RateLimitConfig:
        return RateLimitConfig(
            max_requests=10,
            window_seconds=60,
            ban_threshold=5,
            ban_duration_seconds=10,
            escalation_multiplier=2.0,
            per_api_key=True,
        )

    @pytest.fixture
    def high_limit_key_limiter(
        self, backend: InMemoryBackend, high_limit_key_config: RateLimitConfig
    ) -> RateLimiter:
        return RateLimiter(backend=backend, config=high_limit_key_config)

    async def test_api_key_tracks_independently(
        self, high_limit_key_limiter: RateLimiter
    ) -> None:
        """Same IP, different API keys should have independent key counters."""
        await high_limit_key_limiter.check(
            "1.2.3.4", "/api/data", api_key="key-a"
        )
        await high_limit_key_limiter.check(
            "1.2.3.4", "/api/data", api_key="key-a"
        )

        # key-b is new: IP counter = 3, key-b counter = 1
        headers = await high_limit_key_limiter.check(
            "1.2.3.4", "/api/data", api_key="key-b"
        )
        # IP remaining = 10 - 3 = 7, key-b remaining = 10 - 1 = 9
        assert headers["X-RateLimit-Remaining"] == 7

    async def test_api_key_exceeds_limit_gets_blocked(
        self, api_key_limiter: RateLimiter
    ) -> None:
        for _ in range(3):
            await api_key_limiter.check(
                "1.2.3.4", "/api/data", api_key="key-a"
            )

        with pytest.raises(RateLimitExceeded):
            await api_key_limiter.check(
                "1.2.3.4", "/api/data", api_key="key-a"
            )

    async def test_api_key_fallback_when_no_key(
        self, api_key_limiter: RateLimiter
    ) -> None:
        """When per_api_key is True but no key, fall back to IP-based tracking."""
        for _ in range(3):
            await api_key_limiter.check("1.2.3.4", "/api/data")

        with pytest.raises(RateLimitExceeded):
            await api_key_limiter.check("1.2.3.4", "/api/data")

    async def test_api_key_disabled_when_per_api_key_false(
        self, limiter: RateLimiter
    ) -> None:
        """When per_api_key is False, api_key parameter is ignored."""
        for _ in range(3):
            await limiter.check("1.2.3.4", "/api/data", api_key="key-a")

        with pytest.raises(RateLimitExceeded):
            await limiter.check("1.2.3.4", "/api/data", api_key="key-a")


# ── 3.5 Path-Based Rate Limiting Tests ───────────────────────────────────────

class TestPathBasedRateLimiting:
    @pytest.fixture
    def path_config(self) -> RateLimitConfig:
        return RateLimitConfig(
            max_requests=3,
            window_seconds=60,
            ban_threshold=2,
            ban_duration_seconds=10,
            escalation_multiplier=2.0,
            path_limits={
                "/api/auth/*": RateLimitConfig(max_requests=1),
                "/api/public/*": RateLimitConfig(max_requests=10),
            },
        )

    @pytest.fixture
    def path_limiter(
        self, backend: InMemoryBackend, path_config: RateLimitConfig
    ) -> RateLimiter:
        return RateLimiter(backend=backend, config=path_config)

    async def test_path_specific_limit_applied(
        self, path_limiter: RateLimiter
    ) -> None:
        """Auth endpoints should use the path-specific limit (1 req)."""
        await path_limiter.check("1.2.3.4", "/api/auth/login")

        with pytest.raises(RateLimitExceeded):
            await path_limiter.check("1.2.3.4", "/api/auth/login")

    async def test_path_specific_less_restrictive(
        self, path_limiter: RateLimiter
    ) -> None:
        """Public endpoints should use the higher limit (10 req)."""
        for _ in range(5):
            headers = await path_limiter.check(
                "1.2.3.4", "/api/public/resource"
            )
        assert headers["X-RateLimit-Remaining"] == 5

    async def test_global_limit_applied_when_no_path_match(
        self, path_limiter: RateLimiter
    ) -> None:
        """Endpoints without path pattern should use global config (3 req)."""
        for _ in range(3):
            await path_limiter.check("1.2.3.4", "/api/other")

        with pytest.raises(RateLimitExceeded):
            await path_limiter.check("1.2.3.4", "/api/other")

    async def test_most_specific_path_wins(
        self, backend: InMemoryBackend
    ) -> None:
        """Most specific matching pattern should be used."""
        config = RateLimitConfig(
            max_requests=10,
            window_seconds=60,
            path_limits={
                "/api/*": RateLimitConfig(max_requests=5),
                "/api/auth/*": RateLimitConfig(max_requests=2),
            },
        )
        limiter = RateLimiter(backend=backend, config=config)

        # /api/auth/login should match /api/auth/* (not /api/*)
        await limiter.check("1.2.3.4", "/api/auth/login")
        await limiter.check("1.2.3.4", "/api/auth/login")

        with pytest.raises(RateLimitExceeded):
            await limiter.check("1.2.3.4", "/api/auth/login")

    async def test_global_limit_when_path_limit_disabled(
        self, backend: InMemoryBackend
    ) -> None:
        """Path-specific config can enable per_user even when global doesn't."""
        config = RateLimitConfig(
            max_requests=10,
            window_seconds=60,
            per_user=False,
            path_limits={
                "/api/auth/*": RateLimitConfig(max_requests=3, per_user=True),
            },
        )
        limiter = RateLimiter(backend=backend, config=config)

        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )
        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )
        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )

        with pytest.raises(RateLimitExceeded):
            await limiter.check(
                "1.2.3.4", "/api/auth/login", user_id="alice"
            )


# ── 3.6 Combined / Mixed Tracking Tests ──────────────────────────────────────

class TestCombinedRateLimiting:
    async def test_per_user_and_per_api_key_both_active(
        self, backend: InMemoryBackend
    ) -> None:
        """Both per-user and per-API-key can be active simultaneously."""
        config = RateLimitConfig(
            max_requests=3,
            window_seconds=60,
            per_user=True,
            per_api_key=True,
        )
        limiter = RateLimiter(backend=backend, config=config)

        # First 3 requests: within both limits
        for _ in range(3):
            await limiter.check(
                "1.2.3.4", "/api/data",
                user_id="alice", api_key="key-a",
            )

        with pytest.raises(RateLimitExceeded):
            await limiter.check(
                "1.2.3.4", "/api/data",
                user_id="alice", api_key="key-a",
            )

    async def test_remaining_is_min_of_all_active_limits(
        self, backend: InMemoryBackend
    ) -> None:
        """X-RateLimit-Remaining should reflect the most restrictive limit."""
        config = RateLimitConfig(
            max_requests=5,
            window_seconds=60,
            per_user=True,
        )
        limiter = RateLimiter(backend=backend, config=config)

        # Alice makes 3 requests from IP 1
        for _ in range(3):
            await limiter.check(
                "1.2.3.4", "/api/data", user_id="alice"
            )

        # Alice from IP 2: IP counter fresh (1), Alice counter at 4
        headers = await limiter.check(
            "2.2.2.2", "/api/data", user_id="alice"
        )
        # IP remaining = 5 - 1 = 4, Alice remaining = 5 - 4 = 1
        assert headers["X-RateLimit-Remaining"] == 1

    async def test_path_limit_per_user_with_both(
        self, backend: InMemoryBackend
    ) -> None:
        """Path-specific config can enable per_user even when global doesn't."""
        config = RateLimitConfig(
            max_requests=10,
            window_seconds=60,
            per_user=False,
            path_limits={
                "/api/auth/*": RateLimitConfig(max_requests=3, per_user=True),
            },
        )
        limiter = RateLimiter(backend=backend, config=config)

        # IP-based: 10 limit, user-based: 3 limit (from path config)
        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )
        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )
        await limiter.check(
            "1.2.3.4", "/api/auth/login", user_id="alice"
        )

        with pytest.raises(RateLimitExceeded):
            await limiter.check(
                "1.2.3.4", "/api/auth/login", user_id="alice"
            )
