"""Tests for the IP Access Control module.

Tests follow strict TDD: written before implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.types import SecurityEventType

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from araxys.core.config import IPControlConfig
    from araxys.ip_access.backends import IPAccessBackend


# ── Backend Tests ────────────────────────────────────────────────────────


class TestInMemoryIPAccessBackend:
    """Tests for InMemoryIPAccessBackend."""

    @pytest.fixture
    def backend(self) -> IPAccessBackend:
        from araxys.ip_access.backends import InMemoryIPAccessBackend

        return InMemoryIPAccessBackend(
            allowlist={"192.168.1.0/24", "10.0.0.1"},
            blocklist={"10.0.0.0/8"},
        )

    async def test_is_allowed_exact_match(self, backend: IPAccessBackend) -> None:
        """Exact IP in allowlist should be allowed."""
        result = await backend.is_allowed("10.0.0.1")
        assert result is True

    async def test_is_allowed_cidr_match(self, backend: IPAccessBackend) -> None:
        """IP matching a CIDR in allowlist should be allowed."""
        result = await backend.is_allowed("192.168.1.50")
        assert result is True

    async def test_is_allowed_not_in_allowlist(self, backend: IPAccessBackend) -> None:
        """IP not in allowlist should return False."""
        result = await backend.is_allowed("1.2.3.4")
        assert result is False

    async def test_is_blocked_exact_match(self, backend: IPAccessBackend) -> None:
        """Exact IP in blocklist should be blocked."""
        result = await backend.is_blocked("10.0.0.1")
        assert result is True

    async def test_is_blocked_cidr_match(self, backend: IPAccessBackend) -> None:
        """IP matching a CIDR in blocklist should be blocked."""
        result = await backend.is_blocked("10.1.2.3")
        assert result is True

    async def test_is_blocked_not_in_blocklist(self, backend: IPAccessBackend) -> None:
        """IP not in blocklist should return False."""
        result = await backend.is_blocked("192.168.1.50")
        assert result is False

    async def test_add_to_allowlist(self) -> None:
        from araxys.ip_access.backends import InMemoryIPAccessBackend

        b = InMemoryIPAccessBackend()
        await b.add_to_allowlist("10.0.0.5")
        result = await b.is_allowed("10.0.0.5")
        assert result is True

    async def test_remove_from_allowlist(self, backend: IPAccessBackend) -> None:
        await backend.remove_from_allowlist("10.0.0.1")
        result = await backend.is_allowed("10.0.0.1")
        assert result is False

    async def test_add_to_blocklist(self) -> None:
        from araxys.ip_access.backends import InMemoryIPAccessBackend

        b = InMemoryIPAccessBackend()
        await b.add_to_blocklist("10.0.0.5")
        result = await b.is_blocked("10.0.0.5")
        assert result is True

    async def test_remove_from_blocklist(self, backend: IPAccessBackend) -> None:
        # Remove the CIDR itself, then IP should no longer match
        await backend.remove_from_blocklist("10.0.0.0/8")
        result = await backend.is_blocked("10.0.0.1")
        assert result is False

    async def test_ipv6_cidr_match(self) -> None:
        from araxys.ip_access.backends import InMemoryIPAccessBackend

        b = InMemoryIPAccessBackend(allowlist={"2001:db8::/32"})
        result = await b.is_allowed("2001:db8:dead:beef::1")
        assert result is True
        result2 = await b.is_allowed("2001:db9::1")
        assert result2 is False


class TestRedisIPAccessBackend:
    """Tests for RedisIPAccessBackend using fakeredis."""

    @pytest.fixture
    async def backend(self) -> AsyncGenerator[IPAccessBackend]:
        import fakeredis.aioredis

        from araxys.ip_access.backends import RedisIPAccessBackend

        redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        b = RedisIPAccessBackend(redis)
        # Seed some rules
        await redis.sadd("araxys:ip_access:allowlist", "192.168.1.0/24", "10.0.0.1")  # type: ignore[misc]
        await redis.sadd("araxys:ip_access:blocklist", "10.0.0.0/8")  # type: ignore[misc]
        yield b
        await redis.flushall()
        await redis.aclose()

    async def test_is_allowed_exact_match(
        self, backend: IPAccessBackend
    ) -> None:
        result = await backend.is_allowed("10.0.0.1")
        assert result is True

    async def test_is_allowed_cidr_match(
        self, backend: IPAccessBackend
    ) -> None:
        result = await backend.is_allowed("192.168.1.50")
        assert result is True

    async def test_is_blocked_cidr_match(
        self, backend: IPAccessBackend
    ) -> None:
        result = await backend.is_blocked("10.1.2.3")
        assert result is True

    async def test_add_to_allowlist(self, backend: IPAccessBackend) -> None:
        await backend.add_to_allowlist("172.16.0.1")
        result = await backend.is_allowed("172.16.0.1")
        assert result is True

    async def test_remove_from_blocklist(self, backend: IPAccessBackend) -> None:
        # Remove the CIDR itself, then IP should no longer match
        await backend.remove_from_blocklist("10.0.0.0/8")
        result = await backend.is_blocked("10.0.0.1")
        assert result is False


# ── CIDR Helper Tests ────────────────────────────────────────────────────


class TestIPMatchingCIDR:
    """Tests for the _ip_matches_cidr helper."""

    def test_ipv4_exact_match(self) -> None:
        from araxys.ip_access.backends import _ip_matches_cidr

        assert _ip_matches_cidr("192.168.1.1", "192.168.1.1/32") is True

    def test_ipv4_in_cidr(self) -> None:
        from araxys.ip_access.backends import _ip_matches_cidr

        assert _ip_matches_cidr("192.168.1.100", "192.168.1.0/24") is True

    def test_ipv4_outside_cidr(self) -> None:
        from araxys.ip_access.backends import _ip_matches_cidr

        assert _ip_matches_cidr("192.168.2.1", "192.168.1.0/24") is False

    def test_ipv6_in_cidr(self) -> None:
        from araxys.ip_access.backends import _ip_matches_cidr

        assert _ip_matches_cidr("2001:db8:dead::1", "2001:db8::/32") is True

    def test_ipv6_outside_cidr(self) -> None:
        from araxys.ip_access.backends import _ip_matches_cidr

        assert _ip_matches_cidr("2001:db9::1", "2001:db8::/32") is False


# ── Middleware Tests ─────────────────────────────────────────────────────


def _make_config(**kwargs: object) -> IPControlConfig:
    """Create an IPControlConfig with the given overrides."""
    from araxys.core.config import IPControlConfig

    return IPControlConfig(**kwargs)  # type: ignore[arg-type]


def _make_app(
    config: IPControlConfig | None = None,
    backend: IPAccessBackend | None = None,
) -> FastAPI:
    """Create a FastAPI app with IPAccessMiddleware."""
    from araxys.ip_access.backends import InMemoryIPAccessBackend
    from araxys.ip_access.middleware import IPAccessMiddleware

    app = FastAPI()

    @app.get("/hello")
    async def hello() -> dict[str, str]:
        return {"message": "Hello, World!"}

    cfg = config or _make_config()
    bk = backend or InMemoryIPAccessBackend(
        allowlist=set(cfg.allowlist),
        blocklist=set(cfg.blocklist),
    )
    app.add_middleware(IPAccessMiddleware, config=cfg, backend=bk)

    return app


# ── Event Bus Recording Fixture ──────────────────────────────────────────


@pytest.fixture
def recorded_events() -> list[Any]:
    """Capture security events for assertion."""
    captured: list[Any] = []
    return captured


@pytest.fixture
def event_bus(recorded_events: list[Any]) -> Generator[None]:
    """Attach a recording subscriber to the global SecurityEventBus."""
    from araxys.webhooks.emitter import SecurityEventBus

    bus = SecurityEventBus(queue_size=100)

    async def record(event):  # type: ignore[no-untyped-def]
        recorded_events.append(event)

    bus.subscribe(record)
    bus.start()

    # Monkey-patch the module-level event bus so IPAccessMiddleware uses it
    import araxys.ip_access.middleware as mw_mod

    mw_mod._event_bus = bus  # noqa: SLF001

    yield

    import asyncio

    asyncio.run(bus.stop())
    mw_mod._event_bus = None  # noqa: SLF001


class TestIPAccessMiddlewareAllowMode:
    """Tests for IPAccessMiddleware in 'allow' (default-deny) mode."""

    async def test_ip_in_allowlist_passes(self) -> None:
        """IP in allowlist should pass through."""
        app = _make_app(config=_make_config(mode="allow", allowlist=["192.168.1.0/24"]))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "192.168.1.50"},
            )
            assert response.status_code == 200
            assert response.json() == {"message": "Hello, World!"}

    async def test_ip_not_in_allowlist_returns_403(self) -> None:
        """IP not in allowlist should return 403."""
        app = _make_app(config=_make_config(mode="allow", allowlist=["192.168.1.0/24"]))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.0.0.1"},
            )
            assert response.status_code == 403
            body = response.json()
            assert body["detail"] == "IP not allowed"
            assert body["ip"] == "10.0.0.1"


class TestIPAccessMiddlewareBlockMode:
    """Tests for IPAccessMiddleware in 'block' (default-allow) mode."""

    async def test_ip_not_in_blocklist_passes(self) -> None:
        """IP not in blocklist should pass through."""
        app = _make_app(
            config=_make_config(mode="block", blocklist=["10.0.0.0/8"])
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "192.168.1.50"},
            )
            assert response.status_code == 200

    async def test_ip_in_blocklist_returns_403(self) -> None:
        """IP in blocklist should return 403."""
        app = _make_app(
            config=_make_config(mode="block", blocklist=["10.0.0.0/8"])
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.1.2.3"},
            )
            assert response.status_code == 403
            body = response.json()
            assert body["detail"] == "IP blocked"
            assert body["ip"] == "10.1.2.3"


class TestIPAccessMiddlewareHybridMode:
    """Tests for IPAccessMiddleware in 'hybrid' mode."""

    async def test_ip_in_both_lists_block_wins(self) -> None:
        """IP in both blocklist and allowlist → blocklist wins (403)."""
        app = _make_app(
            config=_make_config(
                mode="hybrid",
                allowlist=["192.168.1.0/24"],
                blocklist=["192.168.1.100"],
            )
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "192.168.1.100"},
            )
            assert response.status_code == 403

    async def test_ip_in_neither_list_returns_403(self) -> None:
        """IP in neither allowlist nor blocklist → 403."""
        app = _make_app(
            config=_make_config(
                mode="hybrid",
                allowlist=["192.168.1.0/24"],
                blocklist=["10.0.0.0/8"],
            )
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "1.2.3.4"},
            )
            assert response.status_code == 403

    async def test_ip_only_in_allowlist_passes(self) -> None:
        """IP only in allowlist passes in hybrid mode."""
        app = _make_app(
            config=_make_config(
                mode="hybrid",
                allowlist=["192.168.1.0/24"],
                blocklist=["10.0.0.0/8"],
            )
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "192.168.1.50"},
            )
            assert response.status_code == 200


class TestIPAccessMiddlewareXForwardedFor:
    """Tests for X-Forwarded-For header fallback."""

    async def test_x_forwarded_for_fallback(self) -> None:
        """Should extract first IP from X-Forwarded-For when client.host is None."""
        app = _make_app(config=_make_config(mode="allow", allowlist=["10.0.0.0/8"]))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.0.0.5, 192.168.1.1"},
            )
            assert response.status_code == 200

    async def test_x_forwarded_for_for_blocked(self) -> None:
        """Blocked IP via X-Forwarded-For."""
        app = _make_app(config=_make_config(mode="block", blocklist=["10.0.0.0/8"]))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.0.0.5, 192.168.1.1"},
            )
            assert response.status_code == 403

    async def test_x_forwarded_for_first_ip_used(self) -> None:
        """First IP in chain should be used, not last."""
        app = _make_app(config=_make_config(mode="block", blocklist=["10.0.0.0/8"]))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # first IP is blocked, even though second is not
            response = await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.0.0.99, 192.168.1.1"},
            )
            assert response.status_code == 403


class TestIPAccessSecurityEvents:
    """Tests for IP_BLOCKED and IP_ALLOWED security events."""

    async def test_blocked_event_emitted(self, recorded_events: list[Any]) -> None:
        """When IP is blocked, IP_BLOCKED event should be emitted."""
        app = _make_app(config=_make_config(mode="block", blocklist=["10.0.0.0/8"]))
        # Inject a simple bus that records events
        from araxys.webhooks.emitter import SecurityEventBus

        bus = SecurityEventBus(queue_size=100)
        recorded: list[Any] = []
        async def record(event):  # type: ignore[no-untyped-def]
            recorded.append(event)
        bus.subscribe(record)
        bus.start()
        import araxys.ip_access.middleware as mw_mod
        mw_mod._event_bus = bus  # noqa: SLF001

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get(
                "/hello",
                headers={"X-Forwarded-For": "10.1.2.3"},
            )

        # Give the async event bus time to deliver
        import asyncio
        await asyncio.sleep(0.1)

        assert len(recorded) >= 1
        assert recorded[0].event_type == SecurityEventType.IP_BLOCKED

        await bus.stop()
        mw_mod._event_bus = None  # noqa: SLF001
