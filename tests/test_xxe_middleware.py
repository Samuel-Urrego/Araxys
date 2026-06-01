"""Integration tests for XXEMiddleware.

Strict TDD: tests written BEFORE middleware implementation.
Uses TestClient (httpx) to verify middleware behavior on XML requests.
Each test creates its own app/client to avoid conftest fixture conflicts.
"""

from __future__ import annotations

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request  # noqa: TC002

# ── Payloads ─────────────────────────────────────────────────────────────────

CLEAN_XML = """<?xml version="1.0"?>
<root>
  <item>safe content</item>
</root>"""

MALICIOUS_XML = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""


# ═════════════════════════════════════════════════════════════════════════════
# T2.3 — Middleware Integration Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestContentTypeRouting:
    """Middleware intercepts XML content types for scanning."""

    async def _make_client(self) -> tuple[FastAPI, AsyncClient]:
        """Helper to create isolated app+client per test."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=XXEConfig())

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        transport = ASGITransport(app=app)
        client = AsyncClient(transport=transport, base_url="http://test")
        return app, client

    async def test_application_xml_is_scanned(self) -> None:
        """application/xml with clean XML passes through."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "application/xml"},
            )
            assert resp.status_code == 200

    async def test_text_xml_is_scanned(self) -> None:
        """text/xml with clean XML passes through."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "text/xml"},
            )
            assert resp.status_code == 200

    async def test_soap_xml_is_scanned(self) -> None:
        """application/soap+xml with clean XML passes through."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "application/soap+xml"},
            )
            assert resp.status_code == 200

    async def test_svg_xml_is_scanned(self) -> None:
        """image/svg+xml with clean XML passes through."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "image/svg+xml"},
            )
            assert resp.status_code == 200

    async def test_plus_xml_suffix_is_scanned(self) -> None:
        """Custom +xml content-type is scanned."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "application/vnd.custom+xml"},
            )
            assert resp.status_code == 200

    async def test_content_type_with_charset_is_scanned(self) -> None:
        """Content-Type with charset parameter is correctly parsed."""
        app, c = await self._make_client()
        async with c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "application/xml; charset=utf-8"},
            )
            assert resp.status_code == 200


class TestXXEDetection:
    """Middleware returns 400 when XXE is detected."""

    async def _make_mw_client(self) -> tuple[FastAPI, AsyncClient]:
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=XXEConfig())

        transport = ASGITransport(app=app)
        client = AsyncClient(transport=transport, base_url="http://test")
        return app, client

    async def test_malicious_xml_returns_400(self) -> None:
        """application/xml with malicious entity returns 400."""
        app, c = await self._make_mw_client()

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        async with c:
            resp = await c.post(
                "/xml",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
            assert resp.status_code == 400
            data = resp.json()
            assert "error" in data
            assert data["error"] == "XXEDetected"
            assert "detail" in data
            assert "detection_type" in data

    async def test_downstream_not_called_on_detection(self) -> None:
        """Downstream handler is NOT called when XXE detected."""
        app, c = await self._make_mw_client()

        call_count = 0

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            nonlocal call_count
            call_count += 1
            return {"status": "ok"}

        async with c:
            await c.post(
                "/xml",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
            assert call_count == 0


class TestCleanXMLPassthrough:
    """Middleware passes clean XML through."""

    async def test_clean_xml_reaches_handler(self) -> None:
        """Clean XML body reaches the downstream handler."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=XXEConfig())

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/xml",
                content=CLEAN_XML,
                headers={"content-type": "application/xml"},
            )
        assert resp.status_code == 200
        assert resp.json()["received"] == CLEAN_XML


class TestNonXMLPassthrough:
    """Middleware passes non-XML content through."""

    async def _make_client(self) -> tuple[FastAPI, AsyncClient]:
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=XXEConfig())
        transport = ASGITransport(app=app)
        client = AsyncClient(transport=transport, base_url="http://test")
        return app, client

    async def test_json_body_passes(self) -> None:
        """application/json body passes through without scanning."""
        app, c = await self._make_client()

        @app.post("/data")
        async def endpoint(request: Request) -> dict[str, object]:
            body = await request.json()
            return {"received": body}

        async with c:
            resp = await c.post("/data", json={"key": "value"})
            assert resp.status_code == 200
            assert resp.json() == {"received": {"key": "value"}}

    async def test_text_plain_passes(self) -> None:
        """text/plain body passes through without scanning."""
        app, c = await self._make_client()

        @app.post("/data")
        async def endpoint(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        async with c:
            resp = await c.post(
                "/data",
                content="plain text body",
                headers={"content-type": "text/plain"},
            )
            assert resp.status_code == 200

    async def test_form_urlencoded_passes(self) -> None:
        """application/x-www-form-urlencoded passes through."""
        app, c = await self._make_client()

        @app.post("/form")
        async def endpoint(request: Request) -> dict[str, str]:
            return {"status": "ok"}

        async with c:
            resp = await c.post("/form", data={"field": "value"})
            assert resp.status_code == 200


class TestExcludedPaths:
    """Middleware respects exclude_paths config."""

    async def test_excluded_path_bypasses_scan(self) -> None:
        """Path in exclude_paths bypasses scanning even with malicious XML."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        config = XXEConfig(exclude_paths=["/webhook"])
        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=config)

        @app.post("/webhook")
        async def webhook(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/webhook",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
        assert resp.status_code == 200
        assert "SYSTEM" in resp.json()["received"]

    async def test_non_excluded_path_still_scanned(self) -> None:
        """Path NOT in exclude_paths is still scanned."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        config = XXEConfig(exclude_paths=["/webhook"])
        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=config)

        @app.post("/api/data")
        async def endpoint(request: Request) -> dict[str, str]:
            return {"status": "ok"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/api/data",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
        assert resp.status_code == 400


class TestExcludedContentTypes:
    """Middleware respects exclude_content_types config."""

    async def test_excluded_content_type_bypasses_scan(self) -> None:
        """Content type in exclude_content_types bypasses scanning."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        config = XXEConfig(exclude_content_types=["image/svg+xml"])
        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=config)

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            body = await request.body()
            return {"received": body.decode()}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/xml",
                content=MALICIOUS_XML,
                headers={"content-type": "image/svg+xml"},
            )
        assert resp.status_code == 200


class TestAuditEventEmission:
    """Middleware emits audit events on XXE detection."""

    async def test_audit_event_emitted_on_detection(self) -> None:
        """SecurityEvent is emitted when XXE detected."""
        from unittest.mock import AsyncMock

        from araxys.xxe import middleware as xxe_middleware
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        # Wire a mock event bus
        mock_bus = AsyncMock()
        mock_bus.emit = AsyncMock()
        xxe_middleware._event_bus = mock_bus

        config = XXEConfig()
        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=config)

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            return {"status": "ok"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/xml",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
        assert resp.status_code == 400

        # Verify event was emitted
        mock_bus.emit.assert_awaited_once()
        call_args = mock_bus.emit.call_args
        event = call_args[0][0]
        assert event.event_type.value == "xxe_detected"
        assert event.severity == "warning"
        assert "SYSTEM" in event.message or "XXE" in event.message

        # Cleanup module-level state
        xxe_middleware._event_bus = None

    async def test_no_event_bus_no_crash(self) -> None:
        """Middleware doesn't crash when _event_bus is None."""
        from araxys.xxe import middleware as xxe_middleware
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.middleware import XXEMiddleware

        # Ensure _event_bus is None
        xxe_middleware._event_bus = None

        app = FastAPI()
        app.add_middleware(XXEMiddleware, config=XXEConfig())

        @app.post("/xml")
        async def endpoint(request: Request) -> dict[str, str]:
            return {"status": "ok"}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/xml",
                content=MALICIOUS_XML,
                headers={"content-type": "application/xml"},
            )
        assert resp.status_code == 400
