"""End-to-end integration tests for the XXE protection module.

Covers full FastAPI app with AraxysShield and XXEConfig:
- Middleware interception of XXE payloads
- Clean XML pass-through
- Non-XML content types pass through
- Disabled-mode pass-through
- Excluded paths bypass
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request  # noqa: TC002

from araxys import AraxysConfig, AraxysShield
from araxys.xxe.config import XXEConfig

# ── Test Payloads ─────────────────────────────────────────────────────────────

CLEAN_XML = b"""<?xml version="1.0"?>
<root>
  <item>safe</item>
</root>"""

XXE_FILE_DISCLOSURE = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b"<root>&xxe;</root>"
)

XXE_DTD_ONLY = b'<?xml version="1.0"?><!DOCTYPE foo><root>test</root>'

XXE_BILLION_LAUGHS = (
    b'<?xml version="1.0"?>'
    b'<!DOCTYPE lolz ['
    b'  <!ENTITY lol "lol">'
    b'  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    b'  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    b'  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
    b']>'
    b"<root>&lol4;</root>"
)

JSON_PAYLOAD = b'{"key": "value"}'


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def app_enabled() -> FastAPI:
    """FastAPI app with AraxysShield + XXE protection enabled."""
    app = FastAPI()

    AraxysShield(
        app,
        AraxysConfig(
            secret_key="test-secret-key-32-chars-minimum!!!!!",
            xxe=XXEConfig(),
        ),
    )

    @app.post("/xml-endpoint")
    async def xml_endpoint(request: Request) -> dict[str, str]:
        body = await request.body()
        return {"status": "ok", "body_length": str(len(body))}

    return app


@pytest.fixture
def app_disabled() -> FastAPI:
    """FastAPI app with AraxysShield + XXE DISABLED (xxe=None)."""
    app = FastAPI()

    AraxysShield(
        app,
        AraxysConfig(
            secret_key="test-secret-key-32-chars-minimum!!!!!",
        ),
    )

    @app.post("/xml-endpoint")
    async def xml_endpoint() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.fixture
def app_excluded_path() -> FastAPI:
    """FastAPI app with XXE exclude_paths covering /bypass."""
    app = FastAPI()

    AraxysShield(
        app,
        AraxysConfig(
            secret_key="test-secret-key-32-chars-minimum!!!!!",
            xxe=XXEConfig(
                exclude_paths=[
                    "/bypass",
                    "/docs",
                    "/redoc",
                    "/openapi.json",
                    "/healthz",
                ],
            ),
        ),
    )

    @app.post("/bypass")
    async def bypass_endpoint() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/xml-endpoint")
    async def xml_endpoint() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.fixture
async def client_enabled(app_enabled: FastAPI) -> AsyncClient:  # type: ignore[misc]
    transport = ASGITransport(app=app_enabled)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def client_disabled(app_disabled: FastAPI) -> AsyncClient:  # type: ignore[misc]
    transport = ASGITransport(app=app_disabled)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def client_excluded_path(app_excluded_path: FastAPI) -> AsyncClient:  # type: ignore[misc]
    transport = ASGITransport(app=app_excluded_path)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Test: Enabled Shield ─────────────────────────────────────────────────────


class TestEnabledShield:
    """XXE-enabled shield blocks malicious XML."""

    async def test_clean_xml_passes(
        self, client_enabled: AsyncClient
    ) -> None:
        """Clean XML POST → 200."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=CLEAN_XML,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    async def test_xxe_file_disclosure_returns_400(
        self, client_enabled: AsyncClient
    ) -> None:
        """XXE with SYSTEM entity → 400."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=XXE_FILE_DISCLOSURE,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "XXEDetected"
        assert "detail" in data
        assert "detection_type" in data

    async def test_dtd_only_returns_400(
        self, client_enabled: AsyncClient
    ) -> None:
        """XML with DOCTYPE (no entities) → 400 (forbid_dtd=True)."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=XXE_DTD_ONLY,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "XXEDetected"

    async def test_billion_laughs_returns_400(
        self, client_enabled: AsyncClient
    ) -> None:
        """Billion laughs → 400."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=XXE_BILLION_LAUGHS,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"] == "XXEDetected"

    async def test_non_xml_passes(
        self, client_enabled: AsyncClient
    ) -> None:
        """JSON POST → 200 (not XML)."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=JSON_PAYLOAD,
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    async def test_empty_body_passes(
        self, client_enabled: AsyncClient
    ) -> None:
        """Empty body with XML content-type → 200."""
        resp = await client_enabled.post(
            "/xml-endpoint",
            content=b"",
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


# ── Test: Disabled Shield ────────────────────────────────────────────────────


class TestDisabledShield:
    """XXE-disabled shield passes all XML."""

    async def test_xxe_payload_passes_when_disabled(
        self, client_disabled: AsyncClient
    ) -> None:
        """XXE payload passes when xxe=None."""
        resp = await client_disabled.post(
            "/xml-endpoint",
            content=XXE_FILE_DISCLOSURE,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 200

    async def test_clean_xml_passes_when_disabled(
        self, client_disabled: AsyncClient
    ) -> None:
        """Clean XML passes when xxe=None."""
        resp = await client_disabled.post(
            "/xml-endpoint",
            content=CLEAN_XML,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 200


# ── Test: Excluded Paths ─────────────────────────────────────────────────────


class TestExcludedPaths:
    """Excluded paths bypass XXE middleware."""

    async def test_excluded_path_skips_scanning(
        self, client_excluded_path: AsyncClient
    ) -> None:
        """XXE payload on excluded path → 200."""
        resp = await client_excluded_path.post(
            "/bypass",
            content=XXE_FILE_DISCLOSURE,
            headers={"content-type": "application/xml"},
        )
        assert resp.status_code == 200
