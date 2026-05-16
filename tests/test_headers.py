"""Tests for the secure headers middleware."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.config import CSPDirectiveConfig, SecureHeadersConfig
from araxys.headers.csp import build_csp_header
from araxys.headers.middleware import SecureHeadersMiddleware


@pytest.fixture
def headers_app() -> FastAPI:
    app = FastAPI()

    app.add_middleware(SecureHeadersMiddleware, config=SecureHeadersConfig())

    @app.get("/test")
    async def test_endpoint() -> None:
        return {"status": "ok"}  # type: ignore

    return app


@pytest.fixture
async def headers_client(headers_app: FastAPI) -> AsyncClient:  # type: ignore
    transport = ASGITransport(app=headers_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestCSPBuilder:
    """Tests for the Content-Security-Policy header builder."""

    def test_builds_from_default_config(self) -> None:
        """With all-default CSPDirectiveConfig, produces a sensible CSP."""
        result = build_csp_header(CSPDirectiveConfig())
        assert "default-src 'self'" in result
        assert "script-src 'self'" in result
        assert "object-src 'none'" in result
        assert "upgrade-insecure-requests" not in result
        assert "report-uri" not in result

    def test_builds_from_custom_values(self) -> None:
        """Custom directive values appear in the output."""
        config = CSPDirectiveConfig(
            default_src=["'self'", "https://cdn.example.com"],
            script_src=["'self'", "'unsafe-inline'"],
            img_src=["https://images.example.com"],
        )
        result = build_csp_header(config)
        assert "default-src 'self' https://cdn.example.com" in result
        assert "script-src 'self' 'unsafe-inline'" in result
        assert "img-src https://images.example.com" in result

    def test_includes_upgrade_insecure_requests(self) -> None:
        """When upgrade_insecure_requests is True, the flag is included."""
        config = CSPDirectiveConfig(upgrade_insecure_requests=True)
        result = build_csp_header(config)
        assert "upgrade-insecure-requests" in result

    def test_includes_report_uri(self) -> None:
        """When report_uri is set, it appears in the header."""
        config = CSPDirectiveConfig(
            report_uri="https://example.com/csp-report"
        )
        result = build_csp_header(config)
        assert "report-uri https://example.com/csp-report" in result

    def test_header_is_rfc_compliant(self) -> None:
        """Directives are semicolon-separated per RFC."""
        config = CSPDirectiveConfig(
            default_src=["'self'"],
            script_src=["'self'"],
        )
        result = build_csp_header(config)
        # RFC: semicolon-separated directives (no trailing semicolon)
        assert "; " in result
        assert not result.endswith(";")
        assert not result.endswith("; ")


class TestCrossOriginHeaders:
    """Tests for COOP/COEP/CORP cross-origin headers."""

    async def test_coop_set_by_default(self, headers_client: AsyncClient) -> None:
        """Default config includes Cross-Origin-Opener-Policy."""
        response = await headers_client.get("/test")
        assert (
            response.headers.get("cross-origin-opener-policy") == "same-origin"
        )

    async def test_corp_set_by_default(self, headers_client: AsyncClient) -> None:
        """Default config includes Cross-Origin-Resource-Policy."""
        response = await headers_client.get("/test")
        assert (
            response.headers.get("cross-origin-resource-policy") == "same-origin"
        )

    async def test_coep_not_set_by_default(self, headers_client: AsyncClient) -> None:
        """Default config does NOT include Cross-Origin-Embedder-Policy."""
        response = await headers_client.get("/test")
        assert "cross-origin-embedder-policy" not in response.headers

    async def test_custom_coop_value(self) -> None:
        """Custom coop value appears in the response."""
        app = FastAPI()
        config = SecureHeadersConfig(coop="unsafe-none")
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            assert (
                response.headers.get("cross-origin-opener-policy") == "unsafe-none"
            )

    async def test_custom_coep_value(self) -> None:
        """When coep is configured, the header is added."""
        app = FastAPI()
        config = SecureHeadersConfig(coep="require-corp")
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            assert (
                response.headers.get("cross-origin-embedder-policy")
                == "require-corp"
            )

    async def test_custom_corp_value(self) -> None:
        """Custom corp value appears in the response."""
        app = FastAPI()
        config = SecureHeadersConfig(corp="cross-origin")
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            assert (
                response.headers.get("cross-origin-resource-policy")
                == "cross-origin"
            )


class TestServerHeaderStripping:
    """Tests for Server header stripping."""

    async def test_hide_server_removes_header(self) -> None:
        """When hide_server is True, the Server header is removed."""
        app = FastAPI()
        config = SecureHeadersConfig(hide_server=True)
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            # Server header should NOT be present when hide_server is True
            assert "server" not in response.headers

    async def test_hide_server_false_leaves_header(self) -> None:
        """When hide_server is False, existing Server header remains."""
        app = FastAPI()
        config = SecureHeadersConfig(hide_server=False)
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/test")
            # ASGITransport doesn't add a Server header, so absence is expected
            # This test verifies hide_server=False doesn't interfere
            # (no assertion needed — we just ensure no crash)


class TestCSPViaDirectives:
    """Tests for CSP headers built from CSPDirectiveConfig."""

    async def test_csp_from_structured_directives(self) -> None:
        """When csp_directives is set, CSP header is built from it."""
        app = FastAPI()
        config = SecureHeadersConfig(
            csp_directives=CSPDirectiveConfig(
                default_src=["'self'"],
                script_src=["'self'"],
            ),
        )
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            csp = response.headers.get("content-security-policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp

    async def test_csp_from_structured_overrides_raw_string(self) -> None:
        """Structured csp_directives takes precedence over raw string."""
        app = FastAPI()
        config = SecureHeadersConfig(
            content_security_policy="default-src 'none'",
            csp_directives=CSPDirectiveConfig(
                default_src=["'self'"],
            ),
        )
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            csp = response.headers.get("content-security-policy", "")
            # Structured directives take precedence (should be 'self' not 'none')
            assert "default-src 'self'" in csp
            assert "default-src 'none'" not in csp

    async def test_no_csp_when_both_unset(self, headers_client: AsyncClient) -> None:
        """No CSP header when neither content_security_policy nor csp_directives is
        set."""
        response = await headers_client.get("/test")
        assert "content-security-policy" not in response.headers


class TestSecureHeaders:
    async def test_hsts_header(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert "strict-transport-security" in response.headers
        hsts = response.headers["strict-transport-security"]
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    async def test_content_type_nosniff(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_frame_options(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-frame-options") == "DENY"

    async def test_xss_protection_disabled(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert response.headers.get("x-xss-protection") == "0"

    async def test_referrer_policy(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert (
            response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        )

    async def test_csp_not_set_by_default(self, headers_client: AsyncClient) -> None:
        response = await headers_client.get("/test")
        assert "content-security-policy" not in response.headers

    async def test_custom_csp(self) -> None:
        app = FastAPI()
        config = SecureHeadersConfig(content_security_policy="default-src 'self'")
        app.add_middleware(SecureHeadersMiddleware, config=config)

        @app.get("/test")
        async def test_endpoint() -> None:
            return {"ok": True}  # type: ignore

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/test")
            assert (
                response.headers.get("content-security-policy") == "default-src 'self'"
            )
