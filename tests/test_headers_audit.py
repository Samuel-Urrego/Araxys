"""Tests for security headers audit module."""


class TestAuditFinding:
    def test_audit_finding_dataclass(self) -> None:
        from araxys.headers.auditor import AuditFinding

        f = AuditFinding(
            header_name="Strict-Transport-Security",
            status="pass",
            found_value="max-age=31536000",
        )
        assert f.header_name == "Strict-Transport-Security"
        assert f.status == "pass"
        assert f.found_value == "max-age=31536000"
        assert f.severity == "info"

    def test_audit_finding_with_all_fields(self) -> None:
        from araxys.headers.auditor import AuditFinding

        f = AuditFinding(
            header_name="X-Frame-Options",
            status="fail",
            found_value=None,
            recommended_value="DENY",
            severity="high",
            detail="Missing header.",
        )
        assert f.header_name == "X-Frame-Options"
        assert f.status == "fail"
        assert f.found_value is None
        assert f.recommended_value == "DENY"
        assert f.severity == "high"
        assert f.detail == "Missing header."


class TestAuditHeaders:
    def test_audit_headers_returns_all_nine_checks(self) -> None:
        from araxys.headers.auditor import audit_headers

        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "0",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        findings = audit_headers(headers)
        assert len(findings) == 9

    def test_all_pass_with_secure_headers(self) -> None:
        from araxys.headers.auditor import audit_headers

        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "0",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
        findings = audit_headers(headers)
        for f in findings:
            assert f.status == "pass", f"{f.header_name}: {f.status} — {f.detail}"

    def test_empty_headers_returns_warnings_and_fails(self) -> None:
        from araxys.headers.auditor import audit_headers

        findings = audit_headers({})
        non_pass = [f for f in findings if f.status != "pass"]
        assert len(non_pass) > 0
        # At least HSTS should fail when missing
        hsts = next(f for f in findings if f.header_name == "Strict-Transport-Security")
        assert hsts.status == "fail"


class TestAuditHSTS:
    def test_hsts_missing(self) -> None:
        from araxys.headers.auditor import _audit_hsts

        f = _audit_hsts({})
        assert f.status == "fail"
        assert f.severity == "high"

    def test_hsts_short_max_age(self) -> None:
        from araxys.headers.auditor import _audit_hsts

        f = _audit_hsts({"Strict-Transport-Security": "max-age=3600"})
        assert f.status == "warn"
        assert "3600" in (f.detail or "")

    def test_hsts_missing_subdomains(self) -> None:
        from araxys.headers.auditor import _audit_hsts

        f = _audit_hsts(
            {"Strict-Transport-Security": "max-age=31536000"}
        )
        assert f.status == "warn"

    def test_hsts_valid(self) -> None:
        from araxys.headers.auditor import _audit_hsts

        f = _audit_hsts(
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        )
        assert f.status == "pass"


class TestAuditContentTypeOptions:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_content_type_options

        f = _audit_content_type_options({})
        assert f.status == "fail"

    def test_wrong_value(self) -> None:
        from araxys.headers.auditor import _audit_content_type_options

        f = _audit_content_type_options({"X-Content-Type-Options": "none"})
        assert f.status == "fail"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_content_type_options

        f = _audit_content_type_options({"X-Content-Type-Options": "nosniff"})
        assert f.status == "pass"


class TestAuditFrameOptions:
    def test_missing_no_csp(self) -> None:
        from araxys.headers.auditor import _audit_frame_options

        f = _audit_frame_options({})
        assert f.status == "warn"

    def test_with_csp_frame_ancestors(self) -> None:
        from araxys.headers.auditor import _audit_frame_options

        f = _audit_frame_options(
            {"Content-Security-Policy": "frame-ancestors 'none'"}
        )
        assert f.status == "pass"

    def test_valid_deny(self) -> None:
        from araxys.headers.auditor import _audit_frame_options

        f = _audit_frame_options({"X-Frame-Options": "DENY"})
        assert f.status == "pass"


class TestAuditCSP:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_csp

        f = _audit_csp({})
        assert f.status == "warn"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_csp

        f = _audit_csp({"Content-Security-Policy": "default-src 'self'"})
        assert f.status == "pass"

    def test_unsafe_inline_without_nonce(self) -> None:
        from araxys.headers.auditor import _audit_csp

        f = _audit_csp(
            {
                "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
            }
        )
        assert f.status == "warn"

    def test_unsafe_eval(self) -> None:
        from araxys.headers.auditor import _audit_csp

        f = _audit_csp(
            {"Content-Security-Policy": "script-src 'unsafe-eval'"}
        )
        assert f.status == "warn"


class TestAuditXSSProtection:
    def test_disabled_zero(self) -> None:
        from araxys.headers.auditor import _audit_xss_protection

        f = _audit_xss_protection({"X-XSS-Protection": "0"})
        assert f.status == "pass"

    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_xss_protection

        f = _audit_xss_protection({})
        assert f.status == "info"


class TestAuditReferrerPolicy:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_referrer_policy

        f = _audit_referrer_policy({})
        assert f.status == "warn"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_referrer_policy

        f = _audit_referrer_policy(
            {"Referrer-Policy": "strict-origin-when-cross-origin"}
        )
        assert f.status == "pass"

    def test_unsafe_url_warns(self) -> None:
        from araxys.headers.auditor import _audit_referrer_policy

        f = _audit_referrer_policy({"Referrer-Policy": "unsafe-url"})
        assert f.status == "warn"


class TestAuditCOOP:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_coop

        f = _audit_coop({})
        assert f.status == "warn"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_coop

        f = _audit_coop({"Cross-Origin-Opener-Policy": "same-origin"})
        assert f.status == "pass"

    def test_unsafe_none_warns(self) -> None:
        from araxys.headers.auditor import _audit_coop

        f = _audit_coop({"Cross-Origin-Opener-Policy": "unsafe-none"})
        assert f.status == "warn"


class TestAuditCORP:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_corp

        f = _audit_corp({})
        assert f.status == "warn"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_corp

        f = _audit_corp(
            {"Cross-Origin-Resource-Policy": "same-origin"}
        )
        assert f.status == "pass"

    def test_cross_origin_warns(self) -> None:
        from araxys.headers.auditor import _audit_corp

        f = _audit_corp(
            {"Cross-Origin-Resource-Policy": "cross-origin"}
        )
        assert f.status == "warn"


class TestAuditPermissionsPolicy:
    def test_missing(self) -> None:
        from araxys.headers.auditor import _audit_permissions_policy

        f = _audit_permissions_policy({})
        assert f.status == "info"

    def test_valid(self) -> None:
        from araxys.headers.auditor import _audit_permissions_policy

        f = _audit_permissions_policy(
            {"Permissions-Policy": "camera=(), microphone=()"}
        )
        assert f.status == "pass"

    def test_wildcard_warns(self) -> None:
        from araxys.headers.auditor import _audit_permissions_policy

        f = _audit_permissions_policy({"Permissions-Policy": "camera=*"})
        assert f.status == "warn"


class TestAuditConfig:
    def test_defaults(self) -> None:
        from araxys.headers.config import AuditConfig

        c = AuditConfig()
        assert c.enabled is False
        assert c.sample_rate == 1.0
        assert "/docs" in c.exclude_paths
        assert c.emit_to_event_bus is True

    def test_custom_values(self) -> None:
        from araxys.headers.config import AuditConfig

        c = AuditConfig(
            enabled=True,
            sample_rate=0.5,
            exclude_paths=["/healthz"],
            emit_to_event_bus=False,
        )
        assert c.enabled is True
        assert c.sample_rate == 0.5
        assert c.exclude_paths == ["/healthz"]
        assert c.emit_to_event_bus is False

    def test_sample_rate_ge_0(self) -> None:
        import pytest

        from araxys.headers.config import AuditConfig

        with pytest.raises(Exception):
            AuditConfig(sample_rate=-0.1)

    def test_sample_rate_le_1(self) -> None:
        import pytest

        from araxys.headers.config import AuditConfig

        with pytest.raises(Exception):
            AuditConfig(sample_rate=1.1)
