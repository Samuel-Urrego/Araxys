"""Tests for the sanitization module."""

import pytest

from araxys.core.exceptions import SanitizationError
from araxys.sanitize.filters import (
    detect_sqli,
    detect_xss,
    sanitize_payload,
    sanitize_value,
    strip_xss,
)


class TestSQLiDetection:
    def test_detects_union_select(self):
        assert detect_sqli("1 UNION SELECT * FROM users") is not None

    def test_detects_drop_table(self):
        assert detect_sqli("'; DROP TABLE users --") is not None

    def test_detects_boolean_blind(self):
        assert detect_sqli("' OR 1=1 --") is not None

    def test_detects_sleep_injection(self):
        assert detect_sqli("1; SLEEP(5)") is not None

    def test_clean_input_passes(self):
        assert detect_sqli("Hello, my name is John") is None

    def test_clean_email_passes(self):
        assert detect_sqli("user@example.com") is None

    def test_clean_url_passes(self):
        assert detect_sqli("https://example.com/page?q=search") is None


class TestXSSDetection:
    def test_detects_script_tag(self):
        assert detect_xss("<script>alert('xss')</script>") is not None

    def test_detects_javascript_uri(self):
        assert detect_xss("javascript:alert(1)") is not None

    def test_detects_event_handler(self):
        assert detect_xss('<img onerror="alert(1)">') is not None

    def test_detects_iframe(self):
        assert detect_xss("<iframe src='evil.com'>") is not None

    def test_clean_input_passes(self):
        assert detect_xss("Hello, world!") is None

    def test_clean_html_entities_pass(self):
        assert detect_xss("&lt;script&gt;") is None


class TestStripXSS:
    def test_strips_script_tags(self):
        result = strip_xss("<script>alert('xss')</script>hello")
        assert "<script>" not in result
        assert "hello" in result

    def test_strips_all_tags(self):
        result = strip_xss("<b>bold</b> <i>italic</i>")
        assert result == "bold italic"

    def test_preserves_plain_text(self):
        result = strip_xss("just plain text")
        assert result == "just plain text"


class TestSanitizeValue:
    def test_blocks_sqli(self):
        with pytest.raises(SanitizationError, match="SQL Injection"):
            sanitize_value("1 UNION SELECT * FROM users")

    def test_strips_xss(self):
        result = sanitize_value("<script>alert(1)</script>safe text")
        assert "<script>" not in result
        assert "safe text" in result

    def test_clean_value_passes(self):
        result = sanitize_value("normal text")
        assert result == "normal text"


class TestSanitizePayload:
    def test_sanitizes_nested_dict(self):
        data = {
            "name": "John",
            "bio": "<script>alert(1)</script>Developer",
            "meta": {"description": "Safe content"},
        }
        result = sanitize_payload(data)
        assert "<script>" not in result["bio"]
        assert result["name"] == "John"

    def test_sanitizes_list(self):
        data = ["safe", "<script>alert(1)</script>unsafe"]
        result = sanitize_payload(data)
        assert "<script>" not in result[1]

    def test_blocks_sqli_in_nested(self):
        data = {"query": {"filter": "1 UNION SELECT * FROM users"}}
        with pytest.raises(SanitizationError):
            sanitize_payload(data)

    def test_max_depth_exceeded(self):
        # Create deeply nested structure
        data: dict = {"a": None}
        current = data
        for _ in range(15):
            current["a"] = {"a": None}
            current = current["a"]
        current["a"] = "value"

        with pytest.raises(SanitizationError, match="nesting depth"):
            sanitize_payload(data, max_depth=10)

    def test_preserves_non_string_types(self):
        data = {"count": 42, "active": True, "ratio": 3.14, "nothing": None}
        result = sanitize_payload(data)
        assert result == data
