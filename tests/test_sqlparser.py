"""Tests for the sqlparse-based SQL injection analyzer."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from araxys.sanitize.filters import detect_sqli
from araxys.sanitize.sqlparser import SqlInjectionAnalyzer, SqlInjectionFinding


class TestSqlInjectionFinding:
    """Verify the finding dataclass."""

    def test_creation(self) -> None:
        f = SqlInjectionFinding(type="test", description="test finding", position=5)
        assert f.type == "test"
        assert f.description == "test finding"
        assert f.position == 5

    def test_default_position(self) -> None:
        f = SqlInjectionFinding(type="a", description="b")
        assert f.position == 0


class TestSqlInjectionAnalyzerHappy:
    """All 5 detection methods — sqlparse installed."""

    def test_detects_union_select(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users UNION SELECT * FROM admin")
        assert len(findings) >= 1
        assert any("union" in f.description.lower() for f in findings)

    def test_detects_stacked_queries(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users; DROP TABLE users;")
        assert len(findings) >= 1
        # sqlparse will see at least 2 statements
        assert any("stacked" in f.type for f in findings)

    def test_detects_tautologies(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users WHERE 1=1 OR 'a'='a'")
        assert len(findings) >= 1
        assert any("tautology" in f.type for f in findings)

    def test_detects_time_based_waitfor(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users; WAITFOR DELAY '0:0:5'")
        assert len(findings) >= 1
        assert any("time" in f.type.lower() for f in findings)

    def test_detects_time_based_benchmark(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT BENCHMARK(1000000, MD5('test'))")
        assert len(findings) >= 1
        assert any("time" in f.type.lower() for f in findings)

    def test_detects_time_based_sleep(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("1; SLEEP(5)")
        assert len(findings) >= 1
        assert any("time" in f.type.lower() for f in findings)

    def test_detects_comment_injection_dash_dash(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users -- injected")
        assert len(findings) >= 1
        assert any("comment" in f.type for f in findings)

    def test_detects_comment_injection_block(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users /* block */")
        assert len(findings) >= 1
        assert any("comment" in f.type for f in findings)

    def test_detects_comment_injection_hash(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users # injected")
        assert len(findings) >= 1
        assert any("comment" in f.type for f in findings)

    def test_false_positive_union_in_plain_text(self) -> None:
        """Plain text mentioning UNION and SELECT should NOT be flagged."""
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("I love UNION SELECT statements in SQL")
        # sqlparse will not parse plain text as SQL — no tokens → no findings
        assert len(findings) == 0

    def test_clean_query_not_flagged(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT id, name FROM users WHERE active = true")
        # No stacked queries, no UNION, no tautologies, no comments, no time-based
        assert len(findings) == 0

    def test_empty_string(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        assert analyzer.analyze("") == []

    def test_none_input(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        with pytest.raises((TypeError, AttributeError)):
            analyzer.analyze(None)  # type: ignore[arg-type]

    def test_very_long_string(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        long_text = "A" * 10000
        findings = analyzer.analyze(long_text)
        assert isinstance(findings, list)

    def test_tautology_or_1_eq_1(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users WHERE 1=1 OR 1=1")
        assert len(findings) >= 1
        assert any("tautology" in f.type for f in findings)

    def test_tautology_or_a_eq_a(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users WHERE 'a'='a'")
        assert len(findings) >= 1
        assert any("tautology" in f.type for f in findings)


class TestDetectSQLIIntegration:
    """Integration: detect_sqli() uses SqlInjectionAnalyzer when available."""

    def test_detect_sqli_stacked(self) -> None:
        result = detect_sqli("1; DROP TABLE users; --")
        assert result is not None

    def test_detect_sqli_union(self) -> None:
        result = detect_sqli("1 UNION SELECT * FROM users")
        assert result is not None

    def test_detect_sqli_tautology(self) -> None:
        result = detect_sqli("' OR 1=1 --")
        assert result is not None

    def test_detect_sqli_time_based(self) -> None:
        result = detect_sqli("1; WAITFOR DELAY '0:0:5'")
        assert result is not None

    def test_detect_sqli_comment(self) -> None:
        result = detect_sqli("SELECT * FROM users -- comment")
        assert result is not None

    def test_detect_sqli_clean_input(self) -> None:
        assert detect_sqli("Hello, my name is John") is None

    def test_detect_sqli_false_positive_plain_text(self) -> None:
        """Plain text mentioning UNION SELECT should NOT be SQLi."""
        result = detect_sqli("I love UNION SELECT statements in SQL")
        assert result is None

    def test_detect_sqli_empty_string(self) -> None:
        assert detect_sqli("") is None


class TestFallbackToRegex:
    """When sqlparse is not available, detect_sqli falls back to regex patterns."""

    def test_fallback_on_import_error(self) -> None:
        """Simulate ImportError by patching the module-level import guard."""
        with patch("araxys.sanitize.sqlparser._HAS_SQLPARSE", False):
            # This forces detect_sqli to use the fallback path
            # UNION SELECT should still be detected
            result = detect_sqli("1 UNION SELECT * FROM users")
            assert result is not None

    def test_fallback_clean(self) -> None:
        with patch("araxys.sanitize.sqlparser._HAS_SQLPARSE", False):
            assert detect_sqli("hello world") is None

    def test_fallback_regex_union(self) -> None:
        """Even via regex fallback, UNION SELECT is caught."""
        with patch("araxys.sanitize.sqlparser._HAS_SQLPARSE", False):
            result = detect_sqli("1 UNION SELECT * FROM users")
            assert result is not None
            assert "UNION" in result.upper() or "union" in result.lower()
