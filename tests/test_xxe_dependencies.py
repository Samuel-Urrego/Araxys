"""Tests for XXE dependencies (xxe_guard + get_xxe_scanner).

Strict TDD: tests written BEFORE implementation.
"""

from __future__ import annotations

import pytest

# ═════════════════════════════════════════════════════════════════════════════
# T2.4 — Dependencies Unit Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestXXEGuardFactory:
    """xxe_guard() factory produces correct callables."""

    def test_factory_returns_callable(self) -> None:
        """xxe_guard() returns a callable."""
        from araxys.xxe.dependencies import xxe_guard

        guard = xxe_guard()
        assert callable(guard)

    def test_factory_accepts_config_override(self) -> None:
        """xxe_guard() accepts optional XXEConfig override."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.dependencies import xxe_guard

        config = XXEConfig(forbid_dtd=False)
        guard = xxe_guard(config_override=config)
        assert callable(guard)


class TestXXEGuardDetection:
    """xxe_guard() detects XXE in string/bytes input."""

    def test_detects_xxe_in_string(self) -> None:
        """Guard raises XXEError when XXE detected in string."""
        from araxys.xxe.dependencies import xxe_guard
        from araxys.xxe.exceptions import XXEError

        guard = xxe_guard()

        malicious = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

        with pytest.raises(XXEError) as exc_info:
            guard(malicious)

        assert exc_info.value.detection_type is not None
        # First threat detected is DTD (before SYSTEM is processed)
        assert exc_info.value.detection_type in ("dtd", "entity", "external_entity")

    def test_passes_clean_xml(self) -> None:
        """Guard returns ScanResult for clean XML (no raise)."""
        from araxys.core.types import ScanResult
        from araxys.xxe.dependencies import xxe_guard

        guard = xxe_guard()

        clean = "<root><item>safe content</item></root>"
        result = guard(clean)

        assert isinstance(result, ScanResult)
        assert not result.is_threat

    def test_handles_bytes_input(self) -> None:
        """Guard accepts bytes input and detects threats."""
        from araxys.xxe.dependencies import xxe_guard
        from araxys.xxe.exceptions import XXEError

        guard = xxe_guard()

        malicious = b"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

        with pytest.raises(XXEError):
            guard(malicious)

    def test_clean_bytes_input(self) -> None:
        """Guard accepts clean bytes input without raising."""
        from araxys.core.types import ScanResult
        from araxys.xxe.dependencies import xxe_guard

        guard = xxe_guard()

        result = guard(b"<root><item>safe</item></root>")
        assert isinstance(result, ScanResult)
        assert not result.is_threat

    def test_handles_non_xml_gracefully(self) -> None:
        """Guard handles non-XML content without error."""
        from araxys.core.types import ScanResult
        from araxys.xxe.dependencies import xxe_guard

        guard = xxe_guard()

        result = guard("This is just plain text, not XML.")
        assert isinstance(result, ScanResult)
        assert not result.is_threat

    def test_billion_laughs_detected(self) -> None:
        """Billion-laughs entity expansion is detected."""
        from araxys.xxe.dependencies import xxe_guard
        from araxys.xxe.exceptions import XXEError

        guard = xxe_guard()

        payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>"""

        with pytest.raises(XXEError):
            guard(payload)

    def test_guard_with_forbid_dtd_false_allows_dtd(self) -> None:
        """Guard with forbid_dtd=False allows DOCTYPE declarations."""
        from araxys.core.types import ScanResult
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.dependencies import xxe_guard

        guard = xxe_guard(config_override=XXEConfig(forbid_dtd=False))

        payload = """<?xml version="1.0"?>
<!DOCTYPE foo>
<root>test</root>"""
        result = guard(payload)
        assert isinstance(result, ScanResult)
        assert not result.is_threat


class TestGetXXEScanner:
    """get_xxe_scanner() returns XXEScanner instance."""

    def test_returns_scanner(self) -> None:
        """get_xxe_scanner() returns an XXEScanner."""
        from araxys.xxe.dependencies import get_xxe_scanner
        from araxys.xxe.scanner import XXEScanner

        scanner = get_xxe_scanner()
        assert isinstance(scanner, XXEScanner)

    def test_returns_scanner_with_config(self) -> None:
        """get_xxe_scanner() accepts optional config override."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.dependencies import get_xxe_scanner
        from araxys.xxe.scanner import XXEScanner

        config = XXEConfig(forbid_dtd=False)
        scanner = get_xxe_scanner(config=config)
        assert isinstance(scanner, XXEScanner)

    def test_scanner_works_with_scan(self) -> None:
        """Scanner returned by get_xxe_scanner() can scan."""
        from araxys.core.types import ScanResult
        from araxys.xxe.dependencies import get_xxe_scanner

        scanner = get_xxe_scanner()
        result = scanner.scan("<root><item>safe</item></root>")
        assert isinstance(result, ScanResult)
        assert not result.is_threat
