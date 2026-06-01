"""Module-level tests for the XXE protection module.

Verifies exports integrity and package metadata.
"""

from __future__ import annotations

import tomllib
from pathlib import Path


class TestModuleExports:
    """Verify that the xxe module exports the expected public API."""

    def test_xxe_config_exported(self) -> None:
        from araxys.xxe import XXEConfig

        assert XXEConfig is not None

    def test_xxe_scanner_exported(self) -> None:
        from araxys.xxe import XXEScanner

        assert XXEScanner is not None

    def test_xxe_middleware_exported(self) -> None:
        from araxys.xxe import XXEMiddleware

        assert XXEMiddleware is not None

    def test_xxe_error_exported(self) -> None:
        from araxys.xxe import XXEError

        assert XXEError is not None

    def test_xxe_guard_exported(self) -> None:
        from araxys.xxe import xxe_guard

        assert xxe_guard is not None

    def test_get_xxe_scanner_exported(self) -> None:
        from araxys.xxe import get_xxe_scanner

        assert get_xxe_scanner is not None

    def test_xxe_audit_events_exported(self) -> None:
        from araxys.xxe import XXE_AUDIT_EVENTS

        assert XXE_AUDIT_EVENTS is not None
        from araxys.core.types import AuditEventType

        assert AuditEventType.XXE_DETECTED in XXE_AUDIT_EVENTS

    def test_xxe_security_events_exported(self) -> None:
        from araxys.xxe import XXE_SECURITY_EVENTS

        assert XXE_SECURITY_EVENTS is not None
        from araxys.core.types import SecurityEventType

        assert SecurityEventType.XXE_DETECTED in XXE_SECURITY_EVENTS

    def test_all_exports_match_expected(self) -> None:
        from araxys.xxe import __all__

        expected = {
            "XXEConfig",
            "XXEError",
            "XXEMiddleware",
            "XXEScanner",
            "get_xxe_scanner",
            "xxe_guard",
            "XXE_AUDIT_EVENTS",
            "XXE_SECURITY_EVENTS",
        }
        assert set(__all__) == expected

    def test_root_araxys_exports_xxe(self) -> None:
        import araxys

        assert hasattr(araxys, "XXEConfig")
        assert hasattr(araxys, "XXEError")
        assert hasattr(araxys, "XXEScanner")
        assert hasattr(araxys, "XXEMiddleware")
        assert hasattr(araxys, "xxe_guard")
        assert hasattr(araxys, "get_xxe_scanner")


class TestDependencyExtra:
    """Verify [xxe] extra is declared in pyproject.toml."""

    def test_xxe_extra_declared(self) -> None:
        pyproject = Path("pyproject.toml")
        assert pyproject.exists(), "pyproject.toml not found"

        with pyproject.open("rb") as f:
            data = tomllib.load(f)

        extras = data.get("project", {}).get("optional-dependencies", {})
        assert "xxe" in extras, "[xxe] extra not found in pyproject.toml"
        assert "defusedxml>=0.7.1" in extras["xxe"], (
            "Expected defusedxml>=0.7.1 in [xxe] extra"
        )
