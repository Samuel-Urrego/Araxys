"""XXE (XML External Entity) Protection Module.

Provides config-driven XML scanning to detect and block XXE attacks
including billion-laughs entity expansion, file disclosure via SYSTEM
entities, SSRF via external entities, and DTD-based attacks.

Uses regex pre-scanning for detection with stdlib fallback (defusedxml
is NOT required — the module works entirely without external deps).

Public API
----------
- :class:`araxys.xxe.config.XXEConfig` — per-feature toggles and exclusions
- :class:`araxys.xxe.exceptions.XXEError` — detection error
- :class:`araxys.xxe.scanner.XXEScanner` — config-driven scanner
"""

from __future__ import annotations

from araxys.xxe.config import XXEConfig
from araxys.xxe.exceptions import XXEError
from araxys.xxe.scanner import XXEScanner

__all__ = [
    "XXEConfig",
    "XXEError",
    "XXEScanner",
]
