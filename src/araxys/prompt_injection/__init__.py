"""Prompt Injection Detection Module.

Provides pure-function detectors, a config-driven scanner, a read-only
ASGI middleware, and a FastAPI ``Depends`` guard for protecting LLM-facing
endpoints from prompt injection attacks.

Public API
----------
- :class:`araxys.core.types.ScanResult` — scan result dataclass
- :class:`araxys.core.exceptions.PromptInjectionError` — injection error
- :func:`detect_direct_injection` — detect instruction override attempts
- :func:`detect_jailbreak` — detect jailbreak attempts (DAN, etc.)
- :func:`detect_delimiter_escape` — detect code-block delimiter escape
- :func:`detect_zero_width_chars` — detect invisible character injection
- :func:`detect_homoglyphs` — detect Cyrillic homoglyph attacks
- :data:`DETECTOR_REGISTRY` — ordered list of (name, detector_fn) pairs
"""

from __future__ import annotations

from araxys.prompt_injection.detectors import (
    DETECTOR_REGISTRY,
    detect_delimiter_escape,
    detect_direct_injection,
    detect_homoglyphs,
    detect_jailbreak,
    detect_zero_width_chars,
)

__all__ = [
    "DETECTOR_REGISTRY",
    "detect_delimiter_escape",
    "detect_direct_injection",
    "detect_homoglyphs",
    "detect_jailbreak",
    "detect_zero_width_chars",
]
