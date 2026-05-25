"""Pure-function detectors for prompt injection attacks.

Each detector is a callable with the signature ``(text: str) -> str | None``
where the return value is a human-readable threat description when a pattern
is matched, or ``None`` when the text is clean.

The module-level :data:`DETECTOR_REGISTRY` provides an ordered list of all
registered detectors. Users may append custom detectors at startup.
"""

from __future__ import annotations

from collections.abc import Callable

from araxys.prompt_injection.patterns import (
    DELIMITER_ESCAPE,
    DIRECT_INJECTION,
    HOMOGLYPH,
    JAILBREAK,
    ZERO_WIDTH,
)

# Type alias for detector functions.
# Takes a text string, returns a threat description or None.
DetectorFn = Callable[[str], str | None]


# ── Direct Instruction Injection ───────────────────────────────────────────

def detect_direct_injection(text: str) -> str | None:
    """Detect attempts to override, ignore, or reveal system instructions.

    Matches patterns like "ignore previous instructions", "reveal the
    system prompt", "show your prompt", and "new instructions:".
    """
    if DIRECT_INJECTION.search(text):
        return "Direct instruction injection"
    return None


# ── Jailbreak Attempts ────────────────────────────────────────────────────

def detect_jailbreak(text: str) -> str | None:
    """Detect jailbreak attempts — DAN, bypass, role-play, persona switch.

    Matches patterns like "do anything now", "bypass restrictions",
    "act as unrestricted", and "no rules".
    """
    if JAILBREAK.search(text):
        return "Jailbreak attempt"
    return None


# ── Delimiter Escape ──────────────────────────────────────────────────────

def detect_delimiter_escape(text: str) -> str | None:
    """Detect delimiter escape — closing a block and injecting new instructions.

    Matches patterns like `````\\nignore previous...`` and
    `````\\nsystem:`` which attempt to close a code block and
    issue new instructions.
    """
    if DELIMITER_ESCAPE.search(text):
        return "Delimiter escape"
    return None


# ── Zero-Width Characters ─────────────────────────────────────────────────

def detect_zero_width_chars(text: str) -> str | None:
    """Detect invisible Unicode characters used to hide injected text.

    Matches zero-width space (\\u200B), zero-width non-joiner (\\u200C),
    zero-width joiner (\\u200D), BOM (\\uFEFF), and word joiner (\\u2060).
    """
    if ZERO_WIDTH.search(text):
        return "Zero-width character injection"
    return None


# ── Homoglyph Attacks ─────────────────────────────────────────────────────

def detect_homoglyphs(text: str) -> str | None:
    """Detect Cyrillic homoglyph characters that visually replace Latin letters.

    Matches Cyrillic code points that closely resemble Latin letters
    (e.g. Cyrillic 'а' U+0430 for Latin 'a', Cyrillic 'е' U+0435 for 'e').
    """
    if HOMOGLYPH.search(text):
        return "Homoglyph attack"
    return None


# ── Detector Registry ─────────────────────────────────────────────────────

DETECTOR_REGISTRY: list[tuple[str, DetectorFn]] = [
    ("direct_injection", detect_direct_injection),
    ("jailbreak", detect_jailbreak),
    ("delimiter_escape", detect_delimiter_escape),
    ("zero_width_chars", detect_zero_width_chars),
    ("homoglyphs", detect_homoglyphs),
]
"""Ordered registry of all built-in detectors.

Order determines priority when multiple detectors match — the first
match in this list wins. Users may append custom detectors at runtime::

    from araxys.prompt_injection.detectors import DETECTOR_REGISTRY

    def my_custom_detector(text: str) -> str | None:
        if "malicious" in text:
            return "Custom threat detected"
        return None

    DETECTOR_REGISTRY.append(("custom", my_custom_detector))
"""
