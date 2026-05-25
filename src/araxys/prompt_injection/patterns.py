"""Compiled regex pattern sets for prompt injection detection.

Each module-level constant is a compiled :class:`re.Pattern` used
by the corresponding detector in :mod:`araxys.prompt_injection.detectors`.
"""

from __future__ import annotations

import re

# ── Direct Instruction Injection ──────────────────────────────────────────
# Attempts to override, ignore, or reveal system-level instructions.
DIRECT_INJECTION: re.Pattern[str] = re.compile(
    r"(?i)"
    r"(?:"
    r"ignore\s+(?:all\s+)?(?:previous|above|prior)(?:\s+instructions?)?"
    r"|reveal\s+(?:the\s+)?(?:system\s+)?prompt"
    r"|forget\s+(?:all\s+)?(?:previous|prior)\s+instructions?"
    r"|you\s+(?:are\s+)?no\s+longer\s+(?:bound\s+)?by"
    r"|you\s+must\s+ignore"
    r"|output\s+(?:your\s+)?(?:system\s+)?prompt"
    r"|print\s+(?:your\s+)?(?:system\s+)?prompt"
    r"|show\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)"
    r"|new\s+instructions?[：:]"
    r")",
    re.UNICODE,
)

# ── Jailbreak Attempts ────────────────────────────────────────────────────
# Known jailbreak patterns including "DAN", "do anything now", persona
# switching, and role-play requests that bypass safety filters.
JAILBREAK: re.Pattern[str] = re.compile(
    r"(?i)"
    r"(?:"
    r"\bDAN\b"
    r"|do\s+anything\s+now"
    r"|bypass\s+(?:all\s+)?(?:restrictions|limitations|safeguards|filters|guardrails)"
    r"|you\s+are\s+(?:now|free)\s+"
    r"|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored)"
    r"|role\s+play\s+as"
    r"|no\s+(?:restrictions?|rules?|limits?|boundaries?)"
    r"|you\s+don['\u2019]t\s+have\s+to\s+follow"
    r"|remove\s+(?:all\s+)?(?:restrictions|limitations|safeguards)"
    r"|new\s+persona"
    r")",
    re.UNICODE,
)

# ── Delimiter Escape ──────────────────────────────────────────────────────
# Attempts to close a code/markdown block delimiter and inject new
# instructions, e.g. `` ``` `` followed by ``ignore previous...``.
DELIMITER_ESCAPE: re.Pattern[str] = re.compile(
    r"(?i)"
    r"(?:"
    r"(?:```|~~~|---|___)\s*\n.*?(?:ignore|forget|new\s+instruction|remember)"
    r"|```\s*\n\s*(?:system|user|assistant)\s*[:：]"
    r")",
    re.DOTALL | re.UNICODE,
)

# ── Zero-Width Characters ─────────────────────────────────────────────────
# Invisible Unicode characters used to smuggle text past filters or to
# encode hidden instructions.
ZERO_WIDTH: re.Pattern[str] = re.compile(
    r"[\u200B\u200C\u200D\uFEFF\u2060\u2061\u2062\u2063\u2064]",
)

# ── Homoglyph Characters ──────────────────────────────────────────────────
# Cyrillic (and a few other Unicode) code points that visually resemble
# Latin letters and are used to bypass keyword-based filters.
#
# Common homoglyphs:
#   а (U+0430) → a    е (U+0435) → e    о (U+043E) → o
#   р (U+0440) → p    с (U+0441) → c    у (U+0443) → y
#   х (U+0445) → x    і (U+0456) → i    ѕ (U+0455) → s
#   А (U+0410) → A    В (U+0412) → B    Е (U+0415) → E
#   К (U+041A) → K    М (U+041C) → M    Н (U+041D) → H
#   О (U+041E) → O    Р (U+0420) → P    С (U+0421) → C
#   Т (U+0422) → T    У (U+0423) → Y    Х (U+0425) → X
HOMOGLYPH: re.Pattern[str] = re.compile(
    r"[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0455"
    r"\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420"
    r"\u0421\u0422\u0423\u0425]",
)
