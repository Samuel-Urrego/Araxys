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
- :class:`PromptInjectionScanner` — config-driven scanner
- :class:`PromptInjectionMiddleware` — read-only ASGI middleware
- :func:`prompt_injection_guard` — per-endpoint FastAPI ``Depends``
- :func:`get_prompt_injection_scanner` — scanner factory dependency
- :data:`FILE_PARSER_REGISTRY` — file format parser registry
- :func:`scan_file_metadata` — metadata extraction for files
- :func:`detect_pdf_hidden_text` — hidden text detection for PDFs
- :func:`detect_office_hidden_text` — hidden text detection for Office docs
"""

from __future__ import annotations

from araxys.prompt_injection.dependencies import (
    PromptInjectionGuard,
    get_prompt_injection_scanner,
    prompt_injection_guard,
)
from araxys.prompt_injection.detectors import (
    DETECTOR_REGISTRY,
    detect_delimiter_escape,
    detect_direct_injection,
    detect_homoglyphs,
    detect_jailbreak,
    detect_zero_width_chars,
)
from araxys.prompt_injection.files import (
    FILE_PARSER_REGISTRY,
    detect_office_hidden_text,
    detect_pdf_hidden_text,
    extract_image_metadata,
    extract_office_metadata,
    extract_pdf_metadata,
    get_parser,
    is_parser_available,
    scan_file_metadata,
)
from araxys.prompt_injection.middleware import PromptInjectionMiddleware
from araxys.prompt_injection.scanner import PromptInjectionScanner

__all__ = [
    "DETECTOR_REGISTRY",
    "FILE_PARSER_REGISTRY",
    "PromptInjectionGuard",
    "PromptInjectionMiddleware",
    "PromptInjectionScanner",
    "detect_delimiter_escape",
    "detect_direct_injection",
    "detect_homoglyphs",
    "detect_jailbreak",
    "detect_office_hidden_text",
    "detect_pdf_hidden_text",
    "detect_zero_width_chars",
    "extract_image_metadata",
    "extract_office_metadata",
    "extract_pdf_metadata",
    "get_parser",
    "get_prompt_injection_scanner",
    "is_parser_available",
    "prompt_injection_guard",
    "scan_file_metadata",
]
