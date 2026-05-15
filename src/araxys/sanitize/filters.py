"""Sanitization filters for SQL injection and XSS detection.

These filters analyze string values within request payloads and
either block or clean them depending on configuration.
"""


from __future__ import annotations

import bleach  # type: ignore
import structlog

from araxys.core.exceptions import SanitizationError
from araxys.sanitize.patterns import SQLI_PATTERNS, XSS_PATTERNS

logger = structlog.get_logger("araxys.sanitize")


def detect_sqli(value: str) -> str | None:
    """Check a string for SQL injection patterns.

    Returns the description of the matched pattern, or None if clean.
    """
    for pattern, description in SQLI_PATTERNS:
        if pattern.search(value):
            return description
    return None


def detect_xss(value: str) -> str | None:
    """Check a string for XSS attack patterns.

    Returns the description of the matched pattern, or None if clean.
    """
    for pattern, description in XSS_PATTERNS:
        if pattern.search(value):
            return description
    return None


def strip_xss(value: str) -> str:
    """Remove XSS payloads from a string using bleach.

    Strips ALL tags and attributes — returns plain text.
    """
    return bleach.clean(value, tags=[], attributes={}, strip=True)  # type: ignore


def sanitize_value(
    value: str,
    *,
    block_sqli: bool = True,
    strip_xss_content: bool = True,
) -> str:
    """Sanitize a single string value.

    Parameters
    ----------
    value:
        The string to sanitize.
    block_sqli:
        If True, raise on SQL injection detection.
    strip_xss_content:
        If True, strip XSS payloads from the value.

    Returns
    -------
    The sanitized string.

    Raises
    ------
    SanitizationError
        If SQL injection is detected (SQLi is always blocked, never stripped).
    """
    if block_sqli:
        sqli_match = detect_sqli(value)
        if sqli_match:
            logger.warning(
                "sanitize.sqli_detected",
                threat=sqli_match,
                preview=value[:100],
            )
            raise SanitizationError(
                threat_type=f"SQL Injection ({sqli_match})",
                value_preview=value[:100],
            )

    if strip_xss_content:
        xss_match = detect_xss(value)
        if xss_match:
            logger.warning(
                "sanitize.xss_detected",
                threat=xss_match,
                preview=value[:100],
            )
            value = strip_xss(value)

    return value


def sanitize_payload(
    data: dict | list | str | int | float | bool | None,  # type: ignore
    *,
    block_sqli: bool = True,
    strip_xss_content: bool = True,
    max_depth: int = 10,
    _current_depth: int = 0,
) -> dict | list | str | int | float | bool | None:  # type: ignore
    """Recursively sanitize a JSON payload.

    Walks through dicts and lists, sanitizing all string values.

    Parameters
    ----------
    data:
        The parsed JSON payload.
    block_sqli:
        Block SQL injection attempts.
    strip_xss_content:
        Strip XSS from string values.
    max_depth:
        Maximum recursion depth to prevent DoS via deeply nested payloads.

    Raises
    ------
    SanitizationError
        If SQL injection is detected or max depth is exceeded.
    """
    if _current_depth > max_depth:
        raise SanitizationError(
            threat_type="Excessive nesting depth",
            value_preview=f"Depth {_current_depth} exceeds max {max_depth}",
        )

    if isinstance(data, str):
        return sanitize_value(
            data, block_sqli=block_sqli, strip_xss_content=strip_xss_content
        )

    if isinstance(data, dict):
        return {
            key: sanitize_payload(
                value,
                block_sqli=block_sqli,
                strip_xss_content=strip_xss_content,
                max_depth=max_depth,
                _current_depth=_current_depth + 1,
            )
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [
            sanitize_payload(
                item,
                block_sqli=block_sqli,
                strip_xss_content=strip_xss_content,
                max_depth=max_depth,
                _current_depth=_current_depth + 1,
            )
            for item in data
        ]

    # int, float, bool, None — pass through
    return data
