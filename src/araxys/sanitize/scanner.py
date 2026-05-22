"""URL-decoding scanner that applies enabled detectors to request data.

The scanner is config-driven: each detector runs only when its corresponding
config flag is ``True``. Values are URL-decoded before scanning to catch
encoded attack payloads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import unquote_plus

from araxys.sanitize.detectors import (
    detect_command_injection,
    detect_nosql_injection,
    detect_path_traversal,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from araxys.core.config import SanitizeConfig


def scan_value(value: str, config: SanitizeConfig) -> str | None:
    """Apply all enabled detectors to a single URL-decoded string value.

    Parameters
    ----------
    value:
        The raw (potentially URL-encoded) string to scan.
    config:
        Sanitization configuration controlling which checks run.

    Returns
    -------
    The threat description if a detector matched, or ``None``.
    """
    decoded = unquote_plus(value)
    # Iteratively decode to defeat double-URL-encoded payloads.
    # e.g. %253Cscript%253E → %3Cscript%3E → <script>
    for _ in range(3):
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded

    if config.check_nosql_injection:
        result = detect_nosql_injection(decoded)
        if result is not None:
            return result

    if config.check_command_injection:
        result = detect_command_injection(decoded)
        if result is not None:
            return result

    if config.check_path_traversal:
        result = detect_path_traversal(decoded)
        if result is not None:
            return result

    return None


def scan_query_params(request: Request, config: SanitizeConfig) -> str | None:
    """Scan all query parameter names and values for injection patterns.

    Both the parameter name and its value are scanned — attacks often hide
    operators in the parameter name (e.g. ``?username[$ne]=admin``).

    Parameters
    ----------
    request:
        The incoming Starlette request.
    config:
        Sanitization configuration.

    Returns
    -------
    The first threat description found, or ``None``.
    """
    for key, value in request.query_params.multi_items():
        # Scan both the parameter name and its value
        for candidate in (key, value):
            threat = scan_value(candidate, config)
            if threat is not None:
                return threat
    return None


def scan_headers(request: Request, config: SanitizeConfig) -> str | None:
    """Scan all request header values for injection patterns.

    Parameters
    ----------
    request:
        The incoming Starlette request.
    config:
        Sanitization configuration.

    Returns
    -------
    The first threat description found, or ``None``.
    """
    for _key, value in request.headers.items():
        threat = scan_value(value, config)
        if threat is not None:
            return threat
    return None
