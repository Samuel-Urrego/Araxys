"""Araxys sanitization module.

Provides detectors for injection attacks, a config-driven scanner for
query parameters and headers, and ASGI middleware for request sanitization.
"""

from araxys.sanitize.detectors import (
    detect_command_injection,
    detect_nosql_injection,
    detect_path_traversal,
)
from araxys.sanitize.filters import sanitize_payload, sanitize_value
from araxys.sanitize.middleware import SanitizeMiddleware
from araxys.sanitize.scanner import scan_headers, scan_query_params, scan_value

__all__ = [
    "SanitizeMiddleware",
    "detect_command_injection",
    "detect_nosql_injection",
    "detect_path_traversal",
    "sanitize_payload",
    "sanitize_value",
    "scan_headers",
    "scan_query_params",
    "scan_value",
]
