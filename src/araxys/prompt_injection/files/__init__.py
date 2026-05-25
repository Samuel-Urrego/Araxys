"""File scanning subpackage for prompt injection detection.

Provides lazy-loaded parsers for file formats (images, PDF, Office),
metadata extraction from EXIF/PDF Info/Office core properties, and
hidden/invisible text detection.
"""

from __future__ import annotations

from araxys.prompt_injection.files.hidden_text import (
    detect_office_hidden_text,
    detect_pdf_hidden_text,
)
from araxys.prompt_injection.files.metadata import (
    extract_image_metadata,
    extract_office_metadata,
    extract_pdf_metadata,
    scan_file_metadata,
)
from araxys.prompt_injection.files.parsers import (
    FILE_PARSER_REGISTRY,
    get_parser,
    is_parser_available,
)

__all__ = [
    "FILE_PARSER_REGISTRY",
    "detect_office_hidden_text",
    "detect_pdf_hidden_text",
    "extract_image_metadata",
    "extract_office_metadata",
    "extract_pdf_metadata",
    "get_parser",
    "is_parser_available",
    "scan_file_metadata",
]
