"""Lazy import wrappers for optional file format parsers.

Each format is registered in :data:`FILE_PARSER_REGISTRY` with its
import path, class/function name, and install hint.  Parsers are
imported on demand (lazy) so missing optional dependencies do not
prevent the module from loading.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Registry: format → (import_path, class_or_function_name, install_hint)
FILE_PARSER_REGISTRY: dict[str, tuple[str, str, str]] = {
    "image": (
        "PIL.Image",
        "open",
        "pip install araxys[prompt-guard-image]",
    ),
    "pdf": (
        "pypdf",
        "PdfReader",
        "pip install araxys[prompt-guard-pdf]",
    ),
    "docx": (
        "docx",
        "Document",
        "pip install araxys[prompt-guard-office]",
    ),
    "xlsx": (
        "openpyxl",
        "load_workbook",
        "pip install araxys[prompt-guard-office]",
    ),
}


def get_parser(format: str) -> Any | None:
    """Lazy-load a file format parser.

    Parameters
    ----------
    format:
        The format key from :data:`FILE_PARSER_REGISTRY` (e.g. ``"image"``,
        ``"pdf"``, ``"docx"``).

    Returns
    -------
    The parser class/function or ``None`` if the format is unknown or
    the dependency is not installed.
    """
    try:
        import_path, name, _hint = FILE_PARSER_REGISTRY[format]
    except KeyError:
        return None

    try:
        module = importlib.import_module(import_path)
        return getattr(module, name)
    except ImportError:
        logger.warning(
            "Parser for '%s' is not available. Install: %s",
            format,
            _hint,
        )
        return None


def is_parser_available(format: str) -> bool:
    """Check whether a parser is installed **without** importing it.

    Attempts a quick ``importlib.import_module`` of the root package
    and catches ``ImportError`` so the full module tree is not loaded.

    Parameters
    ----------
    format:
        The format key from :data:`FILE_PARSER_REGISTRY`.

    Returns
    -------
    ``True`` if the underlying dependency can be imported.
    """
    try:
        import_path, _name, _hint = FILE_PARSER_REGISTRY[format]
    except KeyError:
        return False

    # For dotted paths like "PIL.Image" we only check the root package
    root = import_path.split(".", 1)[0]
    try:
        importlib.import_module(root)
        return True
    except ImportError:
        return False
