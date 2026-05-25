"""File metadata extraction for prompt injection detection.

Extracts text from EXIF (images), /Info dictionary (PDF), and core+
extended properties (Office documents) and feeds them through the
standard text detectors so injection hidden in file metadata is
caught alongside direct text injection.
"""

from __future__ import annotations

import logging
from io import BytesIO
from typing import TYPE_CHECKING, Any

from araxys.core.types import ScanResult
from araxys.prompt_injection.detectors import DETECTOR_REGISTRY

if TYPE_CHECKING:
    from araxys.core.config import FileScanConfig

logger = logging.getLogger(__name__)

# Each detector match contributes this base score.
_DETECTOR_BASE_SCORE: float = 0.3


# ── Internal helpers ─────────────────────────────────────────────────────────


def _read_file_bytes(file: Any) -> bytes:  # noqa: ANN401
    """Read *file* into ``bytes`` regardless of whether it is bytes, ``BytesIO``, etc.

    Returns a ``bytes`` object safe for parsing.
    """
    if isinstance(file, bytes):
        return file
    if isinstance(file, bytearray):
        return bytes(file)
    if hasattr(file, "read"):
        pos = file.tell() if hasattr(file, "tell") else None
        data = file.read()
        if pos is not None:
            file.seek(pos)
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode("utf-8", errors="replace")
        return b""
    return b""


# ── Image (EXIF / IPTC / XMP / PNG chunks) ───────────────────────────────────


def extract_image_metadata(file: Any) -> dict[str, str]:  # noqa: ANN401
    """Extract text metadata from an image file.

    Reads EXIF, IPTC, XMP, and PNG text chunks and returns them
    as a flat dict of ``field_name → text_value``.

    Returns an **empty dict** when Pillow is not installed or the file
    cannot be parsed (graceful degradation).
    """
    try:
        from PIL import Image as PILImage
        from PIL.ExifTags import Base as ExifBase
    except ImportError:
        logger.warning("Pillow not installed — image metadata scanning disabled")
        return {}

    try:
        data = _read_file_bytes(file)
        img = PILImage.open(BytesIO(data))
    except Exception:
        logger.warning("Failed to open image for metadata extraction", exc_info=True)
        return {}

    meta: dict[str, str] = {}

    # ── EXIF tags ────────────────────────────────────────────────────────
    try:
        exif = img.getexif()
        for tag_id, value in exif.items():
            try:
                tag_name = ExifBase(tag_id).name
            except (ValueError, AttributeError):
                tag_name = f"EXIF_{tag_id}"

            # Skip binary/non-text tags
            if isinstance(value, (int, float)):
                continue
            if isinstance(value, bytes):
                try:
                    str_value = value.decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    continue
            else:
                str_value = str(value)

            if str_value.strip():
                meta[tag_name] = str_value
    except Exception:
        logger.warning("Failed to extract EXIF metadata", exc_info=True)

    # ── PNG text chunks ──────────────────────────────────────────────────
    try:
        if hasattr(img, "text"):
            for key, value in img.text.items():
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        continue
                if str(value).strip():
                    meta[f"PNG_{key}"] = str(value)
    except Exception:
        logger.warning("Failed to extract PNG text chunks", exc_info=True)

    img.close()
    return meta


# ── PDF (/Info dictionary) ───────────────────────────────────────────────────


def extract_pdf_metadata(file: Any) -> dict[str, str]:  # noqa: ANN401
    """Extract text metadata from a PDF's /Info dictionary.

    Fields: Author, Title, Subject, Keywords, Creator, Producer.

    Returns an **empty dict** when pypdf is not installed or the file
    cannot be parsed.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        logger.warning("pypdf not installed — PDF metadata scanning disabled")
        return {}

    try:
        data = _read_file_bytes(file)
        reader = PdfReader(BytesIO(data))
    except Exception:
        logger.warning("Failed to open PDF for metadata extraction", exc_info=True)
        return {}

    meta: dict[str, str] = {}

    try:
        info = reader.metadata
        if info is not None:
            for key, value in info.items():
                # Remove leading '/' from PDF key names
                clean_key = key.lstrip("/") if isinstance(key, str) else str(key)
                str_value = str(value) if value is not None else ""
                if str_value.strip():
                    meta[clean_key] = str_value
    except Exception:
        logger.warning("Failed to extract PDF metadata", exc_info=True)

    return meta


# ── Office (core + extended properties) ──────────────────────────────────────


def extract_office_metadata(file: Any) -> dict[str, str]:  # noqa: ANN401
    """Extract core and extended properties from Office documents.

    Works for both DOCX (python-docx) and XLSX (openpyxl).

    Core properties: dc:creator, dc:description, dc:title, cp:keywords.
    Extended: Company, Manager, LastModifiedBy.

    Returns an **empty dict** when the required library is not installed
    or the file cannot be parsed.
    """
    data = _read_file_bytes(file)
    meta: dict[str, str] = {}

    # Try python-docx first
    try:
        from docx import Document as DocxDocument

        doc = DocxDocument(BytesIO(data))
        cp = doc.core_properties

        fields: dict[str, str | None] = {
            "author": cp.author,
            "title": cp.title,
            "subject": cp.subject,
            "comments": cp.comments,
            "category": cp.category,
            "keywords": cp.keywords,
            "last_modified_by": cp.last_modified_by,
            "created": str(cp.created) if cp.created else None,
            "modified": str(cp.modified) if cp.modified else None,
        }
        for key, value in fields.items():
            if value and str(value).strip():
                meta[key] = str(value)

        return meta
    except ImportError:
        pass
    except Exception:
        logger.warning(
            "Failed to extract Office metadata via python-docx", exc_info=True
        )

    # Fall back to openpyxl
    try:
        import openpyxl

        wb = openpyxl.load_workbook(BytesIO(data), read_only=True, data_only=True)
        props = wb.properties

        xl_fields: dict[str, str | None] = {
            "creator": props.creator,
            "title": props.title,
            "description": props.description,
            "subject": props.subject,
            "keywords": props.keywords,
            "category": props.category,
            "last_modified_by": props.lastModifiedBy,
            "company": props.company,
            "manager": props.manager,
        }
        for key, value in xl_fields.items():
            if value and str(value).strip():
                meta[key] = str(value)

        wb.close()
        return meta
    except ImportError:
        logger.warning(
            "Neither python-docx nor openpyxl installed — Office metadata disabled",
        )
        return {}
    except Exception:
        logger.warning("Failed to extract Office metadata via openpyxl", exc_info=True)
        return {}


# ── scan_file_metadata — extract + detect ────────────────────────────────────


def scan_file_metadata(
    file: Any,  # noqa: ANN401
    config: FileScanConfig,
    *,
    format: str | None = None,
) -> ScanResult:
    """Extract metadata from *file* and run text detectors on all text values.

    Parameters
    ----------
    file:
        File content as ``bytes``, ``BytesIO``, or file-like object.
    config:
        File scanning configuration (controls which formats are scanned).
    format:
        Optional format hint (``"image"``, ``"pdf"``, ``"docx"``, ``"xlsx"``).
        Auto-detected from magic bytes when omitted.

    Returns
    -------
    :class:`~araxys.core.types.ScanResult` aggregated from metadata text.
    """
    # Auto-detect format from magic bytes when not provided
    if format is None:
        format = _detect_format(file)

    if format is None:
        return ScanResult()

    # Resolve the extraction function
    if format == "image":
        meta = extract_image_metadata(file)
    elif format == "pdf":
        meta = extract_pdf_metadata(file)
    elif format in ("docx", "xlsx", "pptx", "office"):
        meta = extract_office_metadata(file)
    else:
        return ScanResult()

    if not meta:
        return ScanResult()

    # Run text detectors on concatenated metadata
    text = " ".join(meta.values())
    triggered: list[str] = []
    matched_pattern: str | None = None

    for name, detector_fn in DETECTOR_REGISTRY:
        description = detector_fn(text)
        if description is not None:
            triggered.append(name)
            if matched_pattern is None:
                matched_pattern = description

    if not triggered:
        return ScanResult()

    threat_score = min(len(triggered) * _DETECTOR_BASE_SCORE, 1.0)

    return ScanResult(
        threat_score=threat_score,
        is_threat=threat_score > 0.0,
        detectors_triggered=triggered,
        matched_pattern=matched_pattern,
        metadata={"scanned_format": format},
    )


def _detect_format(file: Any) -> str | None:  # noqa: ANN401
    """Detect file format from magic bytes."""
    data = _read_file_bytes(file)

    if len(data) < 4:
        return None

    # JPEG
    if data[:2] == b"\xff\xd8":
        return "image"
    # PNG
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image"
    # WebP
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image"
    # TIFF
    if data[:2] in (b"II", b"MM"):
        return "image"

    # PDF
    if data[:4] == b"%PDF":
        return "pdf"

    # Office Open XML (DOCX, XLSX, PPTX)
    if data[:2] == b"PK":
        return "docx"

    return None
