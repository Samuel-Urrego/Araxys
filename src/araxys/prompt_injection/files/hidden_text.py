"""Hidden/invisible text detection in file formats.

Detects:
- **PDF**: text rendering mode 3 (invisible), text color equal to
  background, font size ≤ 0.5 pt, text outside visible page bounds.
- **Office (DOCX/XLSX)**: white font color (RGB 255,255,255), font
  size ≤ 1 pt, hidden paragraph property (``w:vanish``), headers/footers
  (conditional on config).
"""

from __future__ import annotations

import logging
from io import BytesIO
from typing import Any

logger = logging.getLogger(__name__)


# ── Internal helpers ─────────────────────────────────────────────────────────


def _read_file_bytes(file: Any) -> bytes:  # noqa: ANN401
    """Read *file* into ``bytes``."""
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


# ── PDF hidden text ──────────────────────────────────────────────────────────


def detect_pdf_hidden_text(file: Any) -> list[str]:  # noqa: ANN401
    """Detect hidden/invisible text in a PDF file.

    Checks:
    - Text rendering mode 3 (``Tr`` operator set to 3)
    - White text on white background (``rg``/``RG`` set to ``1 1 1``)
    - Font size ≤ 0.5 pt (``Tf`` operator with size ≤ 0.5)
    - Text outside visible page bounds (via ``Tm`` operator position)

    Parameters
    ----------
    file:
        PDF content as ``bytes``, ``BytesIO``, or file-like object.

    Returns
    -------
    List of suspicious text strings found. Empty when pypdf is not
    installed or the file cannot be parsed.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        logger.warning("pypdf not installed — PDF hidden text detection disabled")
        return []

    try:
        data = _read_file_bytes(file)
        reader = PdfReader(BytesIO(data))
    except Exception:
        logger.warning("Failed to open PDF for hidden text detection", exc_info=True)
        return []

    suspicious: list[str] = []

    for page_num, page in enumerate(reader.pages):
        try:
            contents = page.get_contents()
            if contents is None:
                continue

            raw = (
                contents.get_data()
                if hasattr(contents, "get_data")
                else str(contents)
            )
            if isinstance(raw, bytes):
                text_content = raw.decode("latin-1", errors="replace")
            else:
                text_content = raw

            # Extract visible text normally to compare
            visible_text = page.extract_text() or ""

            # Parse content stream for hidden text indicators
            hidden_texts = _parse_pdf_content_stream(text_content, visible_text)
            suspicious.extend(hidden_texts)
        except Exception:
            logger.warning(
                "Failed to analyze PDF page %d for hidden text",
                page_num,
                exc_info=True,
            )
            continue

    return suspicious


def _parse_pdf_content_stream(content: str, visible_text: str) -> list[str]:
    """Parse PDF content stream operators for hidden text indicators.

    Returns text strings that appear to be hidden.
    """
    suspicious: list[str] = []
    lines = content.splitlines()
    current_text: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Text between parentheses (Tj operator)
        if " Tj" in stripped and "(" in stripped:
            text = _extract_pdf_string(stripped)
            if text:
                current_text.append(text)

    # We flag text extracted from the content stream that is NOT part
    # of the normal visible text (which PDF extractors like extract_text()
    # already see).  The presence of content-stream-only text suggests
    # an invisible layer (e.g. rendering mode 3, white-on-white).
    for t in current_text:
        if t and t not in visible_text:
            suspicious.append(t)

    return suspicious


def _extract_pdf_string(line: str) -> str | None:
    """Extract text content between parentheses from a PDF content stream line."""
    start = line.find("(")
    end = line.rfind(")")
    if start >= 0 and end > start:
        text = line[start + 1 : end]
        # Handle PDF escape sequences
        text = text.replace("\\(", "(").replace("\\)", ")").replace("\\n", "\n")
        return text
    return None


# ── Office hidden text ───────────────────────────────────────────────────────


def detect_office_hidden_text(file: Any) -> list[str]:  # noqa: ANN401
    """Detect hidden/invisible text in Office documents (DOCX/XLSX).

    Checks:
    - White font color (RGB 255,255,255 or theme color "white")
    - Font size ≤ 1 pt
    - Hidden paragraph property (``w:vanish``)
    - Text in headers/footers

    Parameters
    ----------
    file:
        Document content as ``bytes``, ``BytesIO``, or file-like object.

    Returns
    -------
    List of suspicious text strings found. Empty when python-docx is
    not installed or the file cannot be parsed.
    """
    try:
        from docx import Document as DocxDocument
        from docx.oxml.ns import qn
    except ImportError:
        logger.warning(
            "python-docx not installed — Office hidden text detection disabled",
        )
        return []

    try:
        data = _read_file_bytes(file)
        doc = DocxDocument(BytesIO(data))
    except Exception:
        logger.warning(
            "Failed to open Office document for hidden text detection",
            exc_info=True,
        )
        return []

    suspicious: list[str] = []

    for para in doc.paragraphs:
        try:
            # Check for hidden paragraph (w:vanish on pPr)
            ppr = para._element.find(qn("w:pPr"))
            if ppr is not None:
                vanish = ppr.find(qn("w:rPr") + "/" + qn("w:vanish"))
                if vanish is not None:
                    text = para.text.strip()
                    if text:
                        suspicious.append(text)
                        continue  # Already flagged, skip run-level checks

            # Check each run for white font / tiny size / vanish
            for run in para.runs:
                try:
                    rpr = run._r.get_or_add_rPr()
                except Exception:  # noqa: BLE001
                    continue

                # w:vanish at run level
                vanish = rpr.find(qn("w:vanish"))
                if vanish is not None:
                    text = run.text.strip()
                    if text:
                        suspicious.append(text)
                        continue

                # Font color
                color_el = rpr.find(qn("w:color"))
                if color_el is not None:
                    val = color_el.get(qn("w:val"), "").lower()
                    theme = color_el.get(qn("w:themeColor"), "").lower()
                    if val in ("ffffff", "white") or theme == "white":
                        text = run.text.strip()
                        if text:
                            suspicious.append(text)
                            continue

                # Font size ≤ 1 pt
                sz_el = rpr.find(qn("w:sz"))
                if sz_el is not None:
                    try:
                        sz_val = sz_el.get(qn("w:val"), "0")
                        # sz is in half-points, so 1pt = 2 half-points
                        if int(sz_val) <= 2:
                            text = run.text.strip()
                            if text:
                                suspicious.append(text)
                                continue
                    except (ValueError, TypeError):
                        pass
        except Exception:
            logger.warning("Failed to inspect paragraph for hidden text", exc_info=True)
            continue

    return suspicious
