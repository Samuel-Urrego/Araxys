"""Config-driven scanner for prompt injection attacks.

Aggregates results from multiple detectors and produces a single
:class:`ScanResult` with the highest threat score, a list of all
triggered detectors, and a human-readable matched pattern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from araxys.core.types import ScanResult
from araxys.prompt_injection.detectors import DETECTOR_REGISTRY

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.datastructures import UploadFile

    from araxys.core.config import FileScanConfig, PromptInjectionConfig

# Each detector match contributes this base score.
_DETECTOR_BASE_SCORE: float = 0.3


class PromptInjectionScanner:
    """Config-driven scanner that applies enabled detectors to text input.

    Parameters
    ----------
    config:
        Prompt injection configuration that controls which detectors
        are enabled and the threat score threshold.
    """

    def __init__(self, config: PromptInjectionConfig) -> None:
        self._config = config

    # ── Public API ─────────────────────────────────────────────────────────

    def scan_text(
        self,
        text: str,
        enabled_detectors: list[str] | None = None,
    ) -> ScanResult:
        """Scan *text* with enabled detectors and return an aggregated result.

        Parameters
        ----------
        text:
            The text string to scan.
        enabled_detectors:
            Optional list of detector names to run.  When ``None``, only
            detectors enabled in ``config`` are used.  When provided,
            only the listed detectors run (config toggles are ignored).

        Returns
        -------
        ScanResult with aggregated threat information.
        """
        if not text:
            return ScanResult()

        detectors_to_run = self._resolve_detectors(enabled_detectors)

        triggered: list[str] = []
        matched_pattern: str | None = None
        highest_score: float = 0.0

        for name, detector_fn in detectors_to_run:
            description = detector_fn(text)
            if description is not None:
                triggered.append(name)
                if matched_pattern is None:
                    matched_pattern = description

        if triggered:
            highest_score = min(
                len(triggered) * _DETECTOR_BASE_SCORE,
                1.0,
            )

        is_threat = highest_score > self._config.threshold

        return ScanResult(
            threat_score=highest_score,
            is_threat=is_threat,
            detectors_triggered=triggered,
            matched_pattern=matched_pattern,
        )

    async def scan_file(
        self,
        file: UploadFile,
        config: FileScanConfig,
    ) -> ScanResult:
        """Scan a file upload for prompt injection.

        Performs up to three phases:

        1. **Format & size guard** — checks the file extension against
           enabled formats and the file size against the configured max.
        2. **Metadata scan** — extracts text from file metadata (EXIF,
           PDF Info, Office properties) and runs text detectors.
        3. **Hidden text scan** — detects invisible text in PDF (mode 3,
           white-on-white) and Office (hidden paragraphs, white font).

        Results from each phase are aggregated in a single
        :class:`~araxys.core.types.ScanResult`.

        Parameters
        ----------
        file:
            The uploaded file to scan.
        config:
            File scanning configuration.

        Returns
        -------
        ScanResult with aggregated threat information.
        """
        # Skip if no filename
        if not file.filename:
            return ScanResult()

        # Phase 1 — format guard
        ext = _get_extension(file.filename)
        format_name = _extension_to_format(ext)

        if format_name is None:
            return ScanResult()

        if config.enabled_formats and ext not in config.enabled_formats:
            return ScanResult()

        # Check file size (read first bytes)
        try:
            data = await file.read()
            # Reset so downstream handlers can read
            if hasattr(file, "file") and file.file and hasattr(file.file, "seek"):
                file.file.seek(0)
        except Exception:
            return ScanResult()

        if len(data) > config.max_file_size:
            return ScanResult()

        triggered: list[str] = []
        matched_pattern: str | None = None

        # Phase 2 — metadata scan
        if config.scan_metadata:
            try:
                from araxys.prompt_injection.files.metadata import (
                    scan_file_metadata as _scan_meta,
                )

                meta_result = _scan_meta(data, config, format=format_name)
                if meta_result.is_threat:
                    triggered.extend(meta_result.detectors_triggered)
                    if matched_pattern is None:
                        matched_pattern = meta_result.matched_pattern
            except Exception:
                pass

        # Phase 3 — hidden text scan
        if config.scan_hidden_text:
            try:
                from araxys.prompt_injection.files.hidden_text import (  # noqa: I001
                    detect_office_hidden_text,
                    detect_pdf_hidden_text,
                )

                if format_name == "pdf":
                    hidden = detect_pdf_hidden_text(data)
                elif format_name in ("docx", "xlsx", "pptx"):
                    hidden = detect_office_hidden_text(data)
                else:
                    hidden = []

                for text in hidden:
                    result = self.scan_text(text)
                    if result.is_threat:
                        triggered.extend(result.detectors_triggered)
                        if matched_pattern is None:
                            matched_pattern = result.matched_pattern
            except Exception:
                pass

        # Deduplicate triggered detectors
        triggered = list(dict.fromkeys(triggered))

        if not triggered:
            return ScanResult()

        highest_score = min(len(triggered) * _DETECTOR_BASE_SCORE, 1.0)
        is_threat = highest_score > self._config.threshold

        return ScanResult(
            threat_score=highest_score,
            is_threat=is_threat,
            detectors_triggered=triggered,
            matched_pattern=matched_pattern,
            metadata={"scanned_format": format_name, "file_size": len(data)},
        )

    # ── Internals ──────────────────────────────────────────────────────────

    def _resolve_detectors(
        self,
        enabled_detectors: list[str] | None,
    ) -> list[tuple[str, Callable[[str], str | None]]]:
        """Resolve the list of detector (name, fn) pairs to run.

        When *enabled_detectors* is ``None``, the config's per-detector
        toggles are consulted.  When provided, only the named detectors
        are returned (config toggles are ignored).
        """
        if enabled_detectors is not None:
            # Explicit whitelist — config toggles ignored
            name_set = frozenset(enabled_detectors)
            return [
                (name, fn)
                for name, fn in DETECTOR_REGISTRY
                if name in name_set
            ]

        # Use config toggles
        config_map: dict[str, bool] = {
            "direct_injection": self._config.detect_direct_injection,
            "jailbreak": self._config.detect_jailbreak,
            "delimiter_escape": self._config.detect_delimiter_escape,
            "zero_width_chars": self._config.detect_zero_width,
            "homoglyphs": self._config.detect_homoglyph,
        }
        return [
            (name, fn)
            for name, fn in DETECTOR_REGISTRY
            if config_map.get(name, True)
        ]


# ── File format helpers ──────────────────────────────────────────────────────


def _get_extension(filename: str) -> str:
    """Extract the lowercase file extension (without dot) from a filename."""
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _extension_to_format(ext: str) -> str | None:
    """Map a file extension to a format key used by the file scanner.

    Returns ``None`` for unsupported extensions.
    """
    mapping: dict[str, str] = {
        "jpg": "image",
        "jpeg": "image",
        "png": "image",
        "tiff": "image",
        "tif": "image",
        "webp": "image",
        "pdf": "pdf",
        "docx": "docx",
        "docm": "docx",
        "xlsx": "xlsx",
        "xlsm": "xlsx",
        "pptx": "pptx",
        "ppsm": "pptx",
    }
    return mapping.get(ext)
