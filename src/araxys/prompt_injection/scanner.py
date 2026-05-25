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
        config: FileScanConfig,  # noqa: ARG002
    ) -> ScanResult:
        """Scan a file upload for prompt injection (stub for PR 3).

        .. note::

            File scanning (metadata extraction, hidden text detection) is
            implemented in PR 3.  This stub returns a non-threat result.

        Parameters
        ----------
        file:
            The uploaded file to scan.
        config:
            File scanning configuration.

        Returns
        -------
        An empty (non-threat) ScanResult.
        """
        # Stub: real implementation added in PR 3
        _ = file  # consume parameter to satisfy linters
        return ScanResult()

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
