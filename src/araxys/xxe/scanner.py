"""Config-driven XXE scanner with regex pre-scan and stdlib fallback.

Detection strategy
------------------
1. **Regex pre-scan**: Scans raw XML text for ``<!DOCTYPE``, ``<!ENTITY``,
   ``SYSTEM``, and ``PUBLIC`` patterns before any XML parser touches the
   input.  This catches the dangerous classes without needing defusedxml.

2. **defusedxml** (when available): If the optional ``defusedxml`` package
   is installed, it is used as the primary parser.  ``DefusedXmlException``
   is caught and reported as a threat.

3. **stdlib fallback** (no defusedxml): ``xml.etree.ElementTree`` is used
   to parse.  Because the regex pre-scan has already blocked declarations
   and entities, this path only processes pre-validated XML.  ElementTree
   without pre-scanning is NOT safe — the pre-scan is the defence.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from araxys.core.types import ScanResult

if TYPE_CHECKING:
    from araxys.xxe.config import XXEConfig

# ── Regex patterns for pre-scanning ──────────────────────────────────────────

_DTD_PATTERN = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_ENTITY_PATTERN = re.compile(r"<!ENTITY", re.IGNORECASE)
_SYSTEM_PATTERN = re.compile(r'SYSTEM\s+["\']', re.IGNORECASE)
_PUBLIC_PATTERN = re.compile(r'PUBLIC\s+["\']', re.IGNORECASE)

# ── Scanner ──────────────────────────────────────────────────────────────────


class XXEScanner:
    """Config-driven scanner for XML external entity attack detection.

    Parameters
    ----------
    config:
        XXE configuration controlling which protections are active.
    """

    def __init__(self, config: XXEConfig) -> None:
        self._config = config

    # ── Public API ─────────────────────────────────────────────────────────

    def scan(self, data: str | bytes) -> ScanResult:
        """Scan *data* for XXE attack patterns and return a ScanResult.

        The scan proceeds in three stages:

        1. **Regex pre-scan** — checks for ``<!DOCTYPE``, ``<!ENTITY``,
           ``SYSTEM``, and ``PUBLIC`` patterns.  Threats found here are
           returned immediately if the corresponding config toggle is set.

        2. **defusedxml** — if the optional ``defusedxml`` package is
           installed, ``fromstring()`` is called.  Any
           ``DefusedXmlException`` is caught and reported.

        3. **stdlib fallback** — ``xml.etree.ElementTree.fromstring()``
           is called on pre-validated text.  The regex pre-scan already
           ensures no dangerous declarations reach the parser.

        Parameters
        ----------
        data:
            The XML string or bytes to scan.

        Returns
        -------
        ScanResult with threat information.  ``is_threat`` is ``True``
        when an XXE attack pattern is detected.
        """
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")

        # ── Step 1: Regex pre-scan ───────────────────────────────────────
        threats: list[dict[str, Any]] = []

        if self._config.forbid_dtd and _DTD_PATTERN.search(data):
            threats.append({
                "detection_type": "dtd",
                "detail": "DOCTYPE declaration detected",
            })

        if self._config.forbid_entities and _ENTITY_PATTERN.search(data):
            threats.append({
                "detection_type": "entity",
                "detail": "ENTITY declaration detected",
            })

        if self._config.forbid_external:
            if _SYSTEM_PATTERN.search(data):
                threats.append({
                    "detection_type": "external_entity",
                    "detail": "SYSTEM external entity detected",
                })
            if _PUBLIC_PATTERN.search(data):
                threats.append({
                    "detection_type": "external_entity",
                    "detail": "PUBLIC external entity detected",
                })

        if threats:
            return self._build_threat_result(threats)

        # ── Step 2: Try defusedxml parser (when available) ──────────────
        try:
            from defusedxml.ElementTree import fromstring as _safe_fromstring  # type: ignore[import-untyped]
        except ImportError:
            _safe_fromstring = None

        if _safe_fromstring is not None:
            try:
                _safe_fromstring(data)
                return ScanResult()
            except Exception as exc:
                exc_name = type(exc).__name__
                threats.append({
                    "detection_type": "parser_blocked",
                    "detail": f"{exc_name}: {exc}",
                })
                return self._build_threat_result(threats)

        # ── Step 3: Stdlib fallback ─────────────────────────────────────
        # The regex pre-scan already caught dangerous patterns above.
        # This path processes only pre-validated XML.

        try:
            import xml.etree.ElementTree as ET  # noqa: TC002

            ET.fromstring(data)
        except Exception:
            # Invalid XML is not a threat — just unparseable
            pass

        return ScanResult()

    # ── Internals ────────────────────────────────────────────────────────

    @staticmethod
    def _build_threat_result(
        threats: list[dict[str, Any]],
    ) -> ScanResult:
        """Build a threat ScanResult from a list of detected threats."""
        triggered = list(dict.fromkeys(t["detection_type"] for t in threats))
        detail = "; ".join(t["detail"] for t in threats)
        return ScanResult(
            is_threat=True,
            threat_score=1.0,
            detectors_triggered=triggered,
            matched_pattern=detail,
            metadata={"xxe_threats": threats},
        )
