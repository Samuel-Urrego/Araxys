"""FastAPI dependencies for per-endpoint XXE protection.

Provides :func:`xxe_guard` — a factory that returns a callable for
scanning XML strings or bytes and raising :class:`XXEError` on
detection.

Also provides :func:`get_xxe_scanner` for direct scanner access.

Usage::

    from fastapi import Body, Depends
    from araxys.xxe.dependencies import xxe_guard

    @app.post("/xml")
    async def endpoint(
        body: str = Body(...),
        _: None = Depends(xxe_guard()),
    ):
        # If we get here, the XML is clean
        ...

Or used directly::

    guard = xxe_guard()
    try:
        result = guard(xml_string)
    except XXEError as e:
        # Handle XXE detection
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from araxys.xxe.config import XXEConfig
from araxys.xxe.scanner import XXEScanner

if TYPE_CHECKING:
    from collections.abc import Callable

    from araxys.core.types import ScanResult



def xxe_guard(
    config_override: XXEConfig | None = None,
) -> Callable[[str | bytes], ScanResult]:
    """Factory for a per-endpoint XXE protection guard.

    Parameters
    ----------
    config_override:
        Optional override configuration.  When ``None``, the default
        :class:`XXEConfig` is used (all protections enabled).

    Returns
    -------
    A callable that accepts XML ``str`` or ``bytes``, scans it for
    XXE attacks, and returns a ``ScanResult`` when the input is clean.
    Raises :class:`XXEError` when a threat is detected.

    Example
    -------

    .. code-block:: python

        from fastapi import Body, Depends

        @app.post("/xml")
        async def endpoint(
            body: str = Body(...),
            _: None = Depends(xxe_guard()),
        ):
            ...
    """
    scanner = XXEScanner(config_override or XXEConfig())

    def _guard(data: str | bytes) -> ScanResult:
        """Scan *data* for XXE attacks.

        Parameters
        ----------
        data:
            The XML string or bytes to scan.

        Returns
        -------
        ScanResult when the input is clean.

        Raises
        ------
        XXEError
            When an XXE attack is detected.
        """
        from araxys.xxe.exceptions import XXEError

        result = scanner.scan(data)
        if result.is_threat:
            threats = result.metadata.get("xxe_threats", [{}])
            threat = threats[0] if threats else {}
            raise XXEError(
                detection_type=threat.get("detection_type", "unknown"),
                detail=threat.get("detail", result.matched_pattern or "XXE detected"),
            )
        return result

    return _guard


def get_xxe_scanner(
    config: XXEConfig | None = None,
) -> XXEScanner:
    """Factory dependency for a :class:`XXEScanner`.

    Use in route handlers that need direct scanner access::

        @app.post("/scan")
        async def scan_endpoint(
            body: str = Body(...),
            scanner: XXEScanner = Depends(get_xxe_scanner()),
        ):
            result = scanner.scan(body)
            ...

    Parameters
    ----------
    config:
        Optional configuration.  Uses defaults when ``None``.
    """
    return XXEScanner(config or XXEConfig())
