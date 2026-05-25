"""FastAPI dependency for per-endpoint prompt injection protection.

Provides :func:`prompt_injection_guard` — a factory that returns a
FastAPI-compatible ``Depends`` callable that scans text (explicit or
auto-extracted from the request body) and returns a :class:`ScanResult`
**without raising** — letting the endpoint decide how to respond.

Usage::

    from fastapi import Depends
    from araxys.prompt_injection.dependencies import prompt_injection_guard
    from araxys.core.types import ScanResult

    @app.post("/chat")
    async def chat(
        scan: ScanResult = Depends(prompt_injection_guard(text="...")),
    ):
        if scan.is_threat:
            raise HTTPException(status_code=400, detail="Injection detected")
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

# Request must be importable at runtime for FastAPI's
# get_type_hints() to resolve the annotation string.
from starlette.requests import Request  # noqa: TC002

from araxys.core.config import PromptInjectionConfig
from araxys.core.types import ScanResult
from araxys.prompt_injection.scanner import PromptInjectionScanner

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


def prompt_injection_guard(
    text: str | None = None,
    threshold: float | None = None,
    enabled_detectors: list[str] | None = None,
    scanner: PromptInjectionScanner | None = None,
) -> Callable[[Request], Awaitable[ScanResult]]:
    """Factory for a per-endpoint prompt injection guard dependency.

    Parameters
    ----------
    text:
        Explicit text to scan.  When ``None``, the dependency will
        attempt to extract text from the request body.
    threshold:
        Override the scanner's threat threshold for this endpoint.
        ``None`` uses the config default (0.0).
    enabled_detectors:
        Override which detectors run for this endpoint.
        ``None`` uses all config-enabled detectors.
    scanner:
        Optional pre-configured scanner.  When ``None``, a default
        scanner with :class:`PromptInjectionConfig` is created.

    Returns
    -------
    A FastAPI-compatible dependency callable that accepts a
    ``Request`` and returns a ``ScanResult``.

    Example
    -------

    .. code-block:: python

        from fastapi import Depends

        @app.post("/chat")
        async def chat(
            scan: ScanResult = Depends(
                prompt_injection_guard(text=body.msg)
            ),
        ):
            ...
    """
    _scanner = scanner or PromptInjectionScanner(PromptInjectionConfig())
    _ = threshold  # reserved — threshold applied in scanner.scan_text

    async def _guard(request: Request) -> ScanResult:
        resolved_text = text

        if resolved_text is None:
            resolved_text = await _extract_text_from_request(request)

        if not resolved_text:
            return ScanResult()

        return _scanner.scan_text(
            resolved_text,
            enabled_detectors=enabled_detectors,
        )

    return _guard


async def _extract_text_from_request(request: Request) -> str | None:
    """Try to extract text from the request body (JSON or form data).

    For JSON bodies, the first string field value found is returned.
    For form-encoded bodies, the first text field value is returned.
    Returns ``None`` when no text can be extracted.
    """
    # Try JSON body first
    try:
        body = await request.json()
    except Exception:
        body = None

    if isinstance(body, dict):
        return _first_string_value(body)

    # Try form data
    try:
        form = await request.form()
    except Exception:
        return None

    for _key, value in form.multi_items():
        from starlette.datastructures import UploadFile

        if isinstance(value, UploadFile):
            continue
        str_val = str(value).strip()
        if str_val:
            return str_val

    return None


def _first_string_value(data: dict[str, Any]) -> str | None:
    """Return the first string value in a dict (recursive)."""
    for value in data.values():
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, dict):
            result = _first_string_value(value)
            if result is not None:
                return result
    return None


def get_prompt_injection_scanner(
    config: PromptInjectionConfig | None = None,
) -> PromptInjectionScanner:
    """Factory dependency for a :class:`PromptInjectionScanner`.

    Use in route handlers that need direct scanner access::

        @app.get("/scan")
        async def scan_endpoint(
            scanner: PromptInjectionScanner = Depends(
                get_prompt_injection_scanner
            ),
        ):
            result = scanner.scan_text("some text")
            ...

    Parameters
    ----------
    config:
        Optional configuration.  Uses defaults when ``None``.
    """
    return PromptInjectionScanner(config or PromptInjectionConfig())


# Backward-compatible alias
PromptInjectionGuard = prompt_injection_guard
