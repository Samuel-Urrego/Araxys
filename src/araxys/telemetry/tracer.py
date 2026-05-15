"""OpenTelemetry tracer wrapper with graceful degradation.

Provides ``AraxysTracer`` (config-aware OTEL wrapper) and the
standalone ``araxys_span`` async context manager function.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from araxys.core.config import TelemetryConfig

logger = logging.getLogger("araxys.telemetry")

# Try to import opentelemetry — it's an optional dependency.
# The module-level reference allows tests to patch `araxys.telemetry.tracer.trace`.
def _get_otel_trace() -> Any:
    """Lazy import of opentelemetry.trace.

    Returns the module if available, or None if not installed.
    """
    try:
        import opentelemetry.trace  # type: ignore[import-not-found]

        return opentelemetry.trace
    except ImportError:
        return None


_otel_trace: Any = _get_otel_trace()


def _otel_available() -> bool:
    """Check if the OpenTelemetry SDK is installed."""
    return _otel_trace is not None


class _NoOpSpan:
    """A no-op span that does nothing when OTEL is unavailable or disabled."""

    async def __aenter__(self) -> _NoOpSpan:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    def set_attribute(self, key: str, value: object) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass


class AraxysTracer:
    """Config-aware OpenTelemetry tracer wrapper.

    When ``enabled=False`` or when the OTEL SDK is not installed, all
    methods become no-ops.
    """

    def __init__(self, config: TelemetryConfig) -> None:
        self._enabled = config.enabled and _otel_available()
        self._service_name = config.service_name
        self._tracer: Any = None
        if self._enabled:
            self._init_tracer()

    def _init_tracer(self) -> None:
        """Initialize the OTEL tracer (only called when enabled + available)."""
        if _otel_trace is None:
            self._enabled = False
            return
        try:
            self._tracer = _otel_trace.get_tracer(self._service_name)
        except Exception:
            logger.exception("Failed to initialize OpenTelemetry tracer")
            self._enabled = False

    def get_tracer(self) -> Any:
        """Return the OTEL tracer instance, or None if unavailable."""
        return self._tracer

    @asynccontextmanager
    async def span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> AsyncIterator[Any]:
        """Async context manager that creates an OTEL span.

        Usage::

            async with tracer.span("rate_limit.check", {"ip": ip}) as span:
                ...
        """
        if not self._enabled or self._tracer is None:
            yield _NoOpSpan()
            return

        with self._tracer.start_as_current_span(
            name, attributes=attributes or {}
        ) as span:
            yield span

    async def record_event(
        self, name: str, attributes: dict[str, Any] | None = None
    ) -> None:
        """Add an event to the current span (no-op if no active span)."""
        if not self._enabled or self._tracer is None or _otel_trace is None:
            return
        try:
            span = _otel_trace.get_current_span()
            if span is not None:
                span.add_event(name, attributes or {})
        except Exception:
            pass


@asynccontextmanager
async def araxys_span(
    name: str,
    tracer: AraxysTracer | None = None,
    **attributes: Any,
) -> AsyncIterator[Any]:
    """Standalone async context manager for OTEL spans.

    Usage::

        async with araxys_span("rate_limit.check", ip=client_ip) as span:
            ...

    If ``tracer`` is ``None`` or disabled, yields a no-op span.
    """
    if tracer is None:
        yield _NoOpSpan()
        return

    async with tracer.span(name, attributes=attributes or None) as span:
        yield span
