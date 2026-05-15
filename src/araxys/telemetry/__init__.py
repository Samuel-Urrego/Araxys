"""OpenTelemetry integration — distributed tracing for Araxys.

Provides the ``AraxysTracer`` class and the standalone ``araxys_span``
async context manager. Graceful no-op fallback when OpenTelemetry SDK
is not installed.
"""

from araxys.telemetry.middleware import TelemetryMiddleware
from araxys.telemetry.tracer import AraxysTracer, araxys_span

__all__ = [
    "AraxysTracer",
    "TelemetryMiddleware",
    "araxys_span",
]
