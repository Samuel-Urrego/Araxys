"""Prometheus Metrics — counters, histograms, and /metrics endpoint.

Gracefully degrades when ``prometheus-client`` is not installed
(no import errors, all methods become no-ops).
"""

from araxys.metrics.collector import MetricsRegistry
from araxys.metrics.config import MetricsConfig
from araxys.metrics.endpoint import metrics_endpoint, mount_metrics

__all__ = [
    "MetricsConfig",
    "MetricsRegistry",
    "metrics_endpoint",
    "mount_metrics",
]
