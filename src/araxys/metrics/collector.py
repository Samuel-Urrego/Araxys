"""MetricsRegistry — Prometheus counters and histograms with graceful no-op fallback.

All methods are safe to call even when ``prometheus-client`` is not installed
or when metrics are disabled — they simply become no-ops.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from araxys.core.types import SecurityEventType

if TYPE_CHECKING:
    from araxys.core.config import MetricsConfig
    from araxys.core.types import SecurityEvent

logger = logging.getLogger("araxys.metrics")


# ── Prometheus availability check ─────────────────────────────────────────


def _get_prometheus_client() -> Any:
    """Lazy import of prometheus_client.

    Returns the module if available, or ``None`` if not installed.
    """
    try:
        import prometheus_client

        return prometheus_client
    except ImportError:
        return None


_prometheus: Any = _get_prometheus_client()


def _prometheus_available() -> bool:
    """Check if prometheus_client is installed."""
    return _prometheus is not None


# ── Event Type Mapping ────────────────────────────────────────────────────


def _endpoint_label(event: SecurityEvent) -> dict[str, str]:
    return {"endpoint": event.metadata.get("endpoint", "unknown")}


def _path_label(event: SecurityEvent) -> dict[str, str]:
    return {"path": event.metadata.get("path", "unknown")}


def _attack_type_label(event: SecurityEvent) -> dict[str, str]:
    return {"attack_type": event.metadata.get("attack_type", "unknown")}


def _identifier_label(event: SecurityEvent) -> dict[str, str]:
    return {"identifier": event.metadata.get("identifier", "unknown")}


def _mode_label(event: SecurityEvent) -> dict[str, str]:
    return {"mode": event.metadata.get("mode", "unknown")}


def _event_type_label(event: SecurityEvent) -> dict[str, str]:
    return {"event_type": event.event_type.value}


def _no_labels(event: SecurityEvent) -> dict[str, str]:
    return {}


# Events that map directly to specific counters with labels
_EVENT_COUNTER_MAP: dict[SecurityEventType, tuple[str, Any]] = {
    SecurityEventType.RATE_LIMIT_EXCEEDED: (
        "rate_limit_exceeded",
        _endpoint_label,
    ),
    SecurityEventType.HONEYPOT_TRIGGERED: (
        "honeypot_triggered",
        _path_label,
    ),
    SecurityEventType.IP_BLOCKED: (
        "ip_blocked",
        _mode_label,
    ),
    SecurityEventType.CSRF_VALIDATION_FAILED: (
        "csrf_validation_failed",
        _no_labels,
    ),
    SecurityEventType.BRUTE_FORCE_LOCKOUT: (
        "brute_force_lockout",
        _identifier_label,
    ),
    SecurityEventType.SESSION_REVOKED: (
        "session_revoked",
        _no_labels,
    ),
    SecurityEventType.TOKEN_ROTATED: (
        "jwt_token_rotated",
        _no_labels,
    ),
    SecurityEventType.SANITIZE_BLOCKED: (
        "sanitize_blocked",
        _attack_type_label,
    ),
}

# Events that fall through to the catchall security_events counter
_CATCHALL_EVENTS: set[SecurityEventType] = {
    SecurityEventType.IP_ALLOWED,
    SecurityEventType.PASSWORD_VALIDATION_FAILED,
    SecurityEventType.SESSION_CREATED,
    SecurityEventType.AUDIT_TAMPER_DETECTED,
}


# ── MetricsRegistry ────────────────────────────────────────────────────────


class MetricsRegistry:
    """Central registry for Prometheus metrics.

    Accepts a ``MetricsConfig`` — if metrics are disabled or
    ``prometheus-client`` is not installed, all methods are no-ops.

    Parameters
    ----------
    config:
        Metrics configuration (enabled, path).
    """

    def __init__(self, config: MetricsConfig) -> None:
        self._enabled = config.enabled and _prometheus_available()
        self._config = config
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._registry: Any = None

        if self._enabled:
            self._registry = _prometheus.CollectorRegistry()
            self._init_counters()
            self._init_histograms()

    def _init_counters(self) -> None:
        """Create all Prometheus Counter metrics."""
        if _prometheus is None:
            return

        self._counters["rate_limit_exceeded"] = _prometheus.Counter(
            "araxys_rate_limit_exceeded_total",
            "Total number of rate limit exceeded events",
            ["endpoint"],
            registry=self._registry,
        )
        self._counters["honeypot_triggered"] = _prometheus.Counter(
            "araxys_honeypot_triggered_total",
            "Total number of honeypot triggered events",
            ["path"],
            registry=self._registry,
        )
        self._counters["sanitize_blocked"] = _prometheus.Counter(
            "araxys_sanitize_blocked_total",
            "Total number of sanitize blocked events",
            ["attack_type"],
            registry=self._registry,
        )
        self._counters["jwt_token_rotated"] = _prometheus.Counter(
            "araxys_jwt_token_rotated_total",
            "Total number of JWT token rotations",
            registry=self._registry,
        )
        self._counters["csrf_validation_failed"] = _prometheus.Counter(
            "araxys_csrf_validation_failed_total",
            "Total number of CSRF validation failures",
            registry=self._registry,
        )
        self._counters["brute_force_lockout"] = _prometheus.Counter(
            "araxys_brute_force_lockout_total",
            "Total number of brute force lockouts",
            ["identifier"],
            registry=self._registry,
        )
        self._counters["ip_blocked"] = _prometheus.Counter(
            "araxys_ip_blocked_total",
            "Total number of IP blocks",
            ["mode"],
            registry=self._registry,
        )
        self._counters["session_revoked"] = _prometheus.Counter(
            "araxys_session_revoked_total",
            "Total number of session revocations",
            registry=self._registry,
        )
        self._counters["security_events"] = _prometheus.Counter(
            "araxys_security_events_total",
            "Total number of security events by type",
            ["event_type"],
            registry=self._registry,
        )

    def _init_histograms(self) -> None:
        """Create all Prometheus Histogram metrics."""
        if _prometheus is None:
            return

        self._histograms["middleware_duration"] = _prometheus.Histogram(
            "araxys_middleware_duration_seconds",
            "Duration of middleware processing in seconds",
            ["middleware_name"],
            registry=self._registry,
        )

    # ── Counter Record Methods ───────────────────────────────────────────

    def record_rate_limit_exceeded(self, endpoint: str) -> None:
        """Increment the rate limit exceeded counter."""
        if not self._enabled or "rate_limit_exceeded" not in self._counters:
            return
        self._counters["rate_limit_exceeded"].labels(endpoint=endpoint).inc()

    def record_honeypot_triggered(self, path: str) -> None:
        """Increment the honeypot triggered counter."""
        if not self._enabled or "honeypot_triggered" not in self._counters:
            return
        self._counters["honeypot_triggered"].labels(path=path).inc()

    def record_sanitize_blocked(self, attack_type: str) -> None:
        """Increment the sanitize blocked counter."""
        if not self._enabled or "sanitize_blocked" not in self._counters:
            return
        self._counters["sanitize_blocked"].labels(attack_type=attack_type).inc()

    def record_jwt_token_rotated(self) -> None:
        """Increment the JWT token rotated counter."""
        if not self._enabled or "jwt_token_rotated" not in self._counters:
            return
        self._counters["jwt_token_rotated"].inc()

    def record_csrf_validation_failed(self) -> None:
        """Increment the CSRF validation failed counter."""
        if not self._enabled or "csrf_validation_failed" not in self._counters:
            return
        self._counters["csrf_validation_failed"].inc()

    def record_brute_force_lockout(self, identifier: str) -> None:
        """Increment the brute force lockout counter."""
        if not self._enabled or "brute_force_lockout" not in self._counters:
            return
        self._counters["brute_force_lockout"].labels(identifier=identifier).inc()

    def record_ip_blocked(self, mode: str) -> None:
        """Increment the IP blocked counter."""
        if not self._enabled or "ip_blocked" not in self._counters:
            return
        self._counters["ip_blocked"].labels(mode=mode).inc()

    def record_session_revoked(self) -> None:
        """Increment the session revoked counter."""
        if not self._enabled or "session_revoked" not in self._counters:
            return
        self._counters["session_revoked"].inc()

    def record_security_event(self, event_type: str) -> None:
        """Increment the catchall security events counter."""
        if not self._enabled or "security_events" not in self._counters:
            return
        self._counters["security_events"].labels(event_type=event_type).inc()

    # ── Histogram Record Methods ─────────────────────────────────────────

    def record_middleware_duration(
        self, middleware_name: str, duration_seconds: float
    ) -> None:
        """Record middleware processing duration."""
        if not self._enabled or "middleware_duration" not in self._histograms:
            return
        self._histograms["middleware_duration"].labels(
            middleware_name=middleware_name
        ).observe(duration_seconds)

    # ── Event Bus Subscription ───────────────────────────────────────────

    def subscribe_to_event_bus(self, event_bus: Any) -> None:
        """Subscribe to a ``SecurityEventBus`` to auto-increment counters.

        Parameters
        ----------
        event_bus:
            A ``SecurityEventBus`` instance with a ``subscribe`` method.
        """
        event_bus.subscribe(self._on_event)

    async def _on_event(self, event: SecurityEvent) -> None:
        """Handle a security event from the event bus.

        Maps event types to the appropriate counter and increments it.
        """
        if not self._enabled:
            return

        event_type = event.event_type

        # Direct counter mapping
        if event_type in _EVENT_COUNTER_MAP:
            counter_key, label_fn = _EVENT_COUNTER_MAP[event_type]
            labels = label_fn(event)
            if counter_key in self._counters:
                if labels:
                    self._counters[counter_key].labels(**labels).inc()
                else:
                    self._counters[counter_key].inc()
            return

        # Catchall: any other known event type → security_events counter
        if event_type in _CATCHALL_EVENTS:
            self.record_security_event(event_type.value)
            return
