"""XXE-specific audit and security event type definitions."""

from __future__ import annotations

from araxys.core.types import AuditEventType, SecurityEventType

# Audit events — used by the audit system for logging XXE detections.
XXE_AUDIT_EVENTS: frozenset[AuditEventType] = frozenset({
    AuditEventType.XXE_DETECTED,
})

# Security events — used by the event bus for webhook delivery and metrics.
XXE_SECURITY_EVENTS: frozenset[SecurityEventType] = frozenset({
    SecurityEventType.XXE_DETECTED,
})
