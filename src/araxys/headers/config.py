"""Security header audit configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuditConfig(BaseModel):
    """Configuration for security headers audit middleware.

    When ``None`` on :class:`AraxysConfig`, the audit feature is disabled.
    """

    enabled: bool = Field(
        default=False,
        description="Enable security header audit on responses",
    )
    sample_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Fraction of responses to audit (0-1)",
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["/docs", "/redoc", "/openapi.json", "/healthz"],
        description="Paths excluded from header auditing",
    )
    emit_to_event_bus: bool = Field(
        default=True,
        description="Emit audit events to the security event bus",
    )
