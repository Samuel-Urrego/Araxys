"""WebSocket security configuration — placeholder stub."""

from __future__ import annotations

from pydantic import BaseModel, Field


class WebSocketConfig(BaseModel):
    """Configuration for WebSocket security."""

    enabled: bool = Field(
        default=True,
        description="Enable WebSocket security features",
    )
