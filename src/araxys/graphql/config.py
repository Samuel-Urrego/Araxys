"""Configuration for GraphQL security middleware."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GraphQLSecurityConfig(BaseModel):
    """Configuration for GraphQL query depth, breadth, cost, and introspection.

    When ``None`` on :class:`AraxysConfig`, the entire GraphQL security
    module is disabled.
    """

    enabled: bool = Field(
        default=True,
        description="Enable GraphQL security middleware",
    )
    depth_limit: int = Field(
        default=10,
        ge=1,
        description="Maximum query depth (nested selections)",
    )
    breadth_limit: int = Field(
        default=50,
        ge=1,
        description="Maximum selection set breadth (fields per level)",
    )
    cost_limit: float = Field(
        default=1000.0,
        ge=1.0,
        description="Maximum operation cost",
    )
    introspection_enabled: bool = Field(
        default=True,
        description="Allow introspection queries (e.g. __schema, __type)",
    )
    graphql_path: str = Field(
        default="/graphql",
        description="Path prefix intercepted by the middleware",
    )
