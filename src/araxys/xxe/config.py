"""XXEConfig Pydantic model for XML external entity attack protection."""

from __future__ import annotations

from pydantic import BaseModel, Field


class XXEConfig(BaseModel):
    """Configuration for XXE (XML External Entity) attack protection.

    All three ``forbid_*`` toggles default to ``True``, providing maximal
    protection out of the box.  Set individual toggles to ``False`` to
    selectively allow DTD declarations, entity references, or external
    entity access.

    When ``None`` on :class:`araxys.core.config.AraxysConfig`, the entire
    XXE module is disabled.
    """

    forbid_dtd: bool = Field(
        default=True,
        description="Reject DOCTYPE declarations entirely",
    )
    forbid_entities: bool = Field(
        default=True,
        description="Reject internal/external entity references",
    )
    forbid_external: bool = Field(
        default=True,
        description=(
            "Reject external entity SYSTEM/PUBLIC access "
            "(file://, http://, etc.)"
        ),
    )
    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/healthz",
        ],
        description="Paths excluded from XXE middleware scanning",
    )
    exclude_content_types: list[str] = Field(
        default_factory=list,
        description="Content types excluded from XXE middleware scanning",
    )
