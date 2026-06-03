"""OpenAPI schema reader for WAF rule generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SchemaReader:
    """Reads an OpenAPI schema from a FastAPI app or JSON file.

    Exactly one of *app* or *file_path* must be provided.

    Parameters
    ----------
    app:
        A FastAPI application instance (must have ``app.openapi()``).
    file_path:
        Absolute or relative path to an ``openapi.json`` file.
    """

    def __init__(
        self,
        *,
        app: Any | None = None,
        file_path: str | None = None,
    ) -> None:
        if app is not None and file_path is not None:
            raise ValueError(
                "Provide exactly one of 'app' or 'file_path', not both."
            )
        if app is None and file_path is None:
            raise ValueError(
                "Either 'app' or 'file_path' must be provided."
            )

        if app is not None:
            self._schema: dict[str, Any] = app.openapi()
        else:
            self._load_from_file(file_path)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # File loading
    # ------------------------------------------------------------------

    def _load_from_file(self, file_path: str) -> None:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"OpenAPI schema file not found: {file_path}"
            )
        raw = path.read_text(encoding="utf-8")
        try:
            self._schema = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"File '{file_path}' does not contain valid JSON: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def schema(self) -> dict[str, Any]:
        """The full OpenAPI schema dict."""
        return self._schema

    @property
    def paths(self) -> dict[str, dict[str, Any]]:
        """The ``paths`` section of the schema, keyed by URL path.

        Returns an empty dict when the schema has no ``paths`` key.
        """
        return self._schema.get("paths", {}) or {}
