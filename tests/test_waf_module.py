"""Tests for the waf package — module exports and SchemaReader (Phase 1)."""  # noqa: E501

from __future__ import annotations

import json
import tempfile
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Task 1.5 — Module exports
# ---------------------------------------------------------------------------


class TestWafModuleExports:
    """All Phase 1 exports must be importable from araxys.waf (task 1.5)."""

    def test_schema_reader_importable(self) -> None:
        from araxys.waf import SchemaReader

        assert SchemaReader is not None

    def test_waf_rule_config_re_exported(self) -> None:
        from araxys.waf import WafRuleConfig

        assert WafRuleConfig is not None

    def test_waf_escalation_config_re_exported(self) -> None:
        from araxys.waf import WafEscalationConfig

        assert WafEscalationConfig is not None


# ---------------------------------------------------------------------------
# Task 1.6 — SchemaReader
# ---------------------------------------------------------------------------


MINIMAL_OPENAPI = {
    "openapi": "3.0.2",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "requestBody": {
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
    },
}

MULTI_PATH_OPENAPI = {
    "openapi": "3.0.2",
    "info": {"title": "Multi API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/health": {
            "get": {
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/items": {
            "post": {
                "requestBody": {
                    "content": {"application/json": {}},
                },
                "responses": {"201": {"description": "Created"}},
            },
            "put": {
                "requestBody": {
                    "content": {"application/json": {}},
                },
                "responses": {"200": {"description": "OK"}},
            },
        },
    },
}


class _DummyApp:
    """Simulates a FastAPI app with controlled openapi() output."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    def openapi(self) -> dict[str, Any]:
        return self._schema


class TestSchemaReaderFromApp:
    """SchemaReader ingesting from a FastAPI app (task 1.6)."""

    def test_reads_schema_from_app(self) -> None:
        from araxys.waf import SchemaReader

        app = _DummyApp(MINIMAL_OPENAPI)
        reader = SchemaReader(app=app)
        schema = reader.schema

        assert schema["openapi"] == "3.0.2"
        assert schema["info"]["title"] == "Test API"

    def test_paths_property_extracts_routes(self) -> None:
        from araxys.waf import SchemaReader

        app = _DummyApp(MINIMAL_OPENAPI)
        reader = SchemaReader(app=app)

        paths = reader.paths
        assert "/users" in paths
        assert "get" in paths["/users"]
        assert "post" in paths["/users"]

    def test_multi_path_schema(self) -> None:
        from araxys.waf import SchemaReader

        app = _DummyApp(MULTI_PATH_OPENAPI)
        reader = SchemaReader(app=app)

        paths = reader.paths
        assert "/users" in paths
        assert "/health" in paths
        assert "/items" in paths
        # /items has both post and put
        assert "post" in paths["/items"]
        assert "put" in paths["/items"]

    def test_raises_when_neither_app_nor_file_path(self) -> None:
        from araxys.waf import SchemaReader

        with pytest.raises(ValueError, match="Either 'app' or 'file_path'"):
            SchemaReader()

    def test_raises_when_both_provided(self) -> None:
        from araxys.waf import SchemaReader

        app = _DummyApp(MINIMAL_OPENAPI)
        with pytest.raises(ValueError, match="exactly one"):
            SchemaReader(app=app, file_path="openapi.json")


class TestSchemaReaderFromFile:
    """SchemaReader ingesting from a JSON file path (task 1.6)."""

    @pytest.fixture
    def schema_file(self) -> str:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(MINIMAL_OPENAPI, f)
            return f.name

    def test_reads_schema_from_file(self, schema_file: str) -> None:
        from araxys.waf import SchemaReader

        reader = SchemaReader(file_path=schema_file)
        schema = reader.schema

        assert schema["openapi"] == "3.0.2"
        assert schema["info"]["title"] == "Test API"

    def test_paths_from_file_match_app(self, schema_file: str) -> None:
        from araxys.waf import SchemaReader

        from_app = SchemaReader(app=_DummyApp(MINIMAL_OPENAPI))
        from_file = SchemaReader(file_path=schema_file)

        assert from_app.paths == from_file.paths

    def test_invalid_json_raises(self) -> None:
        from araxys.waf import SchemaReader

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not valid json")
            bad_path = f.name

        with pytest.raises(ValueError, match="valid JSON"):
            SchemaReader(file_path=bad_path)

    def test_file_not_found_raises(self) -> None:
        from araxys.waf import SchemaReader

        with pytest.raises(FileNotFoundError):
            SchemaReader(file_path="nonexistent_file.json")

    def test_schema_without_paths(self) -> None:
        from araxys.waf import SchemaReader

        schema_no_paths = {
            "openapi": "3.0.2", "info": {"title": "Empty", "version": "1.0"},
        }
        app = _DummyApp(schema_no_paths)
        reader = SchemaReader(app=app)

        assert reader.paths == {}
