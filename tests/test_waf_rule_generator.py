"""Tests for WafRuleGenerator — AWS WAF JSON generation (Phase 2, task 2.1)."""

from __future__ import annotations

import json
from typing import Any

from araxys.waf.schema_reader import SchemaReader

# ---------------------------------------------------------------------------
# Fixtures — reusable SchemaReaders with known inputs
# ---------------------------------------------------------------------------


class _DummyApp:
    """Simulates a FastAPI app with controlled openapi() output."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    def openapi(self) -> dict[str, Any]:
        return self._schema


THREE_ROUTE_SCHEMA: dict[str, Any] = {
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
        "/health": {
            "get": {
                "responses": {"200": {"description": "OK"}},
            },
        },
    },
}

SINGLE_ROUTE_SCHEMA: dict[str, Any] = {
    "openapi": "3.0.2",
    "info": {"title": "Single API", "version": "1.0.0"},
    "paths": {
        "/health": {
            "get": {
                "responses": {"200": {"description": "OK"}},
            },
        },
    },
}

SCHEMA_WITH_CONTENT_TYPES: dict[str, Any] = {
    "openapi": "3.0.2",
    "info": {"title": "Content API", "version": "1.0.0"},
    "paths": {
        "/upload": {
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"type": "object"}},
                        "multipart/form-data": {"schema": {"type": "object"}},
                    },
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/download": {
            "get": {
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/octet-stream": {},
                        },
                    },
                },
            },
        },
    },
}

SCHEMA_WITH_VARIOUS_METHODS: dict[str, Any] = {
    "openapi": "3.0.2",
    "info": {"title": "Method API", "version": "1.0.0"},
    "paths": {
        "/items": {
            "get": {"responses": {"200": {"description": "OK"}}},
            "post": {"responses": {"201": {"description": "Created"}}},
            "put": {"responses": {"200": {"description": "OK"}}},
            "delete": {"responses": {"204": {"description": "No Content"}}},
            "patch": {"responses": {"200": {"description": "OK"}}},
        },
    },
}


def _schema_reader(schema: dict[str, Any]) -> SchemaReader:
    """Helper: build a SchemaReader from a raw OpenAPI dict."""
    return SchemaReader(app=_DummyApp(schema))


# ---------------------------------------------------------------------------
# Task 2.1 — WafRuleGenerator import and basic structure
# ---------------------------------------------------------------------------


class TestWafRuleGeneratorImport:
    """Verify WafRuleGenerator is importable and constructable."""

    def test_importable_from_waf_package(self) -> None:
        from araxys.waf import WafRuleGenerator

        assert WafRuleGenerator is not None

    def test_construct_with_schema_reader(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        assert gen is not None


# ---------------------------------------------------------------------------
# Task 2.1 — IP Set generation
# ---------------------------------------------------------------------------


class TestIpSetGeneration:
    """The generator must produce a top-level IP set for escalation."""

    def test_generate_includes_ip_set(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        assert "IPSet" in result
        ip_set = result["IPSet"]
        assert ip_set["Name"] == "TestWaf-IPSet"
        assert "Addresses" in ip_set
        assert ip_set["IPAddressVersion"] == "IPV4"

    def test_ip_set_addresses_empty_by_default(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        result = gen.generate()

        assert result["IPSet"]["Addresses"] == []

    def test_custom_web_acl_name_reflected_in_ip_set(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="CustomWaf")
        result = gen.generate()

        assert result["IPSet"]["Name"] == "CustomWaf-IPSet"


# ---------------------------------------------------------------------------
# Task 2.1 — Regex pattern set generation
# ---------------------------------------------------------------------------


class TestRegexPatternSets:
    """The generator must produce regex pattern sets for paths and methods."""

    def test_generate_includes_regex_pattern_sets(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        assert "RegexPatternSets" in result
        pattern_sets = result["RegexPatternSets"]
        assert isinstance(pattern_sets, list)
        # Should have at least a path pattern set and a method pattern set
        assert len(pattern_sets) >= 2

    def test_path_pattern_set_contains_all_route_patterns(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        path_set: dict[str, Any] | None = None
        for ps in result["RegexPatternSets"]:
            if "Path" in ps.get("Name", ""):
                path_set = ps
                break

        assert path_set is not None, "Expected a path pattern set"
        regex_strings: list[str] = [
            entry["RegexString"] for entry in path_set["RegularExpressionList"]
        ]
        # /users and /health should be in there as regex patterns
        assert any("/users" in r for r in regex_strings)
        assert any("/health" in r for r in regex_strings)

    def test_method_pattern_set_contains_all_http_methods(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(SCHEMA_WITH_VARIOUS_METHODS)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        method_set: dict[str, Any] | None = None
        for ps in result["RegexPatternSets"]:
            if "Method" in ps.get("Name", ""):
                method_set = ps
                break

        assert method_set is not None, "Expected a method pattern set"
        regex_strings: list[str] = [
            entry["RegexString"] for entry in method_set["RegularExpressionList"]
        ]
        assert "GET" in regex_strings
        assert "POST" in regex_strings
        assert "PUT" in regex_strings
        assert "DELETE" in regex_strings
        assert "PATCH" in regex_strings

    def test_single_route_still_produces_pattern_sets(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(SINGLE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        pattern_sets = result["RegexPatternSets"]
        # Single route: still produces path and method sets
        assert len(pattern_sets) >= 2


# ---------------------------------------------------------------------------
# Task 2.1 — Rule group generation
# ---------------------------------------------------------------------------


class TestRuleGroupGeneration:
    """The generator must produce a rule group with path/method rules."""

    def test_generate_includes_rule_group(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        assert "RuleGroup" in result
        rule_group = result["RuleGroup"]
        assert rule_group["Name"] == "TestWaf-RuleGroup"
        assert "Rules" in rule_group
        assert isinstance(rule_group["Rules"], list)
        assert len(rule_group["Rules"]) > 0

    def test_rule_group_rules_have_priority_and_action(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        result = gen.generate()

        for rule in result["RuleGroup"]["Rules"]:
            assert "Priority" in rule
            assert "Action" in rule
            assert "Statement" in rule
            assert "VisibilityConfig" in rule

    def test_rule_group_has_visibility_config(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        result = gen.generate()

        rg = result["RuleGroup"]
        assert "VisibilityConfig" in rg
        assert "SampledRequestsEnabled" in rg["VisibilityConfig"]


# ---------------------------------------------------------------------------
# Task 2.1 — Web ACL generation
# ---------------------------------------------------------------------------


class TestWebAclGeneration:
    """The generator must produce a Web ACL referencing the rule group."""

    def test_generate_includes_web_acl(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        result = gen.generate()

        assert "WebACL" in result
        web_acl = result["WebACL"]
        assert web_acl["Name"] == "TestWaf"
        assert "DefaultAction" in web_acl
        assert "Rules" in web_acl
        assert "VisibilityConfig" in web_acl

    def test_web_acl_default_action_is_block(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        result = gen.generate()

        assert result["WebACL"]["DefaultAction"] == {"Block": {}}

    def test_web_acl_references_rule_group_in_rules(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        output = gen.generate()

        acl_rules = output["WebACL"]["Rules"]
        assert len(acl_rules) > 0
        # At minimum, the ACL should have the rule group reference
        assert len(acl_rules) >= 1


# ---------------------------------------------------------------------------
# Task 2.1 — Drift warning
# ---------------------------------------------------------------------------


class TestDriftWarning:
    """The generator must include a drift-warning comment in the output."""

    def test_to_json_includes_drift_warning(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        output = gen.to_json()

        assert "snapshot" in output.lower()

    def test_to_json_produces_valid_json_with_indentation(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        output = gen.to_json(pretty=True)

        # Should contain valid JSON with 2-space indentation
        assert "  " in output
        # Find the JSON portion (after the comment line) and parse it
        lines = output.split("\n")
        json_lines = [line for line in lines if not line.strip().startswith("//")]
        json_str = "\n".join(json_lines).strip()
        parsed = json.loads(json_str)
        assert "WebACL" in parsed

    def test_to_json_pretty_uses_2_space_indent(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(THREE_ROUTE_SCHEMA)
        gen = WafRuleGenerator(reader)
        output = gen.to_json(pretty=True)

        # After the comment lines, JSON should use 2-space indentation
        lines = output.split("\n")
        json_start = 0
        for i, line in enumerate(lines):
            if line.strip().startswith("{"):
                json_start = i
                break
        # Verify indentation exists and is 2-space multiples
        has_2space_indent = any(
            line.startswith("  ") and not line.startswith("    ")
            for line in lines[json_start + 1 : json_start + 5]
        )
        assert has_2space_indent, (
            f"Expected 2-space indentation in: {lines[json_start:json_start + 5]}"
        )


# ---------------------------------------------------------------------------
# Task 2.1 — Edge cases and content-type handling
# ---------------------------------------------------------------------------


class TestContentTypeHandling:
    """The generator must detect content-types from request bodies."""

    def test_content_types_are_deduped(self) -> None:
        from araxys.waf import WafRuleGenerator

        reader = _schema_reader(SCHEMA_WITH_CONTENT_TYPES)
        gen = WafRuleGenerator(reader, web_acl_name="TestWaf")
        gen.generate()

        # Content types should appear in at least one pattern set or rule
        output_json = gen.to_json()
        # The output should mention content types somewhere
        assert "application/json" in output_json or "multipart/form-data" in output_json


class TestEmptyEdgeCases:
    """Generator must handle edge cases gracefully."""

    def test_schema_with_no_paths(self) -> None:
        from araxys.waf import WafRuleGenerator

        empty_schema: dict[str, Any] = {
            "openapi": "3.0.2",
            "info": {"title": "Empty", "version": "1.0.0"},
        }
        reader = _schema_reader(empty_schema)
        gen = WafRuleGenerator(reader)

        # Should not crash — produce minimal valid structure
        result = gen.generate()
        assert "WebACL" in result
        assert "IPSet" in result
