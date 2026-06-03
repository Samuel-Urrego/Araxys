"""WAF rule generator — produces AWS WAF JSON from an OpenAPI schema."""

from __future__ import annotations

import json
from typing import Any

from araxys.waf.schema_reader import SchemaReader


class WafRuleGenerator:
    """Generates AWS WAF v2 JSON from an OpenAPI schema.

    Parameters
    ----------
    schema_reader:
        A :class:`SchemaReader` already bound to a schema.
    web_acl_name:
        Name for the Web ACL. Used as prefix for derived resources.
    """

    def __init__(
        self,
        schema_reader: SchemaReader,
        web_acl_name: str = "AraxysWaf",
    ) -> None:
        self._reader = schema_reader
        self._web_acl_name = web_acl_name

    # ------------------------------------------------------------------
    # Main generation
    # ------------------------------------------------------------------

    def generate(self) -> dict[str, Any]:
        """Produce the full AWS WAF rule set.

        Returns a dict with keys ``IPSet``, ``RegexPatternSets``,
        ``RuleGroup``, and ``WebACL``.
        """
        paths = self._reader.paths

        # Collect unique paths and HTTP methods
        unique_paths: list[str] = sorted(paths.keys())
        methods_set: set[str] = set()
        content_types: set[str] = set()

        for _path, operations in paths.items():
            for method, details in operations.items():
                methods_set.add(method.upper())
                # Extract content-types from request body if present
                req_body = details.get("requestBody")
                if req_body and "content" in req_body:
                    for ct in req_body["content"]:
                        content_types.add(ct)
                # Also check response content types
                for _status, resp in details.get("responses", {}).items():
                    if "content" in resp:
                        for ct in resp["content"]:
                            content_types.add(ct)

        methods = sorted(methods_set)

        # Build IP set (empty — filled by escalation)
        ip_set = self._build_ip_set()

        # Build regex pattern sets — one for paths, one for methods
        regex_sets = self._build_regex_pattern_sets(unique_paths, methods, content_types)

        # Build rule group
        rule_group = self._build_rule_group(regex_sets, len(unique_paths), len(methods))

        # Build Web ACL
        web_acl = self._build_web_acl(rule_group["Name"])

        return {
            "IPSet": ip_set,
            "RegexPatternSets": regex_sets,
            "RuleGroup": rule_group,
            "WebACL": web_acl,
        }

    # ------------------------------------------------------------------
    # Component builders
    # ------------------------------------------------------------------

    def _build_ip_set(self) -> dict[str, Any]:
        return {
            "Name": f"{self._web_acl_name}-IPSet",
            "IPAddressVersion": "IPV4",
            "Addresses": [],
        }

    def _build_regex_pattern_sets(
        self,
        paths: list[str],
        methods: list[str],
        content_types: set[str],
    ) -> list[dict[str, Any]]:
        sets: list[dict[str, Any]] = []

        # Path pattern set — each path as a regex anchored at start
        if paths:
            path_regexes = [
                {"RegexString": f"^{p}"} for p in paths
            ]
            sets.append({
                "Name": f"{self._web_acl_name}-PathSet",
                "RegularExpressionList": path_regexes,
            })

        # Method pattern set
        if methods:
            method_entries = [{"RegexString": m} for m in methods]
            sets.append({
                "Name": f"{self._web_acl_name}-MethodSet",
                "RegularExpressionList": method_entries,
            })

        # Content-type pattern set (if any content types detected)
        if content_types:
            ct_sorted = sorted(content_types)
            ct_entries = [{"RegexString": ct} for ct in ct_sorted]
            sets.append({
                "Name": f"{self._web_acl_name}-ContentTypeSet",
                "RegularExpressionList": ct_entries,
            })

        return sets

    def _build_rule_group(
        self,
        regex_sets: list[dict[str, Any]],
        _path_count: int,
        _method_count: int,
    ) -> dict[str, Any]:
        rules: list[dict[str, Any]] = []
        priority = 0

        for ps in regex_sets:
            ps_name = ps["Name"]
            priority += 1
            rules.append({
                "Name": f"Allow-{ps_name}",
                "Priority": priority,
                "Action": {"Allow": {}},
                "Statement": {
                    "RegexPatternSetReferenceStatement": {
                        "ARN": f"arn:{ps_name}",
                        "FieldToMatch": (
                            {"UriPath": {}}
                            if "Path" in ps_name
                            else (
                                {"SingleHeader": {"Name": "content-type"}}
                                if "ContentType" in ps_name
                                else {"Method": {}}
                            )
                        ),
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    },
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": f"Allow{ps_name}",
                },
            })

        return {
            "Name": f"{self._web_acl_name}-RuleGroup",
            "Capacity": max(10, priority * 5),
            "Rules": rules,
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": f"{self._web_acl_name}RuleGroup",
            },
        }

    def _build_web_acl(self, rule_group_name: str) -> dict[str, Any]:
        return {
            "Name": self._web_acl_name,
            "DefaultAction": {"Block": {}},
            "Scope": "REGIONAL",
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": self._web_acl_name,
            },
            "Rules": [
                {
                    "Name": f"{self._web_acl_name}-RuleGroupRule",
                    "Priority": 0,
                    "OverrideAction": {"None": {}},
                    "Statement": {
                        "RuleGroupReferenceStatement": {
                            "ARN": f"arn:{rule_group_name}",
                        },
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": f"{self._web_acl_name}RuleGroupRule",
                    },
                },
            ],
        }

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self, pretty: bool = True) -> str:
        """Serialize the generated rules to a JSON string.

        The output is prefixed with a drift-warning comment.
        """
        result = self.generate()
        indent = 2 if pretty else None
        payload = json.dumps(result, indent=indent)

        warning = (
            "// WARNING: This WAF rule set is a static snapshot of the OpenAPI schema"
            " at generation time. Regenerate after API changes to avoid drift.\n"
        )
        return warning + payload
