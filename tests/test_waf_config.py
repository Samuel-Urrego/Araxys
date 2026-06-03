"""Tests for AWS WAF bridge configuration models (Phase 1, tasks 1.2-1.3)."""

from __future__ import annotations


class TestWafRuleConfig:
    """WafRuleConfig — defaults and custom values (task 1.2)."""

    def test_defaults(self) -> None:
        from araxys.core.config import WafRuleConfig

        c = WafRuleConfig()
        assert c.enabled is False
        assert c.openapi_file is None
        assert c.output_file is None
        assert c.web_acl_name == "AraxysWaf"
        assert c.region == "us-east-1"

    def test_custom_values(self) -> None:
        from araxys.core.config import WafRuleConfig

        c = WafRuleConfig(
            enabled=True,
            openapi_file="openapi.json",
            output_file="waf-rules.json",
            web_acl_name="MyWaf",
            region="eu-west-1",
        )
        assert c.enabled is True
        assert c.openapi_file == "openapi.json"
        assert c.output_file == "waf-rules.json"
        assert c.web_acl_name == "MyWaf"
        assert c.region == "eu-west-1"


class TestWafEscalationConfig:
    """WafEscalationConfig — defaults, allowed_event_types, IP set fields (task 1.2)."""

    def test_defaults(self) -> None:
        from araxys.core.config import WafEscalationConfig

        c = WafEscalationConfig()
        assert c.enabled is False
        assert c.dry_run is False
        assert c.multi_strike_count == 3
        assert c.multi_strike_window_seconds == 60
        assert c.ttl_seconds == 86400
        assert "rate_limit_exceeded" in c.allowed_event_types
        assert "sanitize_blocked" in c.allowed_event_types
        assert "brute_force_lockout" in c.allowed_event_types
        assert "honeypot_triggered" in c.allowed_event_types
        assert c.ip_set_id is None
        assert c.ip_set_name == "AraxysBlockedIPs"

    def test_custom_values(self) -> None:
        from araxys.core.config import WafEscalationConfig

        c = WafEscalationConfig(
            enabled=True,
            dry_run=True,
            multi_strike_count=5,
            multi_strike_window_seconds=120,
            ttl_seconds=43200,
            allowed_event_types=["rate_limit_exceeded"],
            ip_set_id="abc-123",
            ip_set_name="MyIPSet",
        )
        assert c.enabled is True
        assert c.dry_run is True
        assert c.multi_strike_count == 5
        assert c.multi_strike_window_seconds == 120
        assert c.ttl_seconds == 43200
        assert c.allowed_event_types == ["rate_limit_exceeded"]
        assert c.ip_set_id == "abc-123"
        assert c.ip_set_name == "MyIPSet"


class TestWafConfigInAraxysConfig:
    """aws_waf and waf_escalation must be optional None on AraxysConfig (task 1.3)."""

    def test_aws_waf_defaults_to_none(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        assert c.aws_waf is None

    def test_waf_escalation_defaults_to_none(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(secret_key="test-secret-key-must-be-32-chars!!")
        assert c.waf_escalation is None

    def test_aws_waf_provided_via_dict(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            aws_waf={"enabled": True, "region": "eu-west-1"},  # type: ignore[arg-type]
        )
        assert c.aws_waf is not None
        assert c.aws_waf.enabled is True
        assert c.aws_waf.region == "eu-west-1"
        # defaults preserved
        assert c.aws_waf.web_acl_name == "AraxysWaf"
        assert c.aws_waf.openapi_file is None

    def test_waf_escalation_provided_via_dict(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            waf_escalation={"enabled": True, "dry_run": True},  # type: ignore[arg-type]
        )
        assert c.waf_escalation is not None
        assert c.waf_escalation.enabled is True
        assert c.waf_escalation.dry_run is True
        # defaults preserved
        assert c.waf_escalation.multi_strike_count == 3
        assert c.waf_escalation.ttl_seconds == 86400

    def test_both_provided_simultaneously(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            aws_waf={"enabled": True, "web_acl_name": "ProdWaf"},  # type: ignore[arg-type]
            waf_escalation={"enabled": True, "ip_set_name": "ProdBlocked"},  # type: ignore[arg-type]
        )
        assert c.aws_waf is not None
        assert c.waf_escalation is not None
        assert c.aws_waf.enabled is True
        assert c.aws_waf.web_acl_name == "ProdWaf"
        assert c.waf_escalation.enabled is True
        assert c.waf_escalation.ip_set_name == "ProdBlocked"

    def test_both_explicitly_none(self) -> None:
        from araxys.core.config import AraxysConfig

        c = AraxysConfig(
            secret_key="test-secret-key-must-be-32-chars!!",
            aws_waf=None,
            waf_escalation=None,
        )
        assert c.aws_waf is None
        assert c.waf_escalation is None
