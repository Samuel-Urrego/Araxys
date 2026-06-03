"""AWS WAF Bridge — Rule generation and escalation (v0.13)."""

# Re-export config models from core for convenience
from araxys.core.config import WafEscalationConfig, WafRuleConfig  # noqa: I001
from araxys.waf.aws_client import WafClient
from araxys.waf.escalation import WafEscalationSubscriber
from araxys.waf.rule_generator import WafRuleGenerator
from araxys.waf.schema_reader import SchemaReader

__all__ = [
    "SchemaReader",
    "WafClient",
    "WafEscalationConfig",
    "WafEscalationSubscriber",
    "WafRuleConfig",
    "WafRuleGenerator",
]
