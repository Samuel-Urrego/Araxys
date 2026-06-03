"""Threat Intelligence Feeds module (v0.14).

Public API for threat intel feed ingestion, scheduling, and
configuration.
"""

from __future__ import annotations

import structlog

from araxys.core.config import FeedConfig, ThreatIntelConfig
from araxys.threat_intel.config import FEED_DEFAULTS
from araxys.threat_intel.scheduler import ThreatIntelScheduler

logger = structlog.get_logger("araxys.threat_intel")

__all__ = [
    "FEED_DEFAULTS",
    "FeedConfig",
    "FeedSource",
    "ThreatIntelConfig",
    "ThreatIntelScheduler",
]
