"""Feed default presets for Threat Intelligence Feeds (v0.14).

Each preset provides a built-in URL, refresh interval, and TTL
for the corresponding feed. Users override via ``FeedConfig``
fields on ``ThreatIntelConfig``.
"""

from __future__ import annotations

FEED_DEFAULTS: dict[str, dict[str, object]] = {
    "firehol_level1": {
        "url": (
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/"
            "master/firehol_level1.netset"
        ),
        "refresh_interval_seconds": 300,
        "ttl_seconds": 86400,
    },
    "firehol_level2": {
        "url": (
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/"
            "master/firehol_level2.netset"
        ),
        "refresh_interval_seconds": 300,
        "ttl_seconds": 86400,
    },
    "firehol_level3": {
        "url": (
            "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/"
            "master/firehol_level3.netset"
        ),
        "refresh_interval_seconds": 300,
        "ttl_seconds": 86400,
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "refresh_interval_seconds": 3600,
        "ttl_seconds": 86400,
    },
    "spamhaus_edrop": {
        "url": "https://www.spamhaus.org/drop/edrop.txt",
        "refresh_interval_seconds": 3600,
        "ttl_seconds": 604800,  # 7 days
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "refresh_interval_seconds": 300,
        "ttl_seconds": 86400,
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/blacklist",
        "api_key": None,  # user must provide
        "refresh_interval_seconds": 3600,
        "ttl_seconds": 86400,
    },
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/indicators/export",
        "api_key": None,  # user must provide
        "refresh_interval_seconds": 3600,
        "ttl_seconds": 86400,
    },
}
