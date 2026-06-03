# Threat Intel Feeds Specification

## Purpose

Proactive ingestion of community threat intelligence IPs into Araxys blocklist. Background scheduling, TTL-based eviction, per-feed configuration, and Shield lifecycle integration. Module disabled by default.

## Requirements

### Requirement: Feed Configuration

The system MUST support per-feed configuration gated by a master `enabled: bool = False` switch. Each feed MUST expose: `enabled`, `refresh_interval_seconds`, `ttl_seconds`, `url`, and optional `api_key`.

#### Scenario: Module disabled by default

- GIVEN no `threat_intel` config key
- WHEN the shield initializes
- THEN no scheduler task is created and no feeds are fetched

#### Scenario: Selective feed enablement

- GIVEN `threat_intel.enabled=true`, Firehol L1 enabled, AbuseIPDB disabled
- WHEN the scheduler runs
- THEN Firehol L1 is fetched; AbuseIPDB is skipped

### Requirement: Feed Fetching

Plaintext feeds (Firehol, Spamhaus, Blocklist.de) MUST parse one-IP/CIDR-per-line format, skip `#` comments, and skip blank lines. API feeds (AbuseIPDB, AlienVault OTX) MUST handle JSON responses with API-key authentication. HTTP errors across all feeds MUST be logged and skipped without crashing the scheduler.

#### Scenario: Plaintext feed parsed

- GIVEN Firehol L1 returns 5 IPs, 2 comments, 1 blank line
- WHEN the fetcher processes it
- THEN 5 IPs extracted; comments and blanks discarded

#### Scenario: API feed with auth

- GIVEN AbuseIPDB configured with valid `api_key`
- WHEN the fetcher queries the endpoint
- THEN JSON response is parsed; IPs meeting the abuse threshold are collected

#### Scenario: HTTP error resilience

- GIVEN Blocklist.de returns HTTP 503
- WHEN the scheduler fetches it
- THEN a warning is logged, the feed skipped, remaining feeds continue

### Requirement: Scheduler Lifecycle

The system MUST start the background asyncio task on shield init when `threat_intel.enabled=true`. It MUST cancel and await the task on shield shutdown. Each feed MUST be fetched per its `refresh_interval_seconds`. A CLI command `araxys threat-intel refresh` SHOULD trigger on-demand refresh.

#### Scenario: Scheduler start

- GIVEN `threat_intel.enabled=true`
- WHEN `AraxysShield.__init__()` runs
- THEN an `asyncio.create_task()` launches the scheduler loop

#### Scenario: Graceful shutdown

- GIVEN a running scheduler task
- WHEN `shield.shutdown()` is called
- THEN the task is cancelled, awaited, and all resources released

### Requirement: IP Storage & Eviction

The system MUST add fetched IPs to the IP Access blocklist. It MUST track per-feed TTL in Redis ZSET `araxys:threat_intel:ips` and evict expired IPs on each sync loop. Large feeds (Blocklist.de ~20K IPs) SHOULD use bulk Redis pipeline operations.

#### Scenario: IPs added to blocklist

- GIVEN Firehol L1 returns 100 IPs
- WHEN the resolver processes them
- THEN all IPs added to the blocklist with TTL recorded in Redis ZSET

#### Scenario: Expired IPs evicted

- GIVEN IP 10.0.0.1 with TTL 3600s, and 3601s elapsed
- WHEN the eviction sync runs
- THEN 10.0.0.1 is removed from both Redis ZSET and the blocklist

### Requirement: False Positive Mitigation

The system MUST support `exclude_ips` — IPs never blocked by threat intel. Per-feed `enabled` flags MUST allow operators to opt in to specific feeds.

#### Scenario: Excluded IP filtered

- GIVEN `exclude_ips=["1.2.3.4"]` and Firehol L1 includes 1.2.3.4
- WHEN the feed is processed
- THEN 1.2.3.4 is filtered out and never added to the blocklist

### Requirement: Event Integration

The system MUST emit `THREAT_INTEL_LOADED` after each feed refresh via `SecurityEventBus`. It MUST emit `THREAT_INTEL_MATCH` when a blocked request's IP originates from threat intel.

#### Scenario: Load event emitted

- GIVEN Firehol L1 refresh completes with 50 new IPs
- WHEN processing finishes
- THEN `THREAT_INTEL_LOADED` emitted with feed name and IP count

#### Scenario: Match event on block

- GIVEN IP 5.6.7.8 was blocklisted via threat intel
- WHEN a request from 5.6.7.8 is blocked by IP Access middleware
- THEN `THREAT_INTEL_MATCH` emitted with matched IP and source feed
