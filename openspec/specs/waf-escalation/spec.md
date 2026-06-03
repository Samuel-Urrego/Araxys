# WAF Escalation Specification

## Purpose

Escalate blocked IPs to AWS WAF IP sets by subscribing to the SecurityEventBus. A multi-strike threshold prevents single-event escalation. Dry-run mode logs without calling AWS.

## Requirements

### Requirement: Event Bus Subscription

The system MUST subscribe to the SecurityEventBus and react to escalation-worthy security events.

#### Scenario: Subscriber wired at start

- GIVEN `WafEscalationConfig.enabled` is `true`
- WHEN the shield initializes with `aws_waf` configured
- THEN a `WafEscalationSubscriber` is created and subscribes via `event_bus.subscribe()`

#### Scenario: Disabled subscriber

- GIVEN `WafEscalationConfig.enabled` is `false`
- WHEN the shield initializes
- THEN no subscriber is created and no AWS calls are made

### Requirement: Multi-Strike Threshold

The system MUST NOT escalate an IP on a single event. An IP MUST receive N events within a configurable time window before escalation.

#### Scenario: Threshold met

- GIVEN `multi_strike_count=3` and `multi_strike_window_seconds=60`
- WHEN IP 1.2.3.4 triggers `RATE_LIMIT_EXCEEDED` three times within 60 seconds
- THEN the IP is escalated to the AWS WAF IP set

#### Scenario: Threshold not met

- GIVEN `multi_strike_count=3` and `multi_strike_window_seconds=60`
- WHEN IP 1.2.3.4 triggers only two `RATE_LIMIT_EXCEEDED` events in that window
- THEN the IP is NOT escalated

### Requirement: Supported Event Types

The system MUST escalate on these event types when configured: `RATE_LIMIT_EXCEEDED`, `SANITIZE_BLOCKED`, `BRUTE_FORCE_LOCKOUT`, `IP_BLOCKED`. `HONEYPOT_TRIGGERED` SHOULD be supported once the honeypot module wires the event bus.

#### Scenario: Allowed event type

- GIVEN `allowed_event_types` includes `RATE_LIMIT_EXCEEDED`
- WHEN an `RATE_LIMIT_EXCEEDED` event is emitted
- THEN the subscriber increments the strike counter for the source IP

#### Scenario: Filtered event type

- GIVEN `allowed_event_types` is `[RATE_LIMIT_EXCEEDED]`
- WHEN a `BRUTE_FORCE_LOCKOUT` event is emitted
- THEN the subscriber ignores it

### Requirement: Dry-Run Mode

When `dry_run=true`, the system MUST log the escalation action but MUST NOT call the AWS WAF API.

#### Scenario: Dry run active

- GIVEN `dry_run=true`
- WHEN an IP meets the multi-strike threshold
- THEN a log entry is emitted at INFO level with the IP and event type, and no AWS API call is made

### Requirement: AWS WAF API Constraints

The system MUST respect AWS WAF API rate limits (1 req/s per IP set) and IP set size limits (10K max entries). It MUST batch updates and evict expired entries.

#### Scenario: Rate limiting

- GIVEN 5 IPs are queued for escalation simultaneously
- WHEN the subscriber processes the queue
- THEN requests are throttled to at most 1 per second against the same IP set

#### Scenario: IP set nearing capacity

- GIVEN the IP set has 9,995 entries
- WHEN 10 more IPs are escalated
- THEN expired entries (past TTL) are evicted first; if still full, oldest entries are evicted

### Requirement: boto3 Handling

The system MUST handle boto3 absence gracefully and wrap all AWS calls in `asyncio.to_thread()`.

#### Scenario: Graceful import

- GIVEN boto3 is not installed
- WHEN `WafEscalationSubscriber` is instantiated
- THEN `ImportError` is caught and a clear message is raised: "boto3 not installed. Install with: pip install araxys[aws_waf]"

### Requirement: Configuration

The system MUST accept these configuration fields via a Pydantic model: `enabled`, `dry_run`, `multi_strike_count`, `multi_strike_window_seconds`, `ttl_seconds`, `allowed_event_types`, `ip_set_id`, `ip_set_name`.

#### Scenario: Default configuration

- GIVEN no explicit escalation config
- WHEN the config model is loaded with defaults
- THEN `enabled=false`, `dry_run=false`, `multi_strike_count=3`, `multi_strike_window_seconds=60`, `ttl_seconds=86400`

#### Scenario: Custom TTL per event type

- GIVEN the user wants RATE_LIMIT_EXCEEDED IPs to expire in 1 hour but BRUTE_FORCE_LOCKOUT IPs in 24 hours
- WHEN `ttl_seconds` is configured per event type
- THEN each escalated IP carries its type-specific TTL in the WAF IP set description
