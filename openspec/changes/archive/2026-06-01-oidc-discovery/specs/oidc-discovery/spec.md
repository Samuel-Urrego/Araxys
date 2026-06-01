# OIDC Discovery Specification

## Purpose

Provide an OIDC Discovery client (RFC 8414) that auto-discovers OIDC
provider endpoints from an issuer URL. This eliminates hardcoded
provider endpoints and optionally integrates with the existing OAuth2
module via `OAuth2Provider.from_issuer()`.

## Requirements

### Requirement: Fetch OIDC Discovery Document

The system MUST fetch `/.well-known/openid-configuration` for a given
issuer URL, resolving the well-known URI as specified by RFC 8414 §3.

#### Scenario: Successful discovery from standard issuer

- GIVEN a valid issuer URL `https://accounts.example.com`
- WHEN `discover(issuer_url)` is called
- THEN the client MUST resolve `https://accounts.example.com/.well-known/openid-configuration`
- AND return a validated `OIDCProviderMetadata` instance

#### Scenario: Issuer URL with trailing slash

- GIVEN `https://accounts.example.com/`
- WHEN discovery is requested
- THEN trailing slashes MUST be stripped before path resolution
- AND the resolved URL MUST NOT contain duplicate slashes

#### Scenario: Unreachable provider or timeout

- GIVEN a host that is unreachable or does not respond within `timeout_seconds`
- WHEN discovery is attempted
- THEN the client MUST raise `OIDCDiscoveryError`
- AND the operation MUST NOT hang indefinitely

---

### Requirement: Validate Provider Metadata

The system MUST parse the discovery response into `OIDCProviderMetadata`
(a Pydantic model) and validate that all RFC 8414 required fields are
present and non-empty: `issuer`, `authorization_endpoint`,
`token_endpoint`, `jwks_uri`.

#### Scenario: Valid response with all required fields

- GIVEN a well-known response containing all required fields
- WHEN the response is parsed and validated
- THEN `OIDCProviderMetadata` MUST be returned with every required field populated

#### Scenario: Response missing a required field

- GIVEN a well-known response that omits `jwks_uri`
- WHEN validation runs
- THEN the client MUST raise `OIDCDiscoveryError` naming the missing field

#### Scenario: Invalid JSON or non-200 status

- GIVEN a response with status 404 or a non-JSON body
- WHEN parsing is attempted
- THEN `OIDCDiscoveryError` MUST be raised with a descriptive message

---

### Requirement: In-Memory Cache with Configurable TTL

The system MUST cache discovered metadata in memory, keyed by issuer
URL, with a configurable TTL (`cache_ttl_seconds`). Requests for the
same issuer within the TTL MUST return the cached result without a
network call.

#### Scenario: Cache hit within TTL

- GIVEN issuer `A` was discovered 30 seconds ago and TTL is 300 seconds
- WHEN `discover("A")` is called again
- THEN the cached result MUST be returned
- AND no HTTP request MUST be made

#### Scenario: Cache miss after TTL expiration

- GIVEN issuer `A` was discovered 350 seconds ago and TTL is 300 seconds
- WHEN `discover("A")` is called again
- THEN a fresh HTTP request MUST be made
- AND the cache MUST be updated

---

### Requirement: OAuth2Provider.from_issuer() Sugar

The `OAuth2Provider` class MUST expose an async `from_issuer()`
classmethod that uses discovery to auto-populate
`authorization_endpoint`, `token_endpoint`, and `userinfo_endpoint`,
while accepting `client_id` and `client_secret` as explicit arguments.

#### Scenario: Auto-populate provider endpoints

- GIVEN a valid issuer URL and client credentials
- WHEN `OAuth2Provider.from_issuer(issuer_url, client_id="abc", client_secret="xyz")` is awaited
- THEN discovery MUST be performed
- AND the returned `OAuth2Provider` MUST have all three endpoints populated from metadata
- AND `client_id` and `client_secret` MUST match the provided values

#### Scenario: Discovery failure propagates

- GIVEN an issuer URL whose well-known endpoint is unreachable
- WHEN `OAuth2Provider.from_issuer(issuer_url, ...)` is awaited
- THEN `OIDCDiscoveryError` MUST be raised with the original discovery error context

---

### Requirement: Configuration via OIDCDiscoveryConfig

The system MUST accept configuration through an `OIDCDiscoveryConfig`
Pydantic model with fields: `enabled`, `cache_ttl_seconds`,
`timeout_seconds`, and `verify_ssl`. It MUST be registered as an
optional field on `AraxysConfig`, defaulting to `None` (disabled).

#### Scenario: Module disabled by default

- GIVEN `AraxysConfig` without an explicit `oidc_discovery` field
- THEN `oidc_discovery` MUST default to `None`
- AND no discovery behavior MUST be active

#### Scenario: Custom cache and timeout

- GIVEN `OIDCDiscoveryConfig(cache_ttl_seconds=600, timeout_seconds=5)`
- WHEN the discovery client is initialized with this config
- THEN cache entries MUST expire after 600 seconds
- AND HTTP requests MUST time out after 5 seconds

#### Scenario: SSL verification toggle

- GIVEN `OIDCDiscoveryConfig(verify_ssl=False)`
- WHEN discovery fetches from an endpoint with a self-signed certificate
- THEN the TLS handshake MUST succeed without certificate validation errors
