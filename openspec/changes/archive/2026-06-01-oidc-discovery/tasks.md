# Tasks: OIDC Discovery

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~380-420 additions, ~5 deletions |
| 400-line budget risk | Medium |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (Foundation, ~130 loc) → PR 2 (Core, ~180 loc) → PR 3 (Tests, ~130 loc) |
| Delivery strategy | force-chained |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: Medium

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Models, config, exception, httpx dep | PR 1 | Foundation — base branch: main |
| 2 | Client, from_issuer(), exports | PR 2 | Core logic — base: main (after PR 1 merges) |
| 3 | Unit + integration tests | PR 3 | Verification — base: main (after PR 2 merges) |

## Phase 1: Foundation

- [x] 1.1 Update `pyproject.toml` — move `httpx>=0.27` from `[project.optional-dependencies] webhooks` to `[project] dependencies`
- [x] 1.2 Update `src/araxys/core/exceptions.py` — add `OIDCDiscoveryError(AraxysError)` with optional `issuer_url` and `detail` fields
- [x] 1.3 Create `src/araxys/oidc/models.py` — `OIDCProviderMetadata(BaseModel)` with required fields: issuer, authorization_endpoint, token_endpoint, jwks_uri; optional: userinfo_endpoint, scopes_supported, response_types_supported
- [x] 1.4 Update `src/araxys/core/config.py` — add `OIDCDiscoveryConfig(BaseModel)` with fields: `enabled: bool = True`, `cache_ttl_seconds: int = 300`, `timeout_seconds: int = 10`, `verify_ssl: bool = True`; attach `oidc_discovery: OIDCDiscoveryConfig | None = Field(default=None)` to `AraxysConfig`

## Phase 2: Core Implementation

- [x] 2.1 Create `src/araxys/oidc/client.py` — `OIDCDiscoveryClient` class: `__init__(config)` accepts optional `OIDCDiscoveryConfig`; `discover(issuer_url)` async method strips trailing slash, checks in-memory dict cache with wall-clock TTL, fetches `{issuer}/.well-known/openid-configuration` via `httpx.AsyncClient`, parses into `OIDCProviderMetadata`, caches result, raises `OIDCDiscoveryError` on failure
- [x] 2.2 Create `src/araxys/oidc/__init__.py` — export `OIDCDiscoveryClient`, `OIDCProviderMetadata`
- [x] 2.3 Update `src/araxys/oauth/flow.py` — add `OAuth2Provider.from_issuer(issuer_url, client_id, client_secret, *, scopes, name)` async classmethod: creates `OIDCDiscoveryClient`, calls `discover()`, constructs `OAuth2Provider` with discovered endpoints; propagate discovery errors
- [x] 2.4 Update `src/araxys/__init__.py` — add exports for `OIDCDiscoveryClient`, `OIDCProviderMetadata`, `OIDCDiscoveryError`, `OIDCDiscoveryConfig`

## Phase 3: Testing

- [x] 3.1 Unit test `OIDCProviderMetadata` — valid JSON response, missing required fields (issuer, jwks_uri), non-JSON body, non-200 status → `OIDCDiscoveryError`
- [x] 3.2 Unit test cache — hit within TTL (0 HTTP calls), miss after expiry (fresh call), trailing-slash normalization; use `time.time` monkey-patching
- [x] 3.3 Integration test — end-to-end `discover()` with `pytest-httpx` or `respx` mock for `/.well-known/openid-configuration`
- [x] 3.4 Unit test `OAuth2Provider.from_issuer()` — mock discovery, assert endpoint fields populated; verify `OIDCDiscoveryError` propagation on failure
