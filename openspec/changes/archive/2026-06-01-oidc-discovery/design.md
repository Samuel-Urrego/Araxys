# Design: OIDC Discovery

## Technical Approach

New `src/araxys/oidc/` module — a pure utility (no middleware, no Shield wiring).
`OIDCDiscoveryClient` fetches `/.well-known/openid-configuration` via httpx,
validates against a Pydantic model, and caches in memory with configurable TTL.
`OAuth2Provider.from_issuer()` classmethod integrates discovery into the existing
oauth module as sugar.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Module files | 3 files: `__init__.py`, `client.py`, `models.py` | No middleware/interceptor needed. Fewer files than proposal's ~5 — cache lives on the client instance, exception lives in core. |
| Cache implementation | Dict + wall-clock TTL (same pattern as `_StateStore` in oauth/router.py) | No external dependency. TTL cache is trivial (<20 lines). Redis would be over-engineering for metadata that changes annually. |
| `from_issuer()` location | Classmethod on `OAuth2Provider` in `oauth/flow.py` | Keeps sugar co-located with the dataclass it constructs. No circular import — oidc imports oauth, not vice versa. |
| Config pattern | `OIDCDiscoveryConfig` as optional `None` field on `AraxysConfig` | Matches `WebAuthnConfig`, `BruteForceConfig` — `None` means disabled. |
| Exception | `OIDCDiscoveryError` in `core/exceptions.py` | Consistent with all other Araxys errors. Not a module-local exception. |
| httpx dependency | Move from `webhooks` optional to core `dependencies` | httpx is already in dev deps and webhooks optional. Reclassifying removes the implicit install requirement for a core feature. |

## Data Flow

```
caller ──► OIDCDiscoveryClient.discover(issuer_url)
                    │
                    ├─ strip trailing slash
                    ├─ check in-memory cache (keyed by normalized URL)
                    │    ├─ HIT + TTL valid ──► return cached OIDCProviderMetadata
                    │    └─ MISS or expired ──► continue
                    ├─ GET {issuer}/.well-known/openid-configuration (httpx)
                    ├─ validate response ──► OIDCProviderMetadata (Pydantic)
                    ├─ store in cache with timestamp
                    └─ return OIDCProviderMetadata

OAuth2Provider.from_issuer() ──► OIDCDiscoveryClient.discover()
                                   └─► constructs OAuth2Provider from metadata fields
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/oidc/__init__.py` | Create | Exports `OIDCDiscoveryClient`, `OIDCProviderMetadata` |
| `src/araxys/oidc/client.py` | Create | `OIDCDiscoveryClient` class: `discover()`, in-memory TTL cache, httpx fetch, config-driven |
| `src/araxys/oidc/models.py` | Create | `OIDCProviderMetadata` Pydantic model — required: issuer, authorization_endpoint, token_endpoint, jwks_uri; optional: userinfo_endpoint, scopes_supported, etc. |
| `src/araxys/oauth/flow.py` | Modify | Add `OAuth2Provider.from_issuer(issuer_url, client_id, client_secret)` async classmethod |
| `src/araxys/core/config.py` | Modify | Add `OIDCDiscoveryConfig(enabled, cache_ttl_seconds, timeout_seconds, verify_ssl)`; attach to `AraxysConfig` |
| `src/araxys/core/exceptions.py` | Modify | Add `OIDCDiscoveryError(AraxysError)` |
| `src/araxys/__init__.py` | Modify | Export new public types: `OIDCDiscoveryClient`, `OIDCProviderMetadata`, `OIDCDiscoveryError`, `OIDCDiscoveryConfig` |
| `pyproject.toml` | Modify | Move `httpx>=0.27` from `[project.optional-dependencies] webhooks` to `[project] dependencies` |

## Interfaces / Contracts

```python
# src/araxys/oidc/models.py
class OIDCProviderMetadata(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    # ... additional optional RFC 8414 fields

# src/araxys/oidc/client.py
class OIDCDiscoveryClient:
    def __init__(self, config: OIDCDiscoveryConfig | None = None) -> None: ...
    async def discover(self, issuer_url: str) -> OIDCProviderMetadata: ...

# src/araxys/oauth/flow.py — addition to OAuth2Provider
@classmethod
async def from_issuer(
    cls,
    issuer_url: str,
    client_id: str,
    client_secret: str,
    *,
    scopes: list[str] | None = None,
    name: str = "oidc",
) -> OAuth2Provider: ...
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `OIDCProviderMetadata` validation | Pydantic parametrized: valid response, missing required fields, non-JSON body |
| Unit | Cache hit/miss/expiry | Monkey-patch `time.time()`, assert HTTP call count |
| Unit | `from_issuer()` construction | Mock `OIDCDiscoveryClient.discover()`, assert correct `OAuth2Provider` fields |
| Integration | End-to-end discovery | httpx `respx` mock or `pytest-httpx` for well-known endpoint |

## Migration / Rollout

No migration required. New module — no existing callers. `httpx` move is additive; existing `webhooks` extra keeps httpx for backward compatibility. `from_issuer()` does not modify existing `OAuth2Provider` constructor.

## Open Questions

- None
