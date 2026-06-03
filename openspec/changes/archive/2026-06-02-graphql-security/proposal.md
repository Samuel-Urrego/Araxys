# Proposal: GraphQL Security

## Intent

GraphQL endpoints are vulnerable to depth/breadth/cost denial-of-service, alias-based batching, and introspection abuse. Araxys has zero GraphQL protection today. This adds plug & play GraphQL security — same automatic middleware pattern as existing modules — using graphql-core AST analysis.

## Scope

### In Scope
- AST-based depth, breadth, and cost analysis via `graphql-core>=3.2` (optional extra)
- `BaseHTTPMiddleware` intercepting POST to configurable path — follows sanitize body-reinjection pattern
- Introspection blocking (reject `__schema`/`__type` queries)
- Strawberry `SchemaExtension` for resolver-level awareness (no re-parsing)
- `GraphQLSecurityConfig` BaseModel with per-check toggles
- Registration in `shield.py` between sanitize and rate-limit

### Out of Scope
- Resolver-level authorization (app concern)
- Ariadne extension, persisted queries, per-operation rate limiting (v2)
- Schema-aware cost analysis in ASGI middleware (only Strawberry extension has schema access)

## Capabilities

### New Capabilities
- `graphql-security`: ASGI middleware + config for GraphQL query validation (depth, breadth, cost, introspection). Includes optional Strawberry `SchemaExtension` for deeper integration.

### Modified Capabilities
None — greenfield module.

## Approach

**Hybrid**: ASGI `BaseHTTPMiddleware` (library-agnostic) + optional Strawberry `SchemaExtension`. Core AST visitors (depth, breadth, cost) are pure functions shared by both paths.

| Layer | Mechanism | Coverage |
|-------|-----------|----------|
| ASGI middleware | Intercepts POST body → parses GraphQL AST → validates → re-injects body | All GraphQL libraries |
| Strawberry extension | `SchemaExtension.on_operation()` — hooks into already-parsed document | Strawberry only |

graphql-core is lazy-imported with install hint: `pip install araxys[graphql]`.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/araxys/graphql/` | New | 8 modules: config, middleware, depth, breadth, cost, parser, extensions/strawberry, __init__ |
| `src/araxys/core/config.py` | Modified | Add `GraphQLSecurityConfig` |
| `src/araxys/shield.py` | Modified | Add `_register_graphql()` |
| `src/araxys/__init__.py` | Modified | Export new public symbols |
| `pyproject.toml` | Modified | Add `[graphql]` optional extra |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Body consumption conflict with sanitize | Medium | Reuse proven sanitize re-injection pattern; integration test both middlewares together |
| graphql-core version conflict with user pin | Low | Pin `>=3.2` (common minimum); document constraint |
| Re-parsing overhead (~1ms) | Low | Strawberry extension skips re-parse entirely |
| Cost analysis false positives | Medium | Users configure per-field costs via `field_costs` dict |

## Rollback Plan

`GraphQLSecurityConfig(enabled=False)` disables all GraphQL middleware instantly. Remove `[graphql]` extra to drop dependency. Shield registration is guarded by `enabled` — zero code paths execute when disabled.

## Dependencies

- `graphql-core>=3.2` (optional extra, pure Python, ~160KB, zero native deps)

## Success Criteria

- [ ] All 1833 existing tests pass (no regression)
- [ ] Depth/breadth/cost visitors reject queries exceeding configured limits
- [ ] Introspection blocked when `disable_introspection=True`
- [ ] GraphQL middleware works end-to-end with httpx `ASGITransport`
- [ ] Strawberry extension loads without errors when `strawberry-graphql` is installed
- [ ] Body re-injection preserves downstream server's ability to parse query
