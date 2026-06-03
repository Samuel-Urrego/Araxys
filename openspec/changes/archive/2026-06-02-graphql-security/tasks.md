# Tasks: GraphQL Security

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 550–700 (new: ~330, modified: ~70, tests: ~250) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Delivery strategy | single-pr → chained (user switched) |
| Suggested split | PR 1: visitors + config → PR 2: middleware + shield + tests |
| Chain strategy | stacked-to-main |

Decision needed before apply: Yes (resolved — chained PRs via stacked-to-main)
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

> ⚠️ `single-pr` strategy requires `size:exception` for High-risk work. If switching to chained, PR 1 delivers standalone visitors (testable in isolation); PR 2 adds wiring + integration tests.

---

## Phase 1: Foundation — Config, Types, Dependencies

- [x] 1.1 Add `GRAPHQL_BLOCKED = "graphql_blocked"` to `SecurityEventType` in `src/araxys/core/types.py`
- [x] 1.2 Create `src/araxys/graphql/config.py` — `GraphQLSecurityConfig(BaseModel)` with all fields: `enabled`, `graphql_path`, `max_depth`(8), `max_breadth`(50), `max_cost`(1000), `default_field_cost`(1), `field_costs`, `disable_introspection`, `exclude_paths`
- [x] 1.3 Add `graphql_security: GraphQLSecurityConfig | None = None` to `AraxysConfig` in `src/araxys/core/config.py`
- [x] 1.4 Add `graphql = ["graphql-core>=3.2", "strawberry-graphql>=0.200"]` to optional-dependencies in `pyproject.toml`

## Phase 2: AST Analysis Visitors

- [x] 2.1 Create `src/araxys/graphql/depth.py` — `DepthVisitor(Visitor)` tracking max nesting via `enter_field`/`leave_field`; `validate_depth(doc, max_depth)` returns error or None
- [x] 2.2 Create `src/araxys/graphql/breadth.py` — `BreadthVisitor` counting selections (aliases as separate) per selection set; `validate_breadth(doc, max_breadth)` returns error or None
- [x] 2.3 Create `src/araxys/graphql/cost.py` — `CostVisitor` summing `default_field_cost` + `field_costs` overrides per field; `validate_cost(doc, max_cost, field_costs, default)` returns error or None
- [x] 2.4 Create `src/araxys/graphql/introspection.py` — `has_introspection(doc) → bool` checking AST for `__schema`/`__type`/`__typename`

## Phase 3: ASGI Middleware Wiring

- [x] 3.1 Create `src/araxys/graphql/middleware.py` — `GraphQLSecurityMiddleware(BaseHTTPMiddleware).dispatch()`: path check → read body → parse JSON query → lazy-import graphql → parse AST → run 4 validators → `JSONResponse(200, {"errors":[...]})` on failure → `request._body = body` → `call_next`
- [x] 3.2 Add `_get_graphql()` lazy import raising `ImportError("pip install araxys[graphql]")` when graphql-core missing

## Phase 4: Strawberry Extension (Optional)

- [x] 4.1 Create `src/araxys/graphql/extensions/strawberry.py` — `GraphQLSecurityExtension(SchemaExtension).on_operation()` validates already-parsed document using same visitor functions from Phase 2

## Phase 5: Shield Registration + Public API

- [x] 5.1 Create `src/araxys/graphql/__init__.py` — export: `GraphQLSecurityConfig`, `GraphQLSecurityMiddleware`, `DepthVisitor`, `BreadthVisitor`, `CostVisitor`, `has_introspection`, `validate_query`
- [x] 5.2 Add `_register_graphql(self, app, config)` to `src/araxys/shield.py` (after `_register_malware`); guard: `if not config.graphql_security or not config.graphql_security.enabled: return`
- [x] 5.3 Call `self._register_graphql(app, config)` between `_register_malware` and `_register_honeypot`
- [x] 5.4 Export `GraphQLSecurityConfig`, `GraphQLSecurityMiddleware` from `src/araxys/__init__.py`

## Phase 6: Testing

- [x] 6.1 `tests/graphql/test_depth.py` — deep nesting: assert depth calc correct; reject > max_depth
- [x] 6.2 `tests/graphql/test_breadth.py` — alias batching (60 aliases): assert breadth per set; reject > max_breadth
- [x] 6.3 `tests/graphql/test_cost.py` — default + overrides sum; reject > max_cost
- [x] 6.4 `tests/graphql/test_introspection.py` — `__schema`/`__type` → True; normal queries → False
- [x] 6.5 `tests/graphql/test_middleware.py` — `httpx.ASGITransport` e2e: valid passes, deep/cost/introspection → 200 + `errors` array; body re-injection enables downstream `request.json()`
- [x] 6.6 `tests/graphql/test_strawberry.py` — extension instantiates without error when strawberry-graphql installed
- [x] 6.7 Run `uv run pytest` — all existing tests pass (no regression)
