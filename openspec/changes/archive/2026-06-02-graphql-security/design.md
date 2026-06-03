# Design: GraphQL Security

## Technical Approach

ASGI `BaseHTTPMiddleware` intercepting POST to `/graphql`, parsing the JSON body's `query` field via `graphql-core>=3.2` AST, and running four validators: depth, breadth, cost, and introspection. Follows the sanitize middleware's body-reinjection pattern exactly (`request._body = body`). graphql-core is lazy-imported with `ImportError` → install hint. Optional `StrawberrySchemaExtension` available when `strawberry-graphql` is installed.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| HTTP status for rejections | **200** with `{"errors": [...]}` | GraphQL spec treats all responses as 200; clients inspect `errors` not status codes |
| Parser per request | **Re-parse in middleware** | graphql-core parsing is ~1ms; avoids serializing AST through request state; Strawberry extension skips this entirely |
| Visitor base class | **`graphql.Visitor`** with enter/leave hooks | Native graphql-core API; no custom tree walker needed |
| Body re-injection | **`request._body = body`** (same as sanitize) | Proven; downstream FastAPI reads `request._body` when calling `request.body()` again |

## Data Flow

```
POST /graphql → Middleware.dispatch()
    │
    ├─ Path check: request.url.path != "/graphql"? → call_next (skip)
    │
    ├─ Read body: body = await request.body()
    ├─ Parse JSON: data = json.loads(body)
    ├─ Extract: query_str = data.get("query", "")
    │
    ├─ Lazy import: graphql = _get_graphql_module()
    ├─ PARSE: doc = graphql.parse(query_str)
    │
    ├─ VISITOR 1: DepthVisitor.visit(doc) → reject if > max_depth
    ├─ VISITOR 2: BreadthVisitor.visit(doc) → reject if > max_breadth
    ├─ VISITOR 3: CostVisitor.visit(doc) → reject if > max_cost
    ├─ VISITOR 4: Introspection check → reject if __schema/__type present
    │
    ├─ RE-INJECT: request._body = body
    └─ call_next(request)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/araxys/graphql/__init__.py` | Create | Public API: `GraphQLSecurityConfig`, `GraphQLSecurityMiddleware`, `DepthVisitor`, `BreadthVisitor`, `CostVisitor`, `validate_query` |
| `src/araxys/graphql/config.py` | Create | `GraphQLSecurityConfig(BaseModel)` — `enabled`, `graphql_path`, `max_depth`(8), `max_breadth`(50), `max_cost`(1000), `default_field_cost`(1), `field_costs`, `disable_introspection`, `exclude_paths` |
| `src/araxys/graphql/middleware.py` | Create | `GraphQLSecurityMiddleware(BaseHTTPMiddleware)` — `dispatch()` reads body, parses GraphQL, runs 4 validators, re-injects body |
| `src/araxys/graphql/depth.py` | Create | `DepthVisitor(graphql.Visitor)` — `enter_field()`/`leave_field()` track nesting |
| `src/araxys/graphql/breadth.py` | Create | `BreadthVisitor` — `enter_selection_set()` counts `selections` length including aliases |
| `src/araxys/graphql/cost.py` | Create | `CostVisitor` — `enter_field()` sums `default_field_cost`; applies `field_costs` dict overrides by field name |
| `src/araxys/graphql/introspection.py` | Create | `has_introspection(doc) → bool` — checks for `__schema`/`__type`/`__typename` in AST |
| `src/araxys/graphql/extensions/strawberry.py` | Create | `GraphQLSecurityExtension(SchemaExtension)` — `on_operation()` validates without re-parsing |
| `src/araxys/core/config.py` | Modify | Add `GraphQLSecurityConfig` class; add `graphql_security: GraphQLSecurityConfig \| None = None` to `AraxysConfig` |
| `src/araxys/shield.py` | Modify | Add `_register_graphql()` method; call between `_register_malware` and `_register_honeypot` |
| `src/araxys/__init__.py` | Modify | Export `GraphQLSecurityConfig`, `GraphQLSecurityMiddleware`, `DepthVisitor`, `BreadthVisitor`, `CostVisitor`, `validate_query` |
| `pyproject.toml` | Modify | Add `graphql = ["graphql-core>=3.2", "strawberry-graphql>=0.200"]` to optional-dependencies |
| `src/araxys/core/types.py` | Modify | Add `GRAPHQL_BLOCKED = "graphql_blocked"` to `SecurityEventType` enum |

## Interface / Contracts

**Lazy import (follows prompt_injection/files/parsers.py pattern)**:
```python
def _get_graphql():
    try:
        import graphql
        return graphql
    except ImportError:
        raise ImportError("graphql-core is required. pip install araxys[graphql]") from None
```

**Rejection response**:
```python
JSONResponse(status_code=200, content={"errors": [{"message": "Query depth 12 exceeds maximum 8"}]})
```

**Shield registration guard** (follows `_register_malware` pattern):
```python
def _register_graphql(self, app, config):
    if config.graphql_security is None or not config.graphql_security.enabled:
        return
    app.add_middleware(GraphQLSecurityMiddleware, config=config.graphql_security)
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | `DepthVisitor` | Parse query string → visit → assert `max_depth` matches expected |
| Unit | `BreadthVisitor` | Queries with aliases → assert breadth counts aliases as separate fields |
| Unit | `CostVisitor` | Default cost + `field_costs` overrides → assert correct sum |
| Unit | `has_introspection()` | Queries with `__schema`/`__type` → assert `True` |
| Integration | Middleware e2e | `httpx.ASGITransport` against FastAPI app with `/graphql` route — valid query passes, deep query rejected, cost query rejected |
| Integration | Body re-injection | After middleware, downstream handler can call `await request.json()` successfully |
| Smoke | Strawberry extension | When `strawberry-graphql` installed, extension instantiates without error (conditional import test) |

## Open Questions

- [ ] Should `graphql-core` be a hard dependency or optional extra? (Proposal says optional extra — confirm)
- [ ] Strawberry extension: `on_operation` receives `ExecutionContext` — verify `execution_context.graphql_document` provides the AST at the point we intercept
