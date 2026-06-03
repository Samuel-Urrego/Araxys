## Exploration: graphql-security

### Current State

Araxys v0.13 is a mature security library with 30+ modules and 1833 passing tests. It uses a layered ASGI middleware architecture orchestrated by `AraxysShield` (in `src/araxys/shield.py`), where middlewares are registered in explicit reverse order (innermost → outermost):

```
Sanitize → XXE → PromptInjection → Malware → Honeypot → AccountProtection →
IP Access → BruteForce → RateLimit → CSRF → Telemetry → SecureHeaders → CORS
```

**Every security module follows the same pattern:**
- A `BaseModel` config class in `src/araxys/core/config.py`
- A `BaseHTTPMiddleware` subclass (e.g., `RateLimitMiddleware`, `SanitizeMiddleware`)
- Registration in `shield.py` via `_register_<module>()` method with `enabled` guard
- Public API exported from `src/araxys/__init__.py`

**No GraphQL code exists anywhere in Araxys** — zero references to `strawberry`, `ariadne`, or `graphql-core` across the entire codebase.

**Key middleware patterns relevant to GraphQL:**

| Module | How it inspects requests | What we can learn |
|--------|-------------------------|-------------------|
| `rate_limit` | Reads path + method + IP; counts requests per key in backend | Per-operation-type limiting maps directly to operation-level counting |
| `sanitize` | Reads `request.body()`, parses JSON, recursively walks payload | Body-reading pattern for intercepting GraphQL POST bodies |
| `prompt_injection` | Scans query params and JSON body leaf strings | Text-scanning approach for query content validation |
| `malware` | Scans multipart file uploads | Modular design with per-detector toggles — pattern for enabling/disabling GraphQL defenses independently |

**Existing optional dependency pattern** (from `src/araxys/prompt_injection/files/parsers.py`):
- Uses `importlib.import_module()` for lazy loading
- Returns `None` with a warning when optional dep is missing
- Install hints point users to extras: `pip install araxys[prompt-guard-image]`
- Registered in `pyproject.toml` under `[project.optional-dependencies]`

**Test pattern** (from `tests/conftest.py`):
- `FastAPI` app created via fixture
- `httpx.ASGITransport` + `AsyncClient` for integration testing
- Tests exercise middleware via real HTTP requests through the ASGI pipeline
- Unit tests for core logic (e.g., `RateLimiter.check()`) use in-memory backends directly

---

### Affected Areas

| File/Module | Why Affected |
|-------------|-------------|
| `src/araxys/core/config.py` | New `GraphQLSecurityConfig` BaseModel subclass |
| `src/araxys/shield.py` | New `_register_graphql()` method for middleware registration |
| `src/araxys/__init__.py` | Export new public API symbols |
| `src/araxys/core/exceptions.py` | New `GraphQLSecurityError` or generic GraphQL validation error |
| `src/araxys/core/types.py` | New `SecurityEventType` entries (e.g., `GRAPHQL_DEPTH_EXCEEDED`, `GRAPHQL_INTROSPECTION_BLOCKED`) |
| `pyproject.toml` | New optional dependency extra: `graphql = ["graphql-core>=3.3"]` |
| `tests/` | New `test_graphql.py` test file (~20-30 test cases) |

**New module structure** (`src/araxys/graphql/`):
```
src/araxys/graphql/
├── __init__.py              # Public API exports
├── config.py                # GraphQLSecurityConfig (or inline in core/config.py)
├── middleware.py             # BaseHTTPMiddleware for ASGI-level interception
├── parser.py                # Query parsing: extracts operation info from GraphQL doc
├── depth.py                 # Query depth calculator (AST visitor)
├── breadth.py               # Field breadth calculator (AST visitor)
├── cost.py                  # Field cost analyzer (AST visitor)
├── extensions/              # Library-specific extensions (optional)
│   └── strawberry.py        # Strawberry SchemaExtension for deep integration
└── persisted.py             # Persisted query whitelist manager (optional)
```

---

### GraphQL Libraries in the FastAPI Ecosystem

| Library | Approach | FastAPI Integration | Popularity |
|---------|----------|-------------------|------------|
| **Strawberry** | Code-first (typed) | `strawberry.fastapi.GraphQLRouter` as APIRouter sub-app | Most popular in Python ecosystem |
| **Ariadne** | Schema-first (SDL) | `ariadne.asgi.GraphQL` as ASGI app mounted | Second most popular |
| **graphql-core** | Low-level engine | Raw ASGI handler (rare in production) | Underlying engine for both above |
| **Graphene** | Code-first | Via Starlette/ASGI adapter | Legacy, losing momentum |

**All three depend on `graphql-core>=3.2`** as the underlying GraphQL engine. graphql-core is the Python port of `graphql-js` and provides:
- `parse(query_string)` → `DocumentNode` AST
- `validate(schema, document)` → list of `GraphQLError`
- `visit(root, visitor)` → AST traversal
- `specified_rules` → standard GraphQL validation rules

**Strawberry** is the recommended primary target because:
- It is the most popular FastAPI GraphQL integration
- It has a built-in `SchemaExtension` system (equivalent to middleware at the GraphQL level)
- It provides `QueryDepthLimiter` and `DisableIntrospection` extensions out-of-the-box (but these don't include cost analysis or batching defense)
- Araxys can provide a **superset** of Strawberry's built-in security with additional features

**Ariadne** is the secondary target because:
- It uses an `Extension` class with lifecycle hooks (`request_started`, `request_finished`, `resolve`, `has_errors`)
- It exposes middleware via the `middleware` parameter (list of callables)
- Its extension API is more primitive than Strawberry's but still workable

---

### GraphQL Attack Vectors and Defense Approaches

| Attack Vector | Description | Defense | Araxys Implementation |
|---------------|-------------|---------|----------------------|
| **Depth attacks** | Nested queries that explode in resolution (e.g., `{ a { b { c { ... } } } }`) | AST walker counting max nesting | `depth.py` — `DepthVisitor(graphql.Visitor)` |
| **Breadth attacks** | Many sibling fields at one level (e.g., 1000 fields on a single type) | AST walker counting max fields per selection set | `breadth.py` — `BreadthVisitor` |
| **Alias-based batching** | Same field aliased N times to bypass rate limits (e.g., `{ a1: user(id:1), a2: user(id:2), ... }`) | Count unique aliases + total selections | Integrated into breadth check |
| **Cost analysis** | Complex queries that are cheap to send but expensive to resolve | Field-level cost weighting via config | `cost.py` — `CostVisitor` with configurable costs |
| **Introspection abuse** | Attacker maps the entire schema to find sensitive fields | Block `__schema`, `__type` at the GraphQL level | Blocked before parsing, or via `DisableIntrospection`-equivalent |
| **Persisted queries** | Only allow pre-registered query hashes | Hash whitelist check before execution | `persisted.py` — SHA-256 hash store |
| **Resolver-level auth** | Unauthorized access to specific fields | This is app-level — Araxys provides middleware to help, not resolver logic | Documentation + optional dependency |
| **Batching/multiplexing** | Multiple queries in one HTTP request | Limit operations per request | Config: `max_operations_per_request` |

**Key insight**: All these defenses (except persisted queries and introspection blocking) operate on the **parsed GraphQL AST**, not on the raw HTTP request. This means Araxys needs access to `graphql.parse()` to walk the AST before the query reaches the GraphQL server.

---

### Approaches

#### Approach 1 — Pure ASGI Middleware (library-agnostic)

**How it works**: An ASGI middleware (`BaseHTTPMiddleware`) intercepts `POST /graphql` (configurable path), reads the body, parses it as JSON, extracts the `query` field, calls `graphql.parse(query)` to get the AST, then runs depth/breadth/cost visitors. Returns `400 Bad Request` with a detailed GraphQL error response if any check fails.

```python
class GraphQLSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path != self._config.graphql_path:
            return await call_next(request)
        body = await request.body()
        payload = json.loads(body)
        query_str = payload.get("query", "")
        
        try:
            doc = graphql.parse(query_str)
        except graphql.GraphQLError:
            return JSONResponse(400, {"errors": [{"message": "Invalid GraphQL query"}]})
        
        if self._config.disable_introspection:
            if has_introspection(doc):
                return JSONResponse(400, {"errors": [{"message": "Introspection disabled"}]})
        
        depth = calculate_depth(doc)
        if depth > self._config.max_depth:
            return JSONResponse(400, {"errors": [{"message": f"Depth {depth} exceeds max {self._config.max_depth}"}]})
        
        return await call_next(request)
```

| Pros | Cons | Complexity |
|------|------|------------|
| Works with ANY GraphQL library (Strawberry, Ariadne, raw graphql-core) | Must re-parse the query (Strawberry/Ariadne will parse it again) | Low-Medium |
| Same middleware pattern as existing modules | Cannot access resolver-level context (no auth integration) | |
| Easy to test with httpx + ASGI transport | No visibility into operation execution — pure AST analysis | |
| graphql-core is a lightweight pure-Python dependency | Body read consumes the request — must re-inject it (same pattern as `sanitize`) | |
| Single integration point in `shield.py` | | |

#### Approach 2 — Strawberry Extension + ASGI Fallback (hybrid, recommended)

**How it works**: Two layers of defense:
1. **Strawberry Extension** (`GraphQLSecurityExtension`) — deep integration via `SchemaExtension.on_operation()`. Runs BEFORE resolvers execute, has access to `execution_context`, can modify errors. Best for Strawberry users who get cost analysis + resolver-level awareness.
2. **ASGI Middleware** (`GraphQLSecurityMiddleware`) — library-agnostic fallback for non-Strawberry users and for checks that must happen before the GraphQL engine even parses (e.g., body size limit, raw introspection blocking via regex pre-check).

```python
# Strawberry extension — for Strawberry users
class GraphQLSecurityExtension(SchemaExtension):
    def on_operation(self):
        # Access parsed document via self.execution_context
        doc = self.execution_context.query.document
        depth = calculate_depth(doc)
        if depth > self.execution_context.context.get("araxys_max_depth", 8):
            raise GraphQLSecurityError("Query depth exceeded")
        yield  # Execute resolvers
        
# ASGI middleware — for everyone else
class GraphQLSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Pre-parse checks (body size, introspection regex, etc.)
        # Delegate to library-specific extensions when detected
        ...
```

| Pros | Cons | Complexity |
|------|------|------------|
| Deepest integration for Strawberry (most popular) | Two code paths to maintain | Medium |
| Resolver-level context available in Strawberry extension | Strawberry extension is Strawberry-specific | |
| ASGI fallback covers Ariadne and custom setups | Need to detect which library is in use (or let user configure) | |
| Strawberry users get cost analysis + per-field limiting | | |
| Follows the "extensions" pattern Strawberry users already know | | |

#### Approach 3 — Standalone Query Validator (no middleware)

**How it works**: Expose pure functions that users call manually in their resolvers or as dependency functions. No automatic interception.

```python
from araxys.graphql import validate_graphql_query, GraphQLSecurityConfig

config = GraphQLSecurityConfig(max_depth=8, max_cost=1000)
errors = validate_graphql_query(query_string, config)
if errors:
    return {"errors": errors}
```

| Pros | Cons | Complexity |
|------|------|------------|
| Zero middleware overhead | User must remember to call it on every endpoint | Low |
| Maximum flexibility | Error-prone — easy to forget | |
| No body-reading issues | Unlike all other Araxys modules (which are automatic) | |
| | Inconsistent with Araxys "plug & play" philosophy | |

---

### Recommendation

**Approach 2 — Hybrid (Strawberry Extension + ASGI Middleware)** with the following implementation strategy:

1. **`graphql-core>=3.2` as optional dependency** under extra `araxys[graphql]`. Lazy-imported at runtime with clear install hints. graphql-core is 100% pure Python, ~160KB, zero native dependencies — lightweight enough to be a soft dependency.

2. **Core AST analysis functions** (`parser.py`, `depth.py`, `breadth.py`, `cost.py`) are library-agnostic. They take a `graphql.DocumentNode` and return metrics. This is the shared logic between both integration paths.

3. **ASGI middleware** (`GraphQLSecurityMiddleware`) is the PRIMARY integration for most users. It follows the exact same pattern as `SanitizeMiddleware` and `RateLimitMiddleware`:
   - `BaseHTTPMiddleware` subclass
   - Registered via `_register_graphql()` in `shield.py`
   - Intercepts `POST` to configurable path (default: `/graphql`)
   - Reads body → parses JSON → extracts `query` → parses GraphQL → validates → re-injects body (same pattern as `sanitize.middleware._process_json_body`)

4. **Strawberry extension** (`extensions/strawberry.py`) as an OPTIONAL deeper integration. Users who want resolver-level awareness or per-field cost weighting can opt into it. The extension is only compiled/loaded if Strawberry is installed.

5. **Config structure** — a single `GraphQLSecurityConfig` BaseModel:

```python
class GraphQLSecurityConfig(BaseModel):
    enabled: bool = True
    graphql_path: str = "/graphql"
    
    # Depth & breadth
    max_depth: int = 8
    max_breadth: int = 50
    max_aliases: int = 20          # alias-based batching defense
    
    # Cost analysis
    max_cost: int = 1000
    default_field_cost: int = 1
    field_costs: dict[str, int] = Field(default_factory=dict)  # per-type.field costs
    
    # Introspection
    disable_introspection: bool = True
    
    # Persisted queries
    persisted_queries_only: bool = False
    persisted_query_map: dict[str, str] = Field(default_factory=dict)  # hash → query
    
    # Operation limits
    max_operations_per_request: int = 1
    
    # Rate limiting per operation type
    query_rate_limit: RateLimitConfig | None = None
    mutation_rate_limit: RateLimitConfig | None = None
    
    # Excluded paths
    exclude_paths: list[str] = Field(default_factory=list)
```

**Middleware registration order**: GraphQL security should be registered in the SAME position as `sanitize` and `rate_limit` (innermost layer). Since GraphQL requests arrive as HTTP POST with JSON body, they should be validated AFTER sanitization but BEFORE rate limiting. Recommended position: **between `_register_malware` and `_register_honeypot`** (or right after `_register_sanitize` for earliest interception):

```
Sanitize → [GraphQL] → XXE → PromptInjection → Malware → Honeypot → ...
```

This ensures:
- Sanitization runs first (catches SQLi/XSS in the raw body)
- GraphQL validation runs second (parses GraphQL, checks depth/cost)
- Remaining middleware works on already-validated requests

---

### Dependencies Needed

| Dependency | Required For | Already in pyproject.toml? | Type |
|------------|-------------|---------------------------|------|
| `graphql-core>=3.2` | AST parsing, validation, visitor pattern | ❌ No | Optional extra `[graphql]` |
| `strawberry-graphql>=0.200` | Strawberry extension (optional) | ❌ No | NOT a project dependency — user installs separately |
| None (stdlib only) | ASGI middleware, config, AST visitors | ✅ Yes | Core |

**`graphql-core` justification**: graphql-core is the de facto standard Python GraphQL engine. It has:
- Zero native dependencies (pure Python)
- ~5 MB installed, ~160 KB compressed
- Used by Strawberry, Ariadne, Graphene, and virtually every Python GraphQL tool
- Stable API since 3.0 (2018)
- Provides exactly what Araxys needs: `parse()`, `visit()`, `Visitor`, `DocumentNode`, `OperationDefinitionNode`, `FieldNode`

**Optional extra in pyproject.toml**:
```toml
[project.optional-dependencies]
graphql = ["graphql-core>=3.2"]
```

Updated `all` extra:
```toml
all = ["araxys[redis,opentelemetry,prometheus,webhooks,audit,vault,aws_secrets,webauthn,prompt-guard-image,prompt-guard-pdf,prompt-guard-office,xxe,graphql]"]
```

**Lazy import strategy** (consistent with existing `prompt_injection/files/parsers.py`):
```python
def _get_graphql():
    try:
        import graphql
        return graphql
    except ImportError:
        raise ImportError(
            "graphql-core is required for GraphQL security. "
            "Install with: pip install araxys[graphql]"
        ) from None
```

---

### Risks

1. **Body consumption conflict**: GraphQL middleware reads `request.body()` to extract the query, which consumes the stream. The `sanitize` middleware already handles this by injecting `request._body = sanitized_bytes`. GraphQL middleware must do the same — re-inject the body so downstream GraphQL routers (Strawberry's `GraphQLRouter`, Ariadne's `GraphQL` app) can read it. This is a solved pattern (see `sanitize/middleware.py` lines 216-218) but must be tested carefully.

2. **graphql-core version compatibility**: Strawberry, Ariadne, and other libraries pin specific versions of graphql-core. Araxys should pin `graphql-core>=3.2` (the common minimum) but there could be version conflicts if a user has an older pin. Mitigation: document the constraint, test against both major versions.

3. **Performance — re-parsing**: With the ASGI middleware approach, the query is parsed TWICE (once by Araxys for validation, once by the GraphQL server for execution). For most queries this is negligible (< 1ms), but for large persisted queries it could add latency. Mitigation: the Strawberry extension path avoids re-parsing since it hooks into the parsed document directly.

4. **Persisted queries + body re-injection**: If `persisted_queries_only` is enabled and the client sends a hash instead of a query string, the middleware must expand the hash to the full query, validate it, and re-inject the expanded query. This changes the structure of the request body — Strawberry/Ariadne must understand the expanded query body.

5. **Operation type detection**: GraphQL can send multiple operations in one request with an `operationName` field. The middleware must correctly identify which operation to validate (or validate all). This requires proper handling of `operationName` and `document.definitions` filtering.

6. **False positives in cost analysis**: Default field costs can be wrong for the user's schema. A field that returns a list of 1000 items might cost 1 (default) but really costs 1000+ at the resolver level. Mitigation: let users configure per-field costs via `field_costs` dict.

7. **No schema awareness in ASGI middleware**: The ASGI middleware parses the query but does not have access to the GraphQL schema (it would need to know the schema to do proper cost analysis). Only the Strawberry extension has schema access. Mitigation: document this limitation — ASGI middleware provides depth/breadth/alias/introspection checks (which are schema-independent), while cost analysis with per-field weights requires the Strawberry extension or manual config.

---

### Ready for Proposal

**Yes** — the attack vectors are well-understood, the Araxys architecture patterns are thoroughly mapped, and the hybrid approach aligns with existing module design. The implementation is feasible within Araxys v0.14 or v0.15.

**Recommended proposal structure**:
1. **Phase 1**: Core AST analysis functions (`depth.py`, `breadth.py`, `cost.py`) — pure functions, testable in isolation
2. **Phase 2**: ASGI middleware (`GraphQLSecurityMiddleware`) — body interception, depth/breadth/introspection checks
3. **Phase 3**: Strawberry extension (`extensions/strawberry.py`) — deeper integration for Strawberry users
4. **Phase 4**: Persisted queries support, operation-type rate limiting integration
5. Each phase independently testable and shippable

**Key decision for the proposal phase**: Should `graphql-core` be a *hard* dependency of Araxys, or truly optional (lazy-imported only when `GraphQLSecurityConfig` is configured)? Given graphql-core's tiny footprint (pure Python, no native deps), I recommend making it a **soft hard dependency** — included in core deps but lazily imported. This avoids the `ImportError` dance for the most common use case while keeping the core install slim.
