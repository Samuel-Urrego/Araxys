# graphql-security Specification

## Purpose

ASGI middleware and configurable validators protecting GraphQL endpoints from depth/breadth/cost denial-of-service, alias-based batching, and introspection abuse. Uses graphql-core AST analysis with an optional Strawberry extension for schema-aware cost estimation without re-parsing.

## Requirements

### Requirement: Query Depth Limiting

The system MUST parse incoming GraphQL query strings into an AST and calculate maximum nesting depth of field selections. Queries exceeding `max_depth` (default 8) MUST be rejected with a GraphQL-compatible error.

#### Scenario: Deeply nested query rejected
- GIVEN `max_depth` is configured to 8
- WHEN a POST arrives with a query nested 12 levels deep
- THEN the system returns HTTP 200 with `[{"message": "Query depth 12 exceeds maximum 8"}]`

### Requirement: Query Breadth Limiting

The system MUST calculate the maximum number of sibling fields at any single selection set level. Aliases MUST count as separate fields to defend against alias-based batching attacks. Queries exceeding `max_breadth` (default 50) MUST be rejected.

#### Scenario: Alias-based batching blocked
- GIVEN `max_breadth` is configured to 50
- WHEN a query uses 60 aliased fields on the same object in a single selection set
- THEN the system rejects with error stating breadth 60 exceeds maximum 50

### Requirement: Query Cost Analysis

The system MUST calculate estimated query cost by summing per-field weights and MUST reject queries exceeding `max_cost` (default 1000). It SHOULD support per-field cost overrides via the `field_costs` configuration dict. The Strawberry extension MAY provide schema-aware cost estimation by accessing field resolver metadata.

#### Scenario: Expensive query rejected
- GIVEN `max_cost` is 1000 and `field_costs={"expensiveField": 500}`
- WHEN a query selects `expensiveField` three times (total cost 1500)
- THEN the system rejects with error stating cost 1500 exceeds maximum 1000

### Requirement: Introspection Blocking

When `disable_introspection` is True (default), the system MUST detect `__schema`, `__type`, or `__typename` fields at the AST level and MUST reject requests containing them.

#### Scenario: Schema introspection blocked
- GIVEN `disable_introspection` is True
- WHEN a POST arrives with `query { __schema { types { name } } }`
- THEN the system returns a GraphQL error: introspection is disabled

### Requirement: ASGI Middleware Interception

The system MUST provide an ASGI middleware that intercepts POST requests to the configured `graphql_path` (default `/graphql`), reads the body for validation, and re-injects it into the request scope using the same pattern as the sanitize middleware. It SHOULD support an `exclude_paths` configuration list. It MUST raise a clear error if `graphql-core` is not installed.

#### Scenario: Middleware validates and forwards query
- GIVEN middleware is enabled with `graphql_path="/graphql"`
- WHEN a POST to `/graphql` contains a valid query within all limits
- THEN the body is re-injected into scope and the request continues to the GraphQL handler unchanged

### Requirement: Strawberry Extension (Optional)

The system SHOULD provide a `SchemaExtension` for Strawberry users that hooks into `on_operation` for resolver-level validation without re-parsing the document. It MUST be optional — loaded only when Strawberry is installed.

#### Scenario: Extension integrates with execution pipeline
- GIVEN `strawberry-graphql` is installed and the extension is registered on the schema
- WHEN a GraphQL operation executes via Strawberry
- THEN the extension receives the already-parsed document and validates it against configured depth, breadth, cost, and introspection limits

### Requirement: Runtime Configuration

All security checks MUST be independently togglable via `GraphQLSecurityConfig` fields: `enabled`, `graphql_path`, `max_depth`, `max_breadth`, `max_cost`, `disable_introspection`, `exclude_paths`, and `field_costs`. When `enabled` is False, zero validation code MUST execute.

#### Scenario: Disabled middleware passes all queries
- GIVEN `GraphQLSecurityConfig(enabled=False)`
- WHEN any query is POSTed to `/graphql`
- THEN no validation occurs and the request passes through unchanged
