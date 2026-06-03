"""Strawberry GraphQL extension for query validation.

Provides a Strawberry :class:`SchemaExtension` that validates operations
against configured depth, breadth, cost, and introspection limits without
re-parsing the document.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from araxys.graphql.cost import calculate_cost

if TYPE_CHECKING:
    from araxys.graphql.config import GraphQLSecurityConfig

logger = logging.getLogger("araxys.graphql")


class GraphQLSecurityExtension:
    """Strawberry extension that validates GraphQL operations.

    Validates depth, breadth, cost, and introspection on every operation
    using the already-parsed document provided by Strawberry.

    Usage::

        import strawberry
        from araxys.graphql.extensions.strawberry import GraphQLSecurityExtension

        schema = strawberry.Schema(
            query=Query,
            extensions=[
                GraphQLSecurityExtension(config),
            ],
        )
    """

    def __init__(self, config: GraphQLSecurityConfig) -> None:
        self._config = config

    def on_operation(self) -> None:
        """Called before operation execution.

        Validates the operation against configured limits. Raises a
        GraphQL error (which Strawberry catches and adds to the response
        errors list) on violation.
        """
        import inspect

        import graphql

        # Access the operation context via Strawberry's execution context
        frame = inspect.currentframe()
        if frame is None:
            return

        try:
            # Walk up the call stack to find the operation
            f: Any = frame.f_back
            while f is not None:
                operation = f.f_locals.get("operation")
                if operation is not None and hasattr(operation, "document"):
                    break
                f = f.f_back
            else:
                return

            document = operation.document

            # Depth check
            from araxys.graphql.middleware import (
                _is_introspection,
                _query_breadth,
                _query_depth,
            )

            depth = _query_depth(document)
            if depth > self._config.depth_limit:
                raise graphql.GraphQLError(
                    f"Query depth {depth} exceeds limit "
                    f"{self._config.depth_limit}"
                )

            # Breadth check
            breadth = _query_breadth(document)
            if breadth > self._config.breadth_limit:
                raise graphql.GraphQLError(
                    f"Query breadth {breadth} exceeds limit "
                    f"{self._config.breadth_limit}"
                )

            # Cost check
            cost = calculate_cost(document)
            if cost > self._config.cost_limit:
                raise graphql.GraphQLError(
                    f"Query cost {cost:.1f} exceeds limit "
                    f"{self._config.cost_limit}"
                )

            # Introspection check
            if not self._config.introspection_enabled and _is_introspection(
                document
            ):
                raise graphql.GraphQLError(
                    "Introspection queries are disabled"
                )

        finally:
            del frame
