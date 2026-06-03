"""GraphQL security middleware — depth, breadth, cost, and introspection enforcement.

Intercepts requests to the configured GraphQL endpoint and validates
queries before they reach the application layer.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from araxys.graphql.config import GraphQLSecurityConfig
    from araxys.webhooks.emitter import SecurityEventBus

logger = logging.getLogger("araxys.graphql")

# Module-level event bus reference — set by AraxysShield during wiring.
_event_bus: SecurityEventBus | None = None


class GraphQLSecurityMiddleware:
    """ASGI middleware that enforces GraphQL query limits.

    Validates operations against configured limits: depth, breadth,
    cost, and introspection control. Violations return HTTP 200 with
    a GraphQL error response (matching GraphQL spec convention).

    Parse errors (malformed queries) return HTTP 400.

    Parameters
    ----------
    app:
        The inner ASGI application.
    config:
        GraphQL security configuration.
    """

    _MAX_BODY_BYTES: int = 1_048_576  # 1 MB

    def __init__(self, app: ASGIApp, config: GraphQLSecurityConfig) -> None:
        self.app = app
        self._config = config
        self._path: str = config.graphql_path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if not path.startswith(self._path):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        if method not in ("POST", "PUT"):
            await self.app(scope, receive, send)
            return

        # Read the request body
        body = b""
        more_body = True
        messages: list[Message] = []
        while more_body:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body += message.get("body", b"")
                more_body = message.get("more_body", False)
                if len(body) > self._MAX_BODY_BYTES:
                    response = JSONResponse(
                        {"error": "Request body too large (max 1 MB)"},
                        status_code=400,
                    )
                    await response(scope, receive, send)
                    return

        # Parse JSON body
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            response = JSONResponse(
                {"error": "Invalid JSON in request body"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        query_str: str | None = payload.get("query")
        if not query_str:
            # No query field — pass through
            await self._replay_and_dispatch(scope, messages, send)
            return

        # Parse the GraphQL query
        try:
            from graphql.language import parse

            document = parse(query_str)
        except Exception:
            response = JSONResponse(
                {"error": "Invalid GraphQL query syntax"},
                status_code=400,
            )
            await response(scope, receive, send)
            return

        # ── Validation pipeline (short-circuits on first violation) ────

        # 1. Depth check
        depth = _query_depth(document)
        if depth > self._config.depth_limit:
            msg = f"Query depth {depth} exceeds limit {self._config.depth_limit}"
            await self._send_graphql_error(send, msg)
            await self._emit_event("graphql_blocked", msg, depth=depth)
            return

        # 2. Breadth check
        breadth = _query_breadth(document)
        if breadth > self._config.breadth_limit:
            msg = (
                f"Query breadth {breadth} exceeds limit "
                f"{self._config.breadth_limit}"
            )
            await self._send_graphql_error(send, msg)
            await self._emit_event("graphql_blocked", msg, breadth=breadth)
            return

        # 3. Cost check
        cost = _calculate_cost(document)
        if cost > self._config.cost_limit:
            msg = f"Query cost {cost:.1f} exceeds limit {self._config.cost_limit}"
            await self._send_graphql_error(send, msg)
            await self._emit_event("graphql_blocked", msg, cost=cost)
            return

        # 4. Introspection check
        if not self._config.introspection_enabled and _is_introspection(document):
            msg = "Introspection queries are disabled"
            await self._send_graphql_error(send, msg)
            await self._emit_event("graphql_blocked", msg)
            return

        # All valid — pass through
        await self._replay_and_dispatch(scope, messages, send)

    async def _replay_and_dispatch(
        self, scope: Scope, messages: list[Message], send: Send
    ) -> None:
        """Replay captured messages and dispatch to the inner app."""
        idx = 0

        async def _receive() -> Message:
            nonlocal idx
            if idx < len(messages):
                msg = messages[idx]
                idx += 1
                return msg
            return {"type": "http.disconnect"}

        await self.app(scope, _receive, send)

    async def _send_graphql_error(self, send: Send, message: str) -> None:
        response = JSONResponse(
            {"errors": [{"message": message}]},
            status_code=200,
        )
        await response(
            {"type": "http", "method": "POST", "path": "/", "headers": []},
            _empty_receive,
            send,
        )

    async def _emit_event(self, event_type: str, message: str, **meta: object) -> None:
        if _event_bus is not None:
            from araxys.core.types import SecurityEvent, SecurityEventType

            try:
                evt_type = SecurityEventType(event_type)
            except ValueError:
                evt_type = SecurityEventType.GRAPHQL_BLOCKED
            event = SecurityEvent(
                event_type=evt_type,
                severity="warning",
                message=message,
                metadata=meta,
            )
            await _event_bus.emit(event)


async def _empty_receive() -> Message:
    return {"type": "http.disconnect"}


def _calculate_cost(document: Any) -> float:
    """Calculate query cost using graphql-core AST."""
    from araxys.graphql.cost import calculate_cost

    return calculate_cost(document)


# ── GraphQL document analysis helpers ──────────────────────────────────


def _query_depth(document: Any) -> int:
    """Calculate the maximum nesting depth of a GraphQL document."""
    from graphql.language import (
        FragmentDefinitionNode,
        OperationDefinitionNode,
    )

    fragments: dict[str, Any] = {}
    for definition in getattr(document, "definitions", []):
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition

    max_depth = 0
    for definition in getattr(document, "definitions", []):
        if isinstance(definition, OperationDefinitionNode):
            depth = _calc_depth(
                definition.selection_set, fragments, current=1
            )
            max_depth = max(max_depth, depth)

    return max_depth


def _calc_depth(
    selection_set: Any,
    fragments: dict[str, Any],
    current: int = 1,
) -> int:
    """Recursively calculate depth of a selection set."""
    from graphql.language import FieldNode, FragmentSpreadNode, InlineFragmentNode

    if selection_set is None:
        return current

    max_child = current
    for sel in getattr(selection_set, "selections", []):
        if isinstance(sel, FieldNode):
            if sel.selection_set:
                child_depth = _calc_depth(
                    sel.selection_set, fragments, current + 1
                )
                max_child = max(max_child, child_depth)
        elif isinstance(sel, FragmentSpreadNode):
            frag = fragments.get(sel.name.value)
            if frag and frag.selection_set:
                child_depth = _calc_depth(
                    frag.selection_set, fragments, current + 1
                )
                max_child = max(max_child, child_depth)
        elif isinstance(sel, InlineFragmentNode) and sel.selection_set:
            child_depth = _calc_depth(
                sel.selection_set, fragments, current + 1
            )
            max_child = max(max_child, child_depth)
    return max_child


def _query_breadth(document: Any) -> int:
    """Calculate the maximum selection set breadth of a GraphQL document."""
    from graphql.language import (
        FragmentDefinitionNode,
        OperationDefinitionNode,
    )

    fragments: dict[str, Any] = {}
    for definition in getattr(document, "definitions", []):
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition

    max_breadth = 0
    for definition in getattr(document, "definitions", []):
        if isinstance(definition, OperationDefinitionNode):
            breadth = _calc_breadth(definition.selection_set, fragments)
            max_breadth = max(max_breadth, breadth)

    return max_breadth


def _calc_breadth(
    selection_set: Any,
    fragments: dict[str, Any],
) -> int:
    """Recursively calculate max breadth of a selection set."""
    from graphql.language import FragmentSpreadNode, InlineFragmentNode

    if selection_set is None:
        return 0

    current = len(selection_set.selections)
    max_child = 0
    for sel in selection_set.selections:
        if hasattr(sel, "selection_set") and sel.selection_set:
            child_breadth = _calc_breadth(sel.selection_set, fragments)
            max_child = max(max_child, child_breadth)
        elif isinstance(sel, FragmentSpreadNode):
            frag = fragments.get(sel.name.value)
            if frag and frag.selection_set:
                child_breadth = _calc_breadth(frag.selection_set, fragments)
                max_child = max(max_child, child_breadth)
        elif isinstance(sel, InlineFragmentNode):
            if sel.selection_set:
                child_breadth = _calc_breadth(sel.selection_set, fragments)
                max_child = max(max_child, child_breadth)
    return max(current, max_child)


def _is_introspection(document: Any) -> bool:
    """Check if the document contains introspection fields."""
    from graphql.language import FieldNode

    for definition in getattr(document, "definitions", []):
        if hasattr(definition, "selection_set"):
            for sel in _iter_fields(definition.selection_set):
                if isinstance(sel, FieldNode) and sel.name.value.startswith("__"):  # noqa: SIM102
                    return True
    return False


def _iter_fields(selection_set: Any) -> Any:
    """Iterate over all field selections in a selection set recursively."""
    from graphql.language import FieldNode, InlineFragmentNode

    if selection_set is None:
        return
    for sel in selection_set.selections:
        if isinstance(sel, FieldNode):
            yield sel
            if sel.selection_set:
                yield from _iter_fields(sel.selection_set)
        elif isinstance(sel, InlineFragmentNode):
            if sel.selection_set:
                yield from _iter_fields(sel.selection_set)
