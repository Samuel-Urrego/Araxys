"""GraphQL query cost calculation using graphql-core AST traversal.

Cost is estimated by summing weighted field selections, taking into
account connection/list fields with multipliers.
"""

from __future__ import annotations

from typing import Any


def calculate_cost(
    document: Any,
    *,
    default_weight: float = 1.0,
    connection_weight: float = 5.0,
    list_weight: float = 2.0,
    depth_multiplier: float = 1.5,
) -> float:
    """Calculate the estimated cost of a GraphQL document.

    Parameters
    ----------
    document:
        Parsed GraphQL document node.
    default_weight:
        Base cost per scalar/enum field.
    connection_weight:
        Cost for list/connection fields (often paginated).
    list_weight:
        Cost multiplier per list field.
    depth_multiplier:
        Exponential multiplier per depth level.

    Returns
    -------
    float
        Total estimated cost.
    """
    from graphql.language import (
        FragmentDefinitionNode,
        OperationDefinitionNode,
    )

    fragments: dict[str, Any] = {}
    total: float = 0.0

    for definition in document.definitions:
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition
        elif isinstance(definition, OperationDefinitionNode):
            total += _cost_for_operation(
                definition,
                fragments,
                default_weight=default_weight,
                connection_weight=connection_weight,
                list_weight=list_weight,
                depth_multiplier=depth_multiplier,
            )

    return total


_FIELD_NAME_WEIGHTS: dict[str, float] = {
    "edges": 5.0,
    "node": 2.0,
    "nodes": 5.0,
    "items": 5.0,
    "results": 5.0,
    "data": 2.0,
}


def _cost_for_operation(
    op: Any,
    fragments: dict[str, Any],
    *,
    default_weight: float,
    connection_weight: float,
    list_weight: float,
    depth_multiplier: float,
    depth: int = 0,
) -> float:
    cost: float = 0.0
    multiplier = depth_multiplier**depth

    if op.selection_set:
        cost += _cost_for_selection_set(
            op.selection_set,
            fragments,
            default_weight=default_weight,
            connection_weight=connection_weight,
            list_weight=list_weight,
            depth_multiplier=depth_multiplier,
            depth=depth,
        )

    return cost * multiplier


def _cost_for_selection_set(
    selection_set: Any,
    fragments: dict[str, Any],
    *,
    default_weight: float,
    connection_weight: float,
    list_weight: float,
    depth_multiplier: float,
    depth: int,
) -> float:
    from graphql.language import (
        FieldNode,
        FragmentSpreadNode,
        InlineFragmentNode,
    )

    cost: float = 0.0

    for selection in selection_set.selections:
        if isinstance(selection, FieldNode):
            field_cost = _field_cost(selection, default_weight, connection_weight)
            if selection.selection_set:
                field_cost += _cost_for_selection_set(
                    selection.selection_set,
                    fragments,
                    default_weight=default_weight,
                    connection_weight=connection_weight,
                    list_weight=list_weight,
                    depth_multiplier=depth_multiplier,
                    depth=depth + 1,
                )
            cost += field_cost
        elif isinstance(selection, FragmentSpreadNode):
            frag = fragments.get(selection.name.value)
            if frag and frag.selection_set:
                cost += _cost_for_selection_set(
                    frag.selection_set,
                    fragments,
                    default_weight=default_weight,
                    connection_weight=connection_weight,
                    list_weight=list_weight,
                    depth_multiplier=depth_multiplier,
                    depth=depth,
                )
        elif isinstance(selection, InlineFragmentNode):
            if selection.selection_set:
                cost += _cost_for_selection_set(
                    selection.selection_set,
                    fragments,
                    default_weight=default_weight,
                    connection_weight=connection_weight,
                    list_weight=list_weight,
                    depth_multiplier=depth_multiplier,
                    depth=depth,
                )

    return cost


def _field_cost(
    field: Any,
    default_weight: float,
    connection_weight: float,
) -> float:
    name = field.name.value
    if name in _FIELD_NAME_WEIGHTS:
        return _FIELD_NAME_WEIGHTS[name]
    # Arguments add cost
    arg_cost = len(field.arguments or []) * 0.5
    return default_weight + arg_cost
