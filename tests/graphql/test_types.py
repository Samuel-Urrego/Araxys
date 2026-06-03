"""Tests for GraphQL config model."""

from araxys.graphql.config import GraphQLSecurityConfig


class TestGraphQLSecurityConfig:
    def test_defaults(self) -> None:
        c = GraphQLSecurityConfig()
        assert c.enabled is True
        assert c.depth_limit == 10
        assert c.breadth_limit == 50
        assert c.cost_limit == 1000.0
        assert c.introspection_enabled is True
        assert c.graphql_path == "/graphql"

    def test_custom_values(self) -> None:
        c = GraphQLSecurityConfig(
            enabled=False,
            depth_limit=5,
            breadth_limit=20,
            cost_limit=500.0,
            introspection_enabled=False,
            graphql_path="/api/graphql",
        )
        assert c.enabled is False
        assert c.depth_limit == 5
        assert c.breadth_limit == 20
        assert c.cost_limit == 500.0
        assert c.introspection_enabled is False
        assert c.graphql_path == "/api/graphql"

    def test_depth_limit_ge_1(self) -> None:
        import pytest

        with pytest.raises(Exception):  # noqa: B017  # noqa: B017
            GraphQLSecurityConfig(depth_limit=0)

    def test_breadth_limit_ge_1(self) -> None:
        import pytest

        with pytest.raises(Exception):  # noqa: B017  # noqa: B017
            GraphQLSecurityConfig(breadth_limit=0)
