"""Tests for GraphQL extensions (Strawberry)."""

import pytest

from araxys.graphql.config import GraphQLSecurityConfig


class TestStrawberryExtension:
    def test_extension_instantiation(self) -> None:
        """Extension can be instantiated with config."""
        config = GraphQLSecurityConfig()
        try:
            from araxys.graphql.extensions.strawberry import (
                GraphQLSecurityExtension,
            )

            ext = GraphQLSecurityExtension(config)
            assert ext is not None
            assert ext._config is config
        except ImportError:
            pytest.skip("strawberry-graphql not installed")

    def test_extension_with_custom_config(self) -> None:
        """Extension respects custom configuration."""
        config = GraphQLSecurityConfig(
            depth_limit=3,
            breadth_limit=10,
            introspection_enabled=False,
        )
        try:
            from araxys.graphql.extensions.strawberry import (
                GraphQLSecurityExtension,
            )

            ext = GraphQLSecurityExtension(config)
            assert ext._config.depth_limit == 3
            assert ext._config.introspection_enabled is False
        except ImportError:
            pytest.skip("strawberry-graphql not installed")
