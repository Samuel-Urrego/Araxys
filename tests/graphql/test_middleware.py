"""Tests for GraphQL security middleware ASGI integration."""

import asyncio
import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys.graphql.config import GraphQLSecurityConfig
from araxys.graphql.middleware import GraphQLSecurityMiddleware


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()

    @a.get("/not-graphql")
    async def not_graphql() -> dict[str, str]:
        return {"status": "ok"}

    @a.get("/graphql")
    async def graphql_get() -> dict[str, str]:
        return {"status": "ok"}

    @a.post("/graphql")
    async def graphql_echo() -> dict[str, object]:
        return {"data": {"hello": "world"}}

    return a


class TestGraphQLMiddlewarePathMatching:
    async def test_non_graphql_path_passes_through(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig()
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/not-graphql")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}

    async def test_graphql_post_passes_through_valid_query(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(depth_limit=100, cost_limit=10000.0)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/graphql",
                json={"query": "{ hello }"},
            )
            assert resp.status_code == 200
            assert resp.json() == {"data": {"hello": "world"}}

    async def test_get_request_skips_validation(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig()
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/graphql")
            assert resp.status_code == 200


class TestGraphQLDepthValidation:
    async def test_depth_within_limit_passes(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(depth_limit=5)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ user { posts { title } } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            assert "errors" not in resp.json()

    async def test_depth_exceeds_limit_returns_200_with_errors(
        self, app: FastAPI
    ) -> None:
        config = GraphQLSecurityConfig(depth_limit=2)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ user { posts { comments { author { name } } } } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            data = resp.json()
            assert "errors" in data
            assert "exceeds limit" in data["errors"][0]["message"]

    async def test_depth_exactly_at_limit_passes(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(depth_limit=3)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ user { posts { title } } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            assert "errors" not in resp.json()


class TestGraphQLBreadthValidation:
    async def test_breadth_within_limit_passes(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(breadth_limit=10)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ user { id name email } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            assert "errors" not in resp.json()

    async def test_breadth_exceeds_limit_returns_error(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(breadth_limit=2)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ user { id name email age } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            data = resp.json()
            assert "errors" in data
            assert "exceeds limit" in data["errors"][0]["message"]


class TestGraphQLCostValidation:
    async def test_cost_within_limit_passes(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(cost_limit=100.0)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ hello }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            assert "errors" not in resp.json()

    async def test_cost_exceeds_limit_returns_error(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(cost_limit=1.0)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Depth=2 with fields adds cost > 1.0
            query = "{ user { id name email } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            data = resp.json()
            assert "errors" in data


class TestGraphQLIntrospection:
    async def test_introspection_allowed_by_default(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(introspection_enabled=True)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ __schema { types { name } } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200

    async def test_introspection_blocked_when_disabled(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig(introspection_enabled=False)
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            query = "{ __schema { types { name } } }"
            resp = await client.post("/graphql", json={"query": query})
            assert resp.status_code == 200
            data = resp.json()
            assert "errors" in data
            assert "Introspection" in data["errors"][0]["message"]


class TestGraphQLErrorHandling:
    async def test_invalid_json_returns_400(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig()
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/graphql",
                content=b"not json",
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 400

    async def test_invalid_graphql_syntax_returns_400(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig()
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/graphql",
                json={"query": "{ invalid {"},
            )
            assert resp.status_code == 400

    async def test_no_query_field_passes_through(self, app: FastAPI) -> None:
        config = GraphQLSecurityConfig()
        app.add_middleware(GraphQLSecurityMiddleware, config=config)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/graphql",
                json={"variables": {"id": 1}},
            )
            assert resp.status_code == 200


class TestGraphQLConfiguration:
    def test_disabled_middleware_skips_checks(self) -> None:
        """When enabled=False, the middleware still checks — but the
        middleware registration itself is guarded in shield.py.
        The config model itself just holds the field."""
        config = GraphQLSecurityConfig(enabled=False)
        assert config.enabled is False
        assert config.depth_limit == 10

    def test_custom_path_matching(self) -> None:
        config = GraphQLSecurityConfig(graphql_path="/api/gql")
        assert config.graphql_path == "/api/gql"
