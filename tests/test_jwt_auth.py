"""Tests for the JWT auth module."""

import pytest

from araxys.core.config import JWTConfig
from araxys.core.exceptions import TokenExpired, TokenInvalid, TokenRevoked
from araxys.core.types import Scope
from araxys.jwt_auth.storage import InMemoryTokenStorage
from araxys.jwt_auth.tokens import JWTManager


@pytest.fixture
def storage() -> InMemoryTokenStorage:
    return InMemoryTokenStorage()


@pytest.fixture
def jwt_manager(storage: InMemoryTokenStorage) -> JWTManager:
    return JWTManager(
        config=JWTConfig(
            access_token_ttl_minutes=30,
            refresh_token_ttl_days=7,
        ),
        secret_key="test-secret-key-must-be-32-chars!!",
        storage=storage,
    )


class TestJWTManager:
    async def test_create_token_pair(self, jwt_manager: JWTManager):
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ, Scope.WRITE]
        )
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type == "bearer"
        assert pair.expires_in > 0

    async def test_decode_access_token(self, jwt_manager: JWTManager):
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        payload = jwt_manager.decode_token(pair.access_token, expected_type="access")
        assert payload.sub == "user-123"
        assert "read" in payload.scopes

    async def test_decode_wrong_type_raises(self, jwt_manager: JWTManager):
        pair = await jwt_manager.create_token_pair(subject="user-123")
        with pytest.raises(TokenInvalid, match="Expected refresh"):
            jwt_manager.decode_token(pair.access_token, expected_type="refresh")

    async def test_rotate_tokens(self, jwt_manager: JWTManager):
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        new_pair = await jwt_manager.rotate_tokens(pair.refresh_token)

        assert new_pair.access_token != pair.access_token
        assert new_pair.refresh_token != pair.refresh_token

        # Old refresh token should now be blacklisted
        with pytest.raises(TokenRevoked):
            await jwt_manager.rotate_tokens(pair.refresh_token)

    async def test_revoke_refresh_token(self, jwt_manager: JWTManager):
        pair = await jwt_manager.create_token_pair(subject="user-123")
        await jwt_manager.revoke_refresh_token(pair.refresh_token)

        with pytest.raises(TokenRevoked):
            await jwt_manager.rotate_tokens(pair.refresh_token)

    async def test_invalid_token_raises(self, jwt_manager: JWTManager):
        with pytest.raises(TokenInvalid):
            jwt_manager.decode_token("not.a.valid.token")

    async def test_token_with_wrong_secret(self, jwt_manager: JWTManager):
        other_manager = JWTManager(
            config=JWTConfig(),
            secret_key="different-secret-key-32-chars!!!!",
            storage=InMemoryTokenStorage(),
        )
        pair = await other_manager.create_token_pair(subject="user-123")

        with pytest.raises(TokenInvalid):
            jwt_manager.decode_token(pair.access_token)
