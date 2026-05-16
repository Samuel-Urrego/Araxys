"""Tests for the JWT auth module."""

from datetime import UTC

import pytest

from araxys.core.config import JWTConfig
from araxys.core.exceptions import TokenInvalid, TokenRevoked
from araxys.core.types import Scope
from araxys.jwt_auth.storage import InMemoryJWKSStore, InMemoryTokenStorage
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
    async def test_create_token_pair(self, jwt_manager: JWTManager) -> None:
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ, Scope.WRITE]
        )
        assert pair.access_token
        assert pair.refresh_token
        assert pair.token_type == "bearer"
        assert pair.expires_in > 0

    async def test_decode_access_token(self, jwt_manager: JWTManager) -> None:
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        payload = jwt_manager.decode_token(pair.access_token, expected_type="access")
        assert payload.sub == "user-123"
        assert "read" in payload.scopes

    async def test_decode_wrong_type_raises(self, jwt_manager: JWTManager) -> None:
        pair = await jwt_manager.create_token_pair(subject="user-123")
        with pytest.raises(TokenInvalid, match="Expected refresh"):
            jwt_manager.decode_token(pair.access_token, expected_type="refresh")

    async def test_rotate_tokens(self, jwt_manager: JWTManager) -> None:
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        new_pair = await jwt_manager.rotate_tokens(pair.refresh_token)

        assert new_pair.access_token != pair.access_token
        assert new_pair.refresh_token != pair.refresh_token

        # Old refresh token should now be blacklisted
        with pytest.raises(TokenRevoked):
            await jwt_manager.rotate_tokens(pair.refresh_token)

    async def test_revoke_refresh_token(self, jwt_manager: JWTManager) -> None:
        pair = await jwt_manager.create_token_pair(subject="user-123")
        await jwt_manager.revoke_refresh_token(pair.refresh_token)

        with pytest.raises(TokenRevoked):
            await jwt_manager.rotate_tokens(pair.refresh_token)

    async def test_invalid_token_raises(self, jwt_manager: JWTManager) -> None:
        with pytest.raises(TokenInvalid):
            jwt_manager.decode_token("not.a.valid.token")

    async def test_token_with_wrong_secret(self, jwt_manager: JWTManager) -> None:
        other_manager = JWTManager(
            config=JWTConfig(),
            secret_key="different-secret-key-32-chars!!!!",
            storage=InMemoryTokenStorage(),
        )
        pair = await other_manager.create_token_pair(subject="user-123")

        with pytest.raises(TokenInvalid):
            jwt_manager.decode_token(pair.access_token)


class TestRS256Support:
    """Tests for RS256 (RSA) asymmetric signing."""

    async def test_create_and_decode_rs256(
        self,
        storage: InMemoryTokenStorage,
        rsa_private_key_pem: str,
        rsa_public_key_pem: str,
    ) -> None:
        manager = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=rsa_private_key_pem,
                public_key=rsa_public_key_pem,
            ),
            secret_key="irrelevant-for-asymmetric",
            storage=storage,
        )
        pair = await manager.create_token_pair(
            subject="user-rsa", scopes=[Scope.READ]
        )
        payload = manager.decode_token(pair.access_token, expected_type="access")
        assert payload.sub == "user-rsa"
        assert "read" in payload.scopes
        assert payload.token_type == "access"

    async def test_rs256_wrong_public_key_fails(
        self,
        storage: InMemoryTokenStorage,
        rsa_private_key_pem: str,
        rsa_public_key_pem: str,
    ) -> None:
        """Sign with RSA private key, verify with a DIFFERENT RSA public key."""
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        other_private = rsa_mod.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        other_public_pem = other_private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

        signer = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=rsa_private_key_pem,
                public_key=rsa_public_key_pem,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        verifier = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=other_private.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                ).decode(),
                public_key=other_public_pem,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        pair = await signer.create_token_pair(subject="user-rsa")
        with pytest.raises(TokenInvalid):
            verifier.decode_token(pair.access_token)

    async def test_rs256_private_key_only_uses_public_from_private(
        self,
        storage: InMemoryTokenStorage,
        rsa_private_key_pem: str,
    ) -> None:
        """Work with only private_key (derive public from it for verification)."""
        manager = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=rsa_private_key_pem,
                public_key=None,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        pair = await manager.create_token_pair(subject="user-rsa")
        payload = manager.decode_token(pair.access_token, expected_type="access")
        assert payload.sub == "user-rsa"


class TestES256Support:
    """Tests for ES256 (ECDSA) asymmetric signing."""

    async def test_create_and_decode_es256(
        self,
        storage: InMemoryTokenStorage,
        ec_private_key_pem: str,
        ec_public_key_pem: str,
    ) -> None:
        manager = JWTManager(
            config=JWTConfig(
                algorithm="ES256",
                private_key=ec_private_key_pem,
                public_key=ec_public_key_pem,
            ),
            secret_key="irrelevant-for-asymmetric",
            storage=storage,
        )
        pair = await manager.create_token_pair(
            subject="user-ec", scopes=[Scope.READ]
        )
        payload = manager.decode_token(pair.access_token, expected_type="access")
        assert payload.sub == "user-ec"
        assert "read" in payload.scopes

    async def test_es256_wrong_public_key_fails(
        self,
        storage: InMemoryTokenStorage,
        ec_private_key_pem: str,
        ec_public_key_pem: str,
    ) -> None:
        """Sign with EC private key, verify with a DIFFERENT EC public key."""
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        other_private = ec_mod.generate_private_key(ec_mod.SECP256R1())
        other_public_pem = other_private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

        signer = JWTManager(
            config=JWTConfig(
                algorithm="ES256",
                private_key=ec_private_key_pem,
                public_key=ec_public_key_pem,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        verifier = JWTManager(
            config=JWTConfig(
                algorithm="ES256",
                private_key=other_private.private_bytes(
                    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                ).decode(),
                public_key=other_public_pem,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        pair = await signer.create_token_pair(subject="user-ec")
        with pytest.raises(TokenInvalid):
            verifier.decode_token(pair.access_token)


class TestJWKS:
    """Tests for JWKS (JSON Web Key Set) support."""

    async def test_in_memory_jwks_store_add_and_get_keys(
        self,
        rsa_public_key_pem: str,
    ) -> None:
        store = InMemoryJWKSStore()
        jwks = await store.get_jwks()
        assert jwks == {"keys": []}

        store.add_key("key-1", rsa_public_key_pem, is_active=True)
        jwks = await store.get_jwks()
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == "key-1"
        assert jwks["keys"][0]["kty"] == "RSA"
        assert jwks["keys"][0]["alg"] == "RS256"
        assert "n" in jwks["keys"][0]
        assert "e" in jwks["keys"][0]

    async def test_jwks_with_ec_key(
        self,
        ec_public_key_pem: str,
    ) -> None:
        store = InMemoryJWKSStore()
        store.add_key("ec-1", ec_public_key_pem, is_active=True, algorithm="ES256")
        jwks = await store.get_jwks()
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kid"] == "ec-1"
        assert jwks["keys"][0]["kty"] == "EC"
        assert jwks["keys"][0]["crv"] == "P-256"
        assert "x" in jwks["keys"][0]
        assert "y" in jwks["keys"][0]

    async def test_jwks_multiple_keys_key_rotation(
        self,
        rsa_public_key_pem: str,
    ) -> None:
        store = InMemoryJWKSStore()
        store.add_key("key-old", rsa_public_key_pem, is_active=False)
        signing_kid = await store.get_signing_key_id()
        assert signing_kid is None

        store.add_key("key-new", rsa_public_key_pem, is_active=True)
        signing_kid = await store.get_signing_key_id()
        assert signing_kid == "key-new"

        jwks = await store.get_jwks()
        assert len(jwks["keys"]) == 2

    async def test_jwks_endpoint_returns_jwks(
        self,
        storage: InMemoryTokenStorage,
        rsa_private_key_pem: str,
        rsa_public_key_pem: str,
    ) -> None:
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        from araxys.jwt_auth.dependencies import create_jwks_router
        from araxys.jwt_auth.tokens import JWTManager

        store = InMemoryJWKSStore()
        store.add_key(
            "test-key-1", rsa_public_key_pem, is_active=True, algorithm="RS256"
        )

        manager = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=rsa_private_key_pem,
                public_key=rsa_public_key_pem,
                jwks_enabled=True,
            ),
            secret_key="irrelevant",
            storage=storage,
            jwks_store=store,
        )
        app = FastAPI()
        app.include_router(create_jwks_router(manager))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/jwks.json")
            assert resp.status_code == 200
            data = resp.json()
            assert "keys" in data
            assert len(data["keys"]) == 1
            assert data["keys"][0]["kid"] == "test-key-1"

    async def test_jwks_endpoint_disabled_when_no_store(
        self,
        storage: InMemoryTokenStorage,
        rsa_private_key_pem: str,
        rsa_public_key_pem: str,
    ) -> None:
        from fastapi import FastAPI, status
        from httpx import ASGITransport, AsyncClient

        from araxys.jwt_auth.dependencies import create_jwks_router

        manager = JWTManager(
            config=JWTConfig(
                algorithm="RS256",
                private_key=rsa_private_key_pem,
                public_key=rsa_public_key_pem,
                jwks_enabled=False,
            ),
            secret_key="irrelevant",
            storage=storage,
        )
        app = FastAPI()
        app.include_router(create_jwks_router(manager))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/.well-known/jwks.json")
            assert resp.status_code == status.HTTP_404_NOT_FOUND


class TestIntrospection:
    """Tests for token introspection (RFC 7662)."""

    async def test_introspect_active_token(
        self,
        jwt_manager: JWTManager,
    ) -> None:
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        result = await jwt_manager.introspect_token(pair.access_token)
        assert result["active"] is True
        assert result["sub"] == "user-123"
        assert result["token_type"] == "access"
        assert "scope" in result
        assert "exp" in result
        assert "iat" in result
        assert "jti" in result

    async def test_introspect_expired_token(
        self,
        storage: InMemoryTokenStorage,
    ) -> None:
        from datetime import datetime, timedelta

        manager = JWTManager(
            config=JWTConfig(
                access_token_ttl_minutes=1,
            ),
            secret_key="test-secret-key-must-be-32-chars!!",
            storage=storage,
        )
        # Create token with an already-expired exp via extra_claims
        expired_ts = datetime.now(UTC) - timedelta(hours=1)
        pair = await manager.create_token_pair(
            subject="user-expired",
            extra_claims={"exp": expired_ts},
        )
        result = await manager.introspect_token(pair.access_token)
        assert result["active"] is False

    async def test_introspect_invalid_token(
        self,
        jwt_manager: JWTManager,
    ) -> None:
        result = await jwt_manager.introspect_token("not.a.valid.token")
        assert result["active"] is False

    async def test_introspect_revoked_token(
        self,
        jwt_manager: JWTManager,
    ) -> None:
        pair = await jwt_manager.create_token_pair(subject="user-123")
        # Revoke the refresh token's JTI — for access tokens we need blacklist
        payload = jwt_manager.decode_token(pair.access_token, expected_type="access")
        await jwt_manager._storage.blacklist_jti(payload.jti, ttl_seconds=3600)

        result = await jwt_manager.introspect_token(pair.access_token)
        assert result["active"] is False

    async def test_introspect_revoked_token_still_returns_claims(
        self,
        jwt_manager: JWTManager,
    ) -> None:
        """Even when revoked, return claims so the caller can audit."""
        pair = await jwt_manager.create_token_pair(
            subject="user-123", scopes=[Scope.READ]
        )
        payload = jwt_manager.decode_token(pair.access_token, expected_type="access")
        await jwt_manager._storage.blacklist_jti(payload.jti, ttl_seconds=3600)

        result = await jwt_manager.introspect_token(pair.access_token)
        assert result["active"] is False
        assert result["sub"] == "user-123"

    async def test_introspect_refresh_token(
        self,
        jwt_manager: JWTManager,
    ) -> None:
        pair = await jwt_manager.create_token_pair(subject="user-123")
        result = await jwt_manager.introspect_token(pair.refresh_token)
        assert result["active"] is True
        assert result["token_type"] == "refresh"
