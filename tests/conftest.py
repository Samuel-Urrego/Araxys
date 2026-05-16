"""Shared test fixtures for Araxys."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from araxys import AraxysConfig, AraxysShield


@pytest.fixture(scope="session")
def rsa_private_key_pem() -> str:
    """Generate a 2048-bit RSA private key PEM for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


@pytest.fixture(scope="session")
def rsa_public_key_pem(rsa_private_key_pem: str) -> str:
    """Derive the RSA public key PEM from the private key."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(rsa_private_key_pem.encode(), password=None)
    return private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


@pytest.fixture(scope="session")
def ec_private_key_pem() -> str:
    """Generate an ES256 (P-256) EC private key PEM for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()


@pytest.fixture(scope="session")
def ec_public_key_pem(ec_private_key_pem: str) -> str:
    """Derive the EC public key PEM from the private key."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(ec_private_key_pem.encode(), password=None)
    return private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


@pytest.fixture
def config() -> AraxysConfig:
    """AraxysConfig with all modules enabled for testing."""
    return AraxysConfig(
        secret_key="test-secret-key-must-be-32-chars!!",
        rate_limit={  # type: ignore
            "max_requests": 5,
            "window_seconds": 60,
            "ban_threshold": 3,
            "ban_duration_seconds": 10,
        },
        honeypot={"paths": ["/admin/config", "/.env"]},  # type: ignore
    )


@pytest.fixture
def app() -> FastAPI:
    """Clean FastAPI app for testing."""
    return FastAPI()


@pytest.fixture
def shield(app: FastAPI, config: AraxysConfig) -> AraxysShield:
    """AraxysShield with all modules registered."""
    return AraxysShield(app, config)


@pytest.fixture
async def client(app: FastAPI, shield: AraxysShield) -> AsyncClient:  # type: ignore
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
