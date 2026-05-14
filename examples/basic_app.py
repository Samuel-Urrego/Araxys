"""Example FastAPI app using Araxys for full security.

Run with:
    uv run uvicorn examples.basic_app:app --reload
"""

from fastapi import Depends, FastAPI

from araxys import AraxysConfig, AraxysShield, Scope
from araxys.api_keys.dependencies import require_api_key
from araxys.api_keys.models import APIKeyRecord
from araxys.jwt_auth.dependencies import require_jwt
from araxys.jwt_auth.tokens import TokenPayload

app = FastAPI(
    title="Araxys Demo API",
    description="Example API protected by Araxys security shield",
    version="0.1.0",
)

# Initialize Araxys with all modules enabled
shield = AraxysShield(
    app,
    AraxysConfig(
        secret_key="this-is-a-demo-key-change-in-prod!!",  # 36 chars
        rate_limit={"max_requests": 10, "window_seconds": 60},
        honeypot={"paths": ["/admin/config", "/wp-admin", "/.env"]},
    ),
)


# --- Public endpoint ---
@app.get("/")
async def root():
    """Public endpoint — no auth required, but rate-limited."""
    return {"message": "Welcome to the Araxys demo!", "status": "protected"}


# --- Create API key (admin only in real apps) ---
@app.post("/keys/create")
async def create_api_key():
    """Create a new API key with read scope."""
    result = await shield.api_key_manager.create_key(
        owner="demo-user",
        scopes=[Scope.READ, Scope.WRITE],
        ttl_days=30,
        label="Demo key",
    )
    return {
        "raw_key": result.raw_key,
        "prefix": result.prefix,
        "message": "Save this key — it won't be shown again!",
    }


# --- Protected by API key ---
@app.get("/data")
async def get_data(
    key: APIKeyRecord = Depends(
        require_api_key(Scope.READ, manager=shield.api_key_manager)
    ),
):
    """Endpoint protected by API key with READ scope."""
    return {
        "data": "This is protected data",
        "accessed_by": key.owner,
        "key_prefix": key.prefix,
    }


# --- JWT auth flow ---
@app.post("/auth/login")
async def login():
    """Simulate login — returns JWT token pair."""
    pair = await shield.jwt_manager.create_token_pair(
        subject="user-123",
        scopes=[Scope.READ, Scope.WRITE],
    )
    return pair.model_dump()


@app.post("/auth/refresh")
async def refresh_token(refresh_token: str):
    """Rotate tokens using a refresh token."""
    pair = await shield.jwt_manager.rotate_tokens(refresh_token)
    return pair.model_dump()


# --- Protected by JWT ---
@app.get("/profile")
async def get_profile(
    user: TokenPayload = Depends(
        require_jwt(Scope.READ, jwt_manager=shield.jwt_manager)
    ),
):
    """Endpoint protected by JWT with READ scope."""
    return {
        "user_id": user.sub,
        "scopes": user.scopes,
        "message": "You're authenticated!",
    }
