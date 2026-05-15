from datetime import UTC, datetime, timedelta

import pytest
from fakeredis.aioredis import FakeRedis

from araxys.api_keys.models import APIKeyRecord
from araxys.api_keys.storage import RedisAPIKeyStorage
from araxys.core.types import Scope


@pytest.fixture
async def redis_storage():
    storage = RedisAPIKeyStorage("redis://localhost")
    # Replace real redis with fakeredis
    storage._redis = FakeRedis(decode_responses=True)
    return storage

@pytest.mark.asyncio
class TestRedisAPIKeyStorage:
    async def test_store_and_retrieve(self, redis_storage):
        record = APIKeyRecord(
            prefix="testpref",
            key_hash="somehash",
            owner="test-owner",
            scopes=[Scope.READ],
            is_active=True
        )
        
        await redis_storage.store(record)
        
        retrieved = await redis_storage.get_by_prefix("testpref")
        assert retrieved is not None
        assert retrieved.owner == "test-owner"
        assert retrieved.prefix == "testpref"

    async def test_revoke_key(self, redis_storage):
        record = APIKeyRecord(
            prefix="revokeme",
            key_hash="somehash",
            owner="test-owner",
            scopes=[Scope.READ],
            is_active=True
        )
        await redis_storage.store(record)
        
        success = await redis_storage.revoke("revokeme")
        assert success
        
        retrieved = await redis_storage.get_by_prefix("revokeme")
        assert retrieved is None # Should return None if is_active is False

    async def test_list_keys(self, redis_storage):
        await redis_storage.store(APIKeyRecord(
            prefix="key00001", key_hash="h1", owner="user1", scopes=[], is_active=True
        ))
        await redis_storage.store(APIKeyRecord(
            prefix="key00002", key_hash="h2", owner="user1", scopes=[], is_active=True
        ))
        await redis_storage.store(APIKeyRecord(
            prefix="key00003", key_hash="h3", owner="user2", scopes=[], is_active=True
        ))
        
        all_keys = await redis_storage.list_keys()
        assert len(all_keys) == 3
        
        user1_keys = await redis_storage.list_keys(owner="user1")
        assert len(user1_keys) == 2

    async def test_expiration(self, redis_storage):
        past_date = datetime.now(UTC) - timedelta(days=1)
        record = APIKeyRecord(
            prefix="expired1",
            key_hash="somehash",
            owner="test-owner",
            scopes=[],
            expires_at=past_date,
            is_active=True
        )
        await redis_storage.store(record)
        
        retrieved = await redis_storage.get_by_prefix("expired1")
        assert retrieved is None
