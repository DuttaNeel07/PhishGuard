import json
import redis.asyncio as redis
from app.config import settings

_redis_client = None

async def get_redis():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client

async def init_db():
    try:
        r = await get_redis()
        await r.ping()
        print("✅ Redis connected")
    except Exception as e:
        print(f"⚠️  Redis unavailable (cache disabled): {e}")

async def get_cached_result(key: str):
    try:
        r = await get_redis()
        data = await r.get(f"phishguard:result:{key}")
        if data:
            return json.loads(data)
    except Exception:
        pass
    return None

async def set_cached_result(key: str, data: dict):
    try:
        r = await get_redis()
        await r.setex(
            f"phishguard:result:{key}",
            settings.CACHE_TTL_SECONDS,
            json.dumps(data, default=str)
        )
    except Exception:
        pass