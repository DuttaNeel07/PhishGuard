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

async def add_to_threat_feed(domain: str, score: int, tactics: list):
    """Store a high-risk scan in the live threat feed list"""
    try:
        r = await get_redis()
        entry = json.dumps({
            "domain": domain,
            "score": score,
            "tactics": tactics[:3],
            "scanned_at": datetime.datetime.utcnow().isoformat(),
            "risk_level": "dangerous" if score >= 70 else "suspicious"
        })
        await r.lpush("phishguard:threat_feed", entry)
        await r.ltrim("phishguard:threat_feed", 0, 49)  # keep only latest 50
    except Exception:
        pass

async def get_threat_feed() -> list:
    """Retrieve the live threat feed"""
    try:
        r = await get_redis()
        entries = await r.lrange("phishguard:threat_feed", 0, 49)
        return [json.loads(e) for e in entries]
    except Exception:
        return []