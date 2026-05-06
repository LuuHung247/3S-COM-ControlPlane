"""Warm cache: alert history per IP, decision dedup. Uses Redis Streams/hashes."""
import json
import time
from typing import Any

import redis.asyncio as aioredis


class RedisStore:
    def __init__(self, url: str, dedup_window: int = 30) -> None:
        self._url = url
        self._dedup_window = dedup_window
        self._client: aioredis.Redis | None = None

    async def connect(self) -> None:
        self._client = aioredis.from_url(self._url, decode_responses=True)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("RedisStore not connected")
        return self._client

    async def get_alert_history(self, src_ip: str, limit: int = 20) -> list[dict[str, Any]]:
        key = f"alert_history:{src_ip}"
        raw = await self.client.lrange(key, 0, limit - 1)
        return [json.loads(r) for r in raw]

    async def push_alert_history(self, src_ip: str, alert: dict[str, Any]) -> None:
        key = f"alert_history:{src_ip}"
        await self.client.lpush(key, json.dumps(alert))
        await self.client.ltrim(key, 0, 99)  # keep last 100
        await self.client.expire(key, 86400)

    async def is_duplicate(self, src_ip: str, sid: int) -> bool:
        key = f"dedup:{src_ip}:{sid}"
        result = await self.client.set(key, "1", ex=self._dedup_window, nx=True)
        return result is None  # None = key already existed = duplicate

    async def cache_decision(self, decision_id: str, data: dict[str, Any]) -> None:
        key = f"decision:{decision_id}"
        # default=str → handles datetime, UUID, Enum, etc. without crashing the cache write
        await self.client.set(key, json.dumps(data, default=str), ex=3600)

    async def ping(self) -> bool:
        try:
            return await self.client.ping()
        except Exception:
            return False
