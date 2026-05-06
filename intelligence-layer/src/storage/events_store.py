"""EventsStore — Redis sorted-set buffer for IDS traffic + violations.

Traffic flows and policy-violation alerts from Suricata are mirrored here as they
arrive over SSE, so the frontend can hydrate the Monitor page from server-side
buffer (7-day window) instead of fetching Suricata's transient 3-min eve.json.

Storage layout (DB 1):
    events:violations  (sorted set)  score=ms_epoch  member=alert_json
    events:flows       (sorted set)  score=ms_epoch  member=flow_json

Both sets share a TTL prune (7 days default) and a global cap. Events are
DEDUPED by event content hash to avoid duplicates from SSE reconnection replay.
"""
import json
import time
from typing import Any

import redis.asyncio as aioredis
import structlog

log = structlog.get_logger()


KEY_VIOLATIONS = "events:violations"
KEY_FLOWS = "events:flows"


class EventsStore:
    def __init__(self, url: str, retention_days: int = 7, max_total: int = 100_000) -> None:
        self._url = url
        self._client: aioredis.Redis | None = None
        self._retention_ms = retention_days * 86400 * 1000
        self._max_total = max_total

    async def connect(self) -> None:
        self._client = aioredis.from_url(self._url, decode_responses=True)
        # Verify connection + log DB selection
        await self._client.ping()
        log.info("events_store_connected", url=self._url,
                 retention_days=self._retention_ms // (86400 * 1000),
                 max_total=self._max_total)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("EventsStore not connected")
        return self._client

    async def push_violation(self, alert: dict[str, Any]) -> None:
        await self._push(KEY_VIOLATIONS, alert)

    async def push_flow(self, flow: dict[str, Any]) -> None:
        await self._push(KEY_FLOWS, flow)

    async def _push(self, key: str, event: dict[str, Any]) -> None:
        try:
            ts_ms = int(time.time() * 1000)
            payload = json.dumps(event, default=str)
            # ZADD with score=ts_ms, member=payload. Duplicate payload → score updated only.
            await self.client.zadd(key, {payload: ts_ms})
            # Cheap inline prune: drop entries older than retention window
            cutoff = ts_ms - self._retention_ms
            await self.client.zremrangebyscore(key, "-inf", cutoff)
            # Cap by count: keep newest N entries (drop oldest beyond cap)
            await self.client.zremrangebyrank(key, 0, -self._max_total - 1)
        except Exception as exc:
            log.warning("events_push_failed", key=key, error=str(exc))

    async def get_events(
        self,
        since_ms: int = 0,
        limit: int = 600,
        kind: str = "all",
    ) -> list[dict[str, Any]]:
        """Fetch events newer than since_ms from one or both kinds, newest-first."""
        results: list[dict[str, Any]] = []
        keys: list[str] = []
        if kind in ("all", "violation"):
            keys.append(KEY_VIOLATIONS)
        if kind in ("all", "flow"):
            keys.append(KEY_FLOWS)
        try:
            for key in keys:
                # ZREVRANGEBYSCORE: walk from +inf down to since_ms, take first `limit` items.
                # This gives NEWEST `limit` events in [since_ms, +inf]. Using zrangebyscore
                # would return the OLDEST `limit` instead — wrong slice when buffer >> limit.
                raw = await self.client.zrevrangebyscore(
                    key, "+inf", since_ms, withscores=False, start=0, num=limit
                )
                kind_label = "violation" if key == KEY_VIOLATIONS else "flow"
                for item in raw:
                    try:
                        ev = json.loads(item)
                        ev["__kind"] = kind_label  # internal hint for client
                        results.append(ev)
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            log.warning("events_get_failed", error=str(exc))
            return []

        # Sort newest-first by timestamp field if present, else by raw order
        def _ts_key(ev: dict[str, Any]) -> float:
            t = ev.get("timestamp")
            if isinstance(t, str):
                try:
                    from datetime import datetime
                    return datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
                except Exception:
                    return 0.0
            return 0.0

        results.sort(key=_ts_key, reverse=True)
        return results[:limit]

    async def stats(self) -> dict[str, Any]:
        try:
            v_count = await self.client.zcard(KEY_VIOLATIONS)
            f_count = await self.client.zcard(KEY_FLOWS)
            v_oldest = await self.client.zrange(KEY_VIOLATIONS, 0, 0, withscores=True)
            f_oldest = await self.client.zrange(KEY_FLOWS, 0, 0, withscores=True)
            return {
                "violations_count": v_count,
                "flows_count": f_count,
                "total_count": v_count + f_count,
                "violations_oldest_ms": v_oldest[0][1] if v_oldest else None,
                "flows_oldest_ms": f_oldest[0][1] if f_oldest else None,
                "retention_days": self._retention_ms // (86400 * 1000),
                "max_total": self._max_total,
            }
        except Exception as exc:
            return {"error": str(exc)}

    async def prune(self) -> dict[str, int]:
        """Force prune both sets — used by background cleanup coroutine."""
        try:
            cutoff = int(time.time() * 1000) - self._retention_ms
            v_pruned = await self.client.zremrangebyscore(KEY_VIOLATIONS, "-inf", cutoff)
            f_pruned = await self.client.zremrangebyscore(KEY_FLOWS, "-inf", cutoff)
            v_cap = await self.client.zremrangebyrank(KEY_VIOLATIONS, 0, -self._max_total - 1)
            f_cap = await self.client.zremrangebyrank(KEY_FLOWS, 0, -self._max_total - 1)
            return {
                "violations_pruned_ttl": v_pruned,
                "flows_pruned_ttl": f_pruned,
                "violations_pruned_cap": v_cap,
                "flows_pruned_cap": f_cap,
            }
        except Exception as exc:
            return {"error": str(exc)}
