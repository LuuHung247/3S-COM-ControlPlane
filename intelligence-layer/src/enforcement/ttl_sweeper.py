"""TTL expiry for agent rules.

Neither the Secure Framework nor nos-acl-bridge expires rules, so the agent owns the
lifetime of what it installs: every enforced rule is recorded in a Redis sorted set
(score = expiry epoch) and revoked once due. On startup, agent rules found on the fabric
but missing from the set (installed before a restart, or by an older build) are adopted
with their declared ttl-seconds counted from now — they are never left unbounded.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog

from ..storage.redis import RedisStore
from .interface import EnforcementBackend

log = structlog.get_logger()

EXPIRY_KEY = "agent:rule_expiry"
SWEEP_INTERVAL_S = 15
DEFAULT_TTL_S = 3600


async def record(redis: RedisStore, rule_id: str, ttl_seconds: int) -> None:
    if rule_id:
        ttl = int(ttl_seconds or DEFAULT_TTL_S)
        await redis.client.zadd(EXPIRY_KEY, {rule_id: time.time() + ttl})


async def sweep_once(redis: RedisStore, backend: EnforcementBackend) -> list[str]:
    due = await redis.client.zrangebyscore(EXPIRY_KEY, "-inf", time.time())
    revoked = []
    for raw in due:
        rule_id = raw.decode() if isinstance(raw, bytes) else raw
        result = await backend.revoke(rule_id)
        if result.success:
            await redis.client.zrem(EXPIRY_KEY, rule_id)
            revoked.append(rule_id)
        else:
            log.warning("ttl_revoke_failed", rule_id=rule_id, error=result.error)
    if revoked:
        log.info("ttl_rules_revoked", rule_ids=revoked)
    return revoked


async def adopt_orphans(redis: RedisStore, ids_agent_url: str) -> int:
    """Register agent rules present on the fabric but unknown to the expiry set."""
    async with httpx.AsyncClient(timeout=15) as client:
        data: dict[str, Any] = (await client.get(f"{ids_agent_url.rstrip('/')}/rules")).json()
    adopted = 0
    for leaf in (data.get("leaves") or {}).values():
        for n in (leaf.get("rules") or {}).get("notification", []):
            for u in n.get("update", []):
                v = u.get("val", {})
                rid = v.get("rule-id") or v.get("rule_id")
                if v.get("source") != "agent" or not rid:
                    continue
                if await redis.client.zscore(EXPIRY_KEY, rid) is None:
                    await record(redis, rid, int(v.get("ttl-seconds") or DEFAULT_TTL_S))
                    adopted += 1
    if adopted:
        log.info("ttl_orphans_adopted", count=adopted)
    return adopted


async def run(redis: RedisStore, backend: EnforcementBackend, ids_agent_url: str) -> None:
    try:
        await adopt_orphans(redis, ids_agent_url)
    except Exception as exc:
        log.warning("ttl_adopt_failed", error=str(exc))
    while True:
        try:
            await sweep_once(redis, backend)
        except asyncio.CancelledError:
            return
        except Exception as exc:
            log.warning("ttl_sweep_error", error=str(exc))
        await asyncio.sleep(SWEEP_INTERVAL_S)
