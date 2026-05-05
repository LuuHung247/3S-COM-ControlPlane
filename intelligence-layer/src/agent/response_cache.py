"""Response cache for LLM-generated PolicyIntent.

Cache key is computed from decision-relevant features (NOT raw alert content) so that
two alerts with the same threat shape hit the same cache entry. The cached intent
template is rebound to the actual alert's src_ip on cache hit — agent never blocks
the wrong target due to stale cache.

This is RESPONSE caching (final LLM output) — different from server-side prompt caching
(KV cache) which only Anthropic supports. Saves ~3500ms per cache hit.
"""
import hashlib
import json
from typing import Any

import structlog

from ..models.alert import SuricataAlert
from ..models.decision import PolicyIntent, PolicyAction
from ..storage.redis import RedisStore
from ..core.topology import ip_to_zone
from ..core import baselines

log = structlog.get_logger()


_CACHE_KEY_PREFIX = "agent:resp_cache:"
_STATS_HITS = "agent:resp_cache:stats:hits"
_STATS_MISSES = "agent:resp_cache:stats:misses"


class ResponseCache:
    """Redis-backed cache for PolicyIntent decisions, keyed by decision-relevant features."""

    def __init__(
        self,
        redis: RedisStore,
        ttl_seconds: int = 60,
        enabled: bool = True,
    ) -> None:
        self._redis = redis
        self._ttl = ttl_seconds
        self._enabled = enabled

    @staticmethod
    def compute_key(
        sid: int,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        correlation_signal: str = "",
    ) -> str:
        """Deterministic cache key from decision-relevant features.

        Features chosen so:
        - Two alerts with same threat pattern → same key (cache hit)
        - Different src_zone or different correlation signal → different key (no false hit)
        - Source IP itself NOT in key — but src_zone IS — so attacker rotating IPs in same
          zone hits same cache (correct: same threat profile), but attacker pivoting zones
          gets different decision (correct: different threat profile).
        """
        src_zone = ip_to_zone(src_ip) or "unknown"
        dst_zone = ip_to_zone(dst_ip) or "unknown" if dst_ip else "none"
        baseline = baselines.match_baseline(src_ip, dst_ip, dst_port, protocol.lower() if protocol else "tcp")
        baseline_name = baseline.name if baseline else "none"

        feature_blob = (
            f"sid={sid}|src_zone={src_zone}|dst_zone={dst_zone}|"
            f"dst_port={dst_port}|proto={protocol}|"
            f"baseline={baseline_name}|corr={correlation_signal}"
        )
        digest = hashlib.sha256(feature_blob.encode("utf-8")).hexdigest()[:16]
        return f"{_CACHE_KEY_PREFIX}{digest}"

    async def get(self, key: str) -> dict[str, Any] | None:
        """Return cached intent dict or None."""
        if not self._enabled:
            return None
        try:
            raw = await self._redis.client.get(key)
        except Exception as exc:
            log.warning("response_cache_get_failed", error=str(exc))
            return None
        if not raw:
            await self._incr(_STATS_MISSES)
            return None
        try:
            data = json.loads(raw)
            await self._incr(_STATS_HITS)
            return data
        except Exception:
            return None

    async def set(self, key: str, intent: PolicyIntent) -> None:
        """Cache enforced intent template. Note: src_ip in cached value is the ORIGINAL
        decision's src_ip — caller MUST rebind on cache hit to avoid blocking wrong target.
        """
        if not self._enabled:
            return
        try:
            payload = json.dumps({
                "intent": intent.model_dump(mode="json"),
                "cached_at": _now_iso(),
            })
            await self._redis.client.set(key, payload, ex=self._ttl)
        except Exception as exc:
            log.warning("response_cache_set_failed", error=str(exc))

    async def stats(self) -> dict[str, int]:
        try:
            hits = await self._redis.client.get(_STATS_HITS)
            misses = await self._redis.client.get(_STATS_MISSES)
            hit_count = int(hits or 0)
            miss_count = int(misses or 0)
            total = hit_count + miss_count
            hit_rate = round(hit_count / total, 3) if total > 0 else 0.0
            return {
                "hits": hit_count,
                "misses": miss_count,
                "total": total,
                "hit_rate": hit_rate,
                "ttl_seconds": self._ttl,
                "enabled": self._enabled,
            }
        except Exception:
            return {"hits": 0, "misses": 0, "total": 0, "hit_rate": 0.0, "enabled": self._enabled}

    async def reset_stats(self) -> None:
        try:
            await self._redis.client.delete(_STATS_HITS, _STATS_MISSES)
        except Exception:
            pass

    async def _incr(self, counter_key: str) -> None:
        try:
            await self._redis.client.incr(counter_key)
        except Exception:
            pass


def rebind_cached_intent(cached_data: dict[str, Any], alert: SuricataAlert) -> PolicyIntent | None:
    """Reconstruct PolicyIntent from cache, rebinding src_ip to current alert's actual
    source. Critical safety: cache value contains a TEMPLATE, not a target — actual
    block target always derives from the live alert.
    """
    if not isinstance(cached_data, dict) or "intent" not in cached_data:
        return None
    raw_intent = cached_data["intent"]
    try:
        # Force rebind: src_ip MUST come from current alert, not cache
        raw_intent["src_ip"] = f"{alert.src_ip}/32" if "/" not in alert.src_ip else alert.src_ip
        # Reset deterministic rule_id so it regenerates from new (src,dst,port,proto)
        raw_intent["rule_id"] = ""
        # Map action enum if needed
        action_str = raw_intent.get("action", "log_only")
        if action_str not in (PolicyAction.DROP.value, PolicyAction.LOG_ONLY.value):
            raw_intent["action"] = PolicyAction.LOG_ONLY.value
        return PolicyIntent(**raw_intent)
    except Exception as exc:
        log.warning("rebind_cached_intent_failed", error=str(exc))
        return None


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
