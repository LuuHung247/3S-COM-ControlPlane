"""FlowBatchDispatcher — window-close callback that:
  1. Aggregates flows into per-IP-pair records (FlowAggregator)
  2. Cheap rule-based pre-filter (suspect_score) to flag obvious attacks
  3. LLaMA Tier-1 batch classifier — 1 call/window judges every pair
     (NORMAL vs SUSPECT_*). Catches borderline cases heuristic misses.
  4. Checks the agent trigger flag (Redis key `agent:trigger:enabled`)
  5. Final SUSPECT set = (heuristic ≥2) ∪ (LLaMA SUSPECT_*) →
     synthetic alert per pair → existing on_alert pipeline (GLM Stage 1 + safety).

Token-economy:
  - Heuristic catches policy violations & known shapes (0 token)
  - LLaMA Tier-1: 1 cheap call/window (~$0.0001)
  - GLM Stage 1: only on SUSPECT_* pairs (~$0.001 each)
  - Toggle=OFF short-circuits Tier-1 + Stage 1 (LLaMA also skipped)
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

import structlog

from ..agent.llm.interface import LLMClient
from ..models.alert import SuricataAlert
from ..models.flow import SuricataFlowEvent, AggregatedIPPair
from ..storage.events_store import EventsStore
from ..storage.redis import RedisStore
from .flow_aggregator import aggregate_flows, suspect_score
from .llama_batch_classifier import classify_batch as llama_classify_batch

log = structlog.get_logger()

AlertCallback = Callable[[SuricataAlert], Awaitable[None]]
ZoneLookup = Callable[[str], str]  # ip → zone

_AGENT_TRIGGER_KEY = "agent:trigger:enabled"
_SUSPECT_THRESHOLD = 2     # suspect_score >= threshold → dispatch to agent
_SYNTHETIC_SID_BASE = 9900000   # 9900xxx reserved for flow-batch synthetic alerts


class FlowBatchDispatcher:
    def __init__(
        self,
        on_alert: AlertCallback,
        redis: RedisStore | None = None,
        ip_to_zone: ZoneLookup | None = None,
        suspect_threshold: int = _SUSPECT_THRESHOLD,
        fast_llm: LLMClient | None = None,
        events_store: EventsStore | None = None,
    ) -> None:
        self._on_alert = on_alert
        self._redis = redis
        self._ip_to_zone = ip_to_zone
        self._suspect_threshold = suspect_threshold
        self._fast_llm = fast_llm
        self._events_store = events_store

        # Stats snapshot of the most recent window, surfaced via /admin/flow-batch/status
        self.last_window_stats: dict = {
            "flows_in_window": 0,
            "ip_pairs_total": 0,
            "ip_pairs_suspect_heuristic": 0,
            "ip_pairs_suspect_llama": 0,
            "ip_pairs_suspect": 0,
            "dispatched": 0,
            "agent_calls_skipped": 0,
            "llama_called": False,
            "window_end": "",
        }

    async def _trigger_enabled(self) -> bool:
        if self._redis is None:
            return True
        try:
            val = await self._redis.client.get(_AGENT_TRIGGER_KEY)
        except Exception:
            return True
        if val is None:
            return True
        return val in (b"1", "1", b"true", "true")

    async def _publish_window_summary(
        self,
        window_start: str,
        window_end: str,
        all_pairs: list[AggregatedIPPair],
        llama_results: dict[str, dict],
        heuristic_suspects: dict,
        skipped: bool,
    ) -> None:
        """Emit a per-window summary 'event' to EventsStore so FE shows alive signal
        every window (regardless of whether any pair was suspect)."""
        if self._events_store is None:
            return
        per_pair_summary = []
        for p in all_pairs:
            pid = _pair_key(p)
            cls = llama_results.get(pid, {})
            heur_score = heuristic_suspects.get(pid, (None, 0))[1] if pid in heuristic_suspects else 0
            per_pair_summary.append({
                "pair": pid,
                "src_zone": p.src_zone,
                "dst_zone": p.dest_zone,
                "flow_count": p.flow_count,
                "bytes_to_server": p.bytes_toserver_sum,
                "bytes_to_client": p.bytes_toclient_sum,
                "heuristic_score": heur_score,
                "llama_label": cls.get("label", "—"),
                "llama_confidence": cls.get("confidence"),
                "llama_reason": cls.get("reason", ""),
            })
        event = {
            "event_type": "window_summary",
            "timestamp": window_end,
            "window_start": window_start,
            "window_end": window_end,
            "skipped_by_toggle": skipped,
            "stats": dict(self.last_window_stats),
            "pairs": per_pair_summary,
        }
        try:
            await self._events_store.push_flow(event)
        except Exception as exc:
            log.warning("window_summary_push_failed", error=str(exc))

    async def on_window_close(
        self,
        flows: list[SuricataFlowEvent],
        window_start: str,
        window_end: str,
    ) -> None:
        """Single entry point called by FlowWindow when window closes."""
        if not flows:
            log.debug("flow_batch_empty_window")
            return

        # 1. Aggregate
        aggregated = aggregate_flows(
            flows,
            window_start=window_start,
            window_end=window_end,
            ip_to_zone=self._ip_to_zone,
        )

        # 2. Cheap heuristic pre-filter — catches obvious attacks for free
        scored = [(p, suspect_score(p)) for p in aggregated]
        heuristic_suspects = {
            _pair_key(p): (p, s) for p, s in scored if s >= self._suspect_threshold
        }

        log.info(
            "flow_batch_heuristic_summary",
            flows_in_window=len(flows),
            ip_pairs_total=len(aggregated),
            heuristic_suspects=len(heuristic_suspects),
            top_score=max((s for _, s in scored), default=0),
        )

        # 3. Toggle gate FIRST — saves LLaMA call too when paused
        enabled = await self._trigger_enabled()

        # Pre-populate stats so window summary is published even when skipped
        self.last_window_stats = {
            "flows_in_window": len(flows),
            "ip_pairs_total": len(aggregated),
            "ip_pairs_suspect_heuristic": len(heuristic_suspects),
            "ip_pairs_suspect_llama": 0,
            "ip_pairs_suspect": 0,
            "dispatched": 0,
            "agent_calls_skipped": 0,
            "llama_called": False,
            "window_end": window_end,
        }

        if not enabled:
            total_candidates = len(heuristic_suspects)
            self.last_window_stats["agent_calls_skipped"] = total_candidates
            log.info(
                "flow_batch_agent_disabled_skip_dispatch",
                suspects_skipped=total_candidates,
            )
            await self._publish_window_summary(
                window_start, window_end, [p for p, _ in scored], {}, heuristic_suspects, skipped=True
            )
            return

        # 4. LLaMA Tier-1 batch classifier — 1 call/window
        llama_results: dict[str, dict] = {}
        if self._fast_llm is not None and aggregated:
            llama_results = await llama_classify_batch(self._fast_llm, aggregated)
            self.last_window_stats["llama_called"] = bool(llama_results)
        llama_suspects: dict[str, tuple] = {}
        for pair in aggregated:
            pid = _pair_key(pair)
            cls = llama_results.get(pid)
            if cls and cls.get("label", "").startswith("SUSPECT"):
                llama_suspects[pid] = (pair, cls)

        # 5. Union: heuristic-suspect ∪ llama-suspect
        union_keys = set(heuristic_suspects) | set(llama_suspects)
        log.info(
            "flow_batch_llama_summary",
            llama_suspects=len(llama_suspects),
            union_suspects=len(union_keys),
        )
        self.last_window_stats["ip_pairs_suspect_llama"] = len(llama_suspects)
        self.last_window_stats["ip_pairs_suspect"] = len(union_keys)

        if not union_keys:
            await self._publish_window_summary(
                window_start, window_end, [p for p, _ in scored], llama_results, heuristic_suspects, skipped=False
            )
            return

        # 6. Dispatch each suspect IP-pair as a synthetic alert
        dispatched = 0
        for pid in union_keys:
            pair = heuristic_suspects.get(pid, (None,))[0] or llama_suspects.get(pid, (None,))[0]
            heur_score = heuristic_suspects.get(pid, (None, 0))[1]
            llama_cls = llama_suspects.get(pid, (None, {}))[1] if pid in llama_suspects else {}
            try:
                synth = _build_synthetic_alert(pair, heur_score, llama_cls)
                await self._on_alert(synth)
                dispatched += 1
            except Exception as exc:
                log.error(
                    "flow_batch_dispatch_error",
                    src=pair.src_ip if pair else "?",
                    dst=pair.dest_ip if pair else "?",
                    error=str(exc),
                )
        self.last_window_stats["dispatched"] = dispatched
        await self._publish_window_summary(
            window_start, window_end, [p for p, _ in scored], llama_results, heuristic_suspects, skipped=False
        )


def _pair_key(pair: AggregatedIPPair) -> str:
    return (
        f"{pair.src_ip}→{pair.dest_ip}"
        f":{pair.unique_dst_ports[0] if pair.unique_dst_ports else 0}"
    )


def _build_synthetic_alert(
    pair: AggregatedIPPair,
    score: int,
    llama_cls: dict | None = None,
) -> SuricataAlert:
    """Convert an aggregated IP-pair into a SuricataAlert-shaped record so
    the existing Stage 1 pipeline can consume it.

    SID = 9900000 + score_bucket. Severity inferred from heuristic score:
      score >= 5 → P1
      score 3-4  → P2
      score 2    → P3
      score 0-1  (LLaMA-only) → P3 (lean toward log_only unless GLM disagrees)
    """
    if score >= 5:
        severity = 1
    elif score >= 3:
        severity = 2
    else:
        severity = 3

    sid = _SYNTHETIC_SID_BASE + min(score, 99)

    # Primary destination port = most common from unique_dst_ports
    dest_port = pair.unique_dst_ports[0] if pair.unique_dst_ports else 0

    proto = "tcp" if pair.tcp_flow_count >= pair.udp_flow_count else "udp"

    signature = (
        f"FLOW_BATCH suspect (score={score}) "
        f"{pair.src_zone or '?'}→{pair.dest_zone or '?'} "
        f"{pair.src_ip}→{pair.dest_ip} "
        f"flows={pair.flow_count} "
        f"unique_ports={pair.unique_dst_port_count} "
        f"bytes_to_server={pair.bytes_toserver_sum} "
        f"bytes_to_client={pair.bytes_toclient_sum}"
    )

    alert_blob = {
        "signature_id": sid,
        "signature": signature,
        "severity": severity,
        "category": "flow-batch-anomaly",
        # Flow features as JSON payload so the agent prompt can see them
        "flow_features": pair.model_dump(),
        "suspect_score": score,
        "llama_classification": llama_cls or {},
    }

    return SuricataAlert(
        timestamp=pair.window_end,
        src_ip=pair.src_ip,
        dest_ip=pair.dest_ip,
        src_port=0,
        dest_port=dest_port,
        proto=proto,
        alert=alert_blob,
        raw={
            "event_type": "flow_batch",
            "src_ip": pair.src_ip,
            "dest_ip": pair.dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "alert": alert_blob,
            "flow_window": {
                "start": pair.window_start,
                "end": pair.window_end,
            },
            "flow_features": pair.model_dump(),
        },
    )
