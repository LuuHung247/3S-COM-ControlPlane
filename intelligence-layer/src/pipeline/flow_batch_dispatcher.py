"""FlowBatchDispatcher — window-close callback that:
  1. Aggregates flows into per-IP-pair records (FlowAggregator)
  2. Cheap rule-based pre-filter (suspect_score) to skip clearly-normal traffic
  3. Checks the agent trigger flag (Redis key `agent:trigger:enabled`)
  4. If enabled, builds a synthetic SuricataAlert per suspect IP-pair and
     dispatches via the existing `on_alert` callback (reusing the full
     Stage 1 pipeline + 9-layer safety).

Token-economy notes:
  - Pre-filter drops obvious benign traffic before any LLM call (~95% saving)
  - Toggle=OFF short-circuits the entire dispatch — 0 tokens
  - Each surviving IP-pair becomes one Stage 1 call (~3K input + 500 output)
"""
from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

import structlog

from ..models.alert import SuricataAlert
from ..models.flow import SuricataFlowEvent, AggregatedIPPair
from ..storage.redis import RedisStore
from .flow_aggregator import aggregate_flows, suspect_score

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
    ) -> None:
        self._on_alert = on_alert
        self._redis = redis
        self._ip_to_zone = ip_to_zone
        self._suspect_threshold = suspect_threshold

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

        # 2. Cheap pre-filter
        scored = [(p, suspect_score(p)) for p in aggregated]
        suspects = [(p, s) for p, s in scored if s >= self._suspect_threshold]

        log.info(
            "flow_batch_summary",
            flows_in_window=len(flows),
            ip_pairs_total=len(aggregated),
            ip_pairs_suspect=len(suspects),
            top_score=max((s for _, s in scored), default=0),
        )

        if not suspects:
            return

        # 3. Toggle gate — token economy control
        enabled = await self._trigger_enabled()
        if not enabled:
            log.info(
                "flow_batch_agent_disabled_skip_dispatch",
                suspects_skipped=len(suspects),
            )
            return

        # 4. Dispatch each suspect IP-pair as a synthetic alert
        for pair, score in suspects:
            try:
                synth = _build_synthetic_alert(pair, score)
                await self._on_alert(synth)
            except Exception as exc:
                log.error(
                    "flow_batch_dispatch_error",
                    src=pair.src_ip,
                    dst=pair.dest_ip,
                    error=str(exc),
                )


def _build_synthetic_alert(pair: AggregatedIPPair, score: int) -> SuricataAlert:
    """Convert an aggregated IP-pair into a SuricataAlert-shaped record so
    the existing Stage 1 pipeline can consume it.

    SID = 9900000 + score_bucket (reserves a recognizable namespace).
    Severity inferred from score:
      score >= 5 → P1 (severity=1)
      score 3-4  → P2 (severity=2)
      score 2    → P3 (severity=3)
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
