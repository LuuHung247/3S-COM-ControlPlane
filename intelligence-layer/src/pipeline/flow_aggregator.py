"""FlowAggregator — group flow events by IP-pair within a window.

For each `(src_ip, dest_ip)` pair, computes the NetVigil Table 2 features
(packet/byte sums + max, TCP/UDP flow counts, unique dest ports/app_protos).
Output: list[AggregatedIPPair] which the batch dispatcher feeds to the agent.

Source-of-truth for the feature schema: knowledge/infra/flow-features.md
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from ..models.flow import SuricataFlowEvent, AggregatedIPPair


def aggregate_flows(
    flows: Iterable[SuricataFlowEvent],
    window_start: str,
    window_end: str,
    ip_to_zone: callable | None = None,
) -> list[AggregatedIPPair]:
    """Aggregate flow events into per-IP-pair records.

    Args:
        flows: iterable of flow events captured in the window
        window_start, window_end: ISO timestamps for the window boundaries
        ip_to_zone: optional callable(ip) -> zone name (for src_zone/dest_zone enrichment)
    """
    buckets: dict[tuple[str, str], list[SuricataFlowEvent]] = defaultdict(list)
    for f in flows:
        if not f.src_ip or not f.dest_ip:
            continue
        buckets[(f.src_ip, f.dest_ip)].append(f)

    aggregated: list[AggregatedIPPair] = []
    for (src, dst), bucket in buckets.items():
        tcp = sum(1 for f in bucket if f.proto.lower() == "tcp")
        udp = sum(1 for f in bucket if f.proto.lower() == "udp")
        pkts_ts = [f.pkts_toserver for f in bucket]
        pkts_tc = [f.pkts_toclient for f in bucket]
        bytes_ts = [f.bytes_toserver for f in bucket]
        bytes_tc = [f.bytes_toclient for f in bucket]
        dst_ports = sorted({f.dest_port for f in bucket if f.dest_port})
        app_protos = sorted({f.app_proto for f in bucket if f.app_proto})
        states = sorted({f.flow_state for f in bucket})
        flow_ids = [f.flow_id for f in bucket if f.flow_id]

        agg = AggregatedIPPair(
            src_ip=src,
            dest_ip=dst,
            window_start=window_start,
            window_end=window_end,
            flow_count=len(bucket),
            tcp_flow_count=tcp,
            udp_flow_count=udp,
            pkts_toserver_sum=sum(pkts_ts),
            pkts_toclient_sum=sum(pkts_tc),
            bytes_toserver_sum=sum(bytes_ts),
            bytes_toclient_sum=sum(bytes_tc),
            pkts_toserver_max=max(pkts_ts) if pkts_ts else 0,
            pkts_toclient_max=max(pkts_tc) if pkts_tc else 0,
            bytes_toserver_max=max(bytes_ts) if bytes_ts else 0,
            bytes_toclient_max=max(bytes_tc) if bytes_tc else 0,
            unique_dst_ports=dst_ports,
            unique_dst_port_count=len(dst_ports),
            unique_app_protos=app_protos,
            states_observed=states,
            flow_ids=flow_ids,
            src_zone=(ip_to_zone(src) if ip_to_zone else "") or "",
            dest_zone=(ip_to_zone(dst) if ip_to_zone else "") or "",
        )
        aggregated.append(agg)

    return aggregated


def suspect_score(pair: AggregatedIPPair) -> int:
    """Lightweight heuristic to flag IP-pairs worth the LLM call.

    Returns: int score; >=2 is "suspicious enough to dispatch to agent".
    Cheap rule-based pre-filter so the toggle keeps token usage tractable
    even when toggle=ON.

    Signals (additive):
      +2  cross-zone with critical dest (DB/MGT) and >1 flow
      +2  unusual dst port (admin: 22/3389) from non-MGT source
      +1  high flow count (>10)
      +2  fan-out (many unique dst ports >5)
      +1  off-hours (caller checks; we just return base score here)
    """
    score = 0
    src_z = pair.src_zone.upper()
    dst_z = pair.dest_zone.upper()

    if src_z != dst_z and dst_z in {"DB", "MGT"} and pair.flow_count > 1:
        score += 2

    # admin port from workload tier
    admin_ports = {22, 3389, 5985, 5986}
    if any(p in admin_ports for p in pair.unique_dst_ports) and src_z not in {"MGT"}:
        score += 2

    if pair.flow_count > 10:
        score += 1

    if pair.unique_dst_port_count > 5:
        score += 2

    # DB initiating outbound (sensitive zone outbound)
    if src_z == "DB" and dst_z and dst_z != "DB":
        score += 3

    return score
