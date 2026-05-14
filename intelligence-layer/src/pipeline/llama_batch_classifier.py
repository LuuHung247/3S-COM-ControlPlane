"""LLaMA batch classifier — Tier-1 LLM triage between heuristic and GLM Stage 1.

One LLaMA call per window (not per flow) → classifies every aggregated IP-pair
as NORMAL / SUSPECT_<class>. Only SUSPECT_* pairs forward to GLM Stage 1.

Cost shape per 2-min window:
  - 1 LLaMA call (cheap, ~$0.0001)
  - K GLM Stage 1 calls (K = SUSPECT pairs, expensive)

Combined with cheap Python heuristic (suspect_score) for OBVIOUS cases:
the heuristic catches policy violations / known patterns without any LLM;
LLaMA judges borderline cases the heuristic flagged with score 0–1.

Match paper: NetVigil-style window batch, 2-stage triage (cost-aware).
"""
from __future__ import annotations

from typing import Any

import structlog

from ..agent.llm.interface import LLMClient
from ..models.flow import AggregatedIPPair

log = structlog.get_logger()


# Output schema: per-pair label
_CLASSIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "classifications": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "pair_id": {"type": "string",
                                "description": "Echo back src_ip→dest_ip:dst_port"},
                    "label": {
                        "type": "string",
                        "enum": [
                            "NORMAL",
                            "SUSPECT_scan",
                            "SUSPECT_exfil",
                            "SUSPECT_burst",
                            "SUSPECT_c2_beacon",
                            "SUSPECT_lateral",
                            "SUSPECT_content",
                            "SUSPECT_other",
                        ],
                        "description": (
                            "NORMAL = baseline traffic (no agent action needed). "
                            "SUSPECT_* = forward to deeper agent reasoning."
                        ),
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                    },
                    "reason": {
                        "type": "string",
                        "description": "≤ 100 chars rationale for label.",
                    },
                },
                "required": ["pair_id", "label", "confidence"],
            },
        },
    },
    "required": ["classifications"],
}


def _build_pair_summary(pair: AggregatedIPPair) -> str:
    """Compact 1-line summary of features for prompt."""
    return (
        f"{pair.src_ip}→{pair.dest_ip}:{pair.unique_dst_ports[:3] or [0]} "
        f"({pair.src_zone or '?'}→{pair.dest_zone or '?'}) "
        f"flows={pair.flow_count} tcp={pair.tcp_flow_count} udp={pair.udp_flow_count} "
        f"unique_dst_ports={pair.unique_dst_port_count} "
        f"bytes_tx={pair.bytes_toserver_sum} bytes_rx={pair.bytes_toclient_sum} "
        f"states={pair.states_observed}"
    )


def _build_pair_id(pair: AggregatedIPPair) -> str:
    return (
        f"{pair.src_ip}→{pair.dest_ip}"
        f":{pair.unique_dst_ports[0] if pair.unique_dst_ports else 0}"
    )


_SYSTEM_PROMPT = """You are a fast Tier-1 triage classifier for east-west data center
network anomalies.

Input: a batch of IP-pair aggregations from one 2-minute window.
Output: per-pair label + confidence.

CONTEXT:
- Zones: WEB 10.1.100/24, DB 10.1.200/24, APP 10.2.100/24, MGT 10.2.50/24
- Allowed paths: WEB→APP, APP→DB, MGT→ANY (audit), ICMP/health
- DENY paths (always suspect): WEB→DB direct, DB outbound, workload→workload SSH
- Baselines: WEB→APP ~60/min, APP→DB OLTP ~60/min, MGT compliance traffic NEVER blocks
- NEVER_BLOCK: MGT host (10.2.50.10) — always NORMAL even at high rate

TASK:
For EACH input pair, choose ONE label:
- NORMAL — matches baseline / allowed path / MGT compliance
- SUSPECT_scan — fan-out (many unique dst ports OR many unique dst IPs)
- SUSPECT_exfil — high outbound volume OR DB→outside
- SUSPECT_burst — rate >>baseline (e.g., 200+/min on a 60/min baseline)
- SUSPECT_c2_beacon — periodic small outbound to external
- SUSPECT_lateral — workload→workload admin port (22/3389)
- SUSPECT_content — destructive content pattern (needs deeper inspection)
- SUSPECT_other — anomaly not clearly fitting above

Be CONSERVATIVE: when in doubt between NORMAL and SUSPECT_*, lean SUSPECT_*
(downstream agent will reason in detail). Cost of false-NORMAL > false-SUSPECT.

Be DECISIVE on baselines: MGT compliance, normal OLTP, normal proxy → NORMAL with confidence ≥ 0.85.
"""


async def classify_batch(
    fast_llm: LLMClient,
    pairs: list[AggregatedIPPair],
) -> dict[str, dict[str, Any]]:
    """Single LLaMA call over the entire window's IP-pair set.

    Returns: {pair_id → {label, confidence, reason}}
    On error: returns {} (caller should fall back to heuristic-only).
    """
    if not pairs:
        return {}

    pair_lines = "\n".join(f"- {_build_pair_summary(p)}" for p in pairs)
    user_msg = (
        f"Window batch — {len(pairs)} IP-pair(s):\n\n"
        f"{pair_lines}\n\n"
        f"Classify each pair. Echo `pair_id` exactly as src_ip→dest_ip:port "
        f"(use the FIRST dst port if multiple)."
    )

    try:
        result = await fast_llm.chat_json(
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            schema=_CLASSIFY_SCHEMA,
        )
    except Exception as exc:
        log.warning("llama_classify_failed", error=str(exc))
        return {}

    out: dict[str, dict[str, Any]] = {}
    raw_items = result.get("classifications", []) if isinstance(result, dict) else []
    # llama3.1-8b sometimes emits the nested array as a JSON-encoded string.
    # Try to parse it back into a list so downstream code is uniform.
    if isinstance(raw_items, str):
        # llama3.1-8b sometimes emits as JSON string OR Python repr (single quotes).
        # Try JSON first, then ast.literal_eval as fallback for Python-style.
        import json as _json
        import ast
        parsed = None
        try:
            parsed = _json.loads(raw_items)
        except _json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(raw_items)
            except (ValueError, SyntaxError) as e:
                log.warning(
                    "llama_classify_bad_shape",
                    got="str_unparseable",
                    err=str(e)[:100],
                    preview=raw_items[:200],
                )
                return {}
        raw_items = parsed
    if not isinstance(raw_items, list):
        log.warning("llama_classify_bad_shape", got=type(raw_items).__name__)
        return {}
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("pair_id", "") or "")
        if not pid:
            continue
        try:
            conf = float(item.get("confidence", 0.5) or 0.5)
        except (TypeError, ValueError):
            conf = 0.5
        out[pid] = {
            "label": str(item.get("label", "SUSPECT_other") or "SUSPECT_other"),
            "confidence": conf,
            "reason": str(item.get("reason", "") or "")[:160],
        }
    log.info(
        "llama_batch_classified",
        pairs_in=len(pairs),
        pairs_classified=len(out),
        normal_count=sum(1 for v in out.values() if v["label"] == "NORMAL"),
        suspect_count=sum(1 for v in out.values() if v["label"].startswith("SUSPECT")),
    )
    return out
