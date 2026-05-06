"""Agent tools and forced-output schema.

The agent has ONE action capability: push DROP rule via Secure Framework.
Investigation tools below are READ-ONLY data fetchers — they enrich LLM context
but never mutate system state. They are pre-fetched in parallel during
node_gather_context and injected into the LLM prompt (single-call enriched, not ReAct).
"""
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, func

from ..storage.redis import RedisStore
from ..storage.postgres import DecisionRecord, PostgresStore
from ..core import system_model, baselines, topology
from ..core.threat_playbook import find_kill_chain_stage


# ─────────────────────────────────────────────────────────────────────────────
# LLM-callable tool definitions (only get_alert_history is LLM-facing)
# ─────────────────────────────────────────────────────────────────────────────
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_alert_history",
            "description": "Retrieve the recent alert history for a given source IP from cache.",
            "parameters": {
                "type": "object",
                "properties": {
                    "src_ip": {"type": "string"},
                    "limit": {"type": "integer", "default": 10},
                },
                "required": ["src_ip"],
            },
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# SPLIT SCHEMAS (V3) — separate critical-path policy from audit-only reasoning
#
# Group 1 — POLICY_DECISION_SCHEMA: scalar fields only, ~0% Cerebras parser fail
#   Used for: SF rule push, L7 confidence gate, response cache key
#   Blocking — agent cannot enforce without this
#
# Group 2 — REASONING_TRACE_SCHEMA: array-heavy, audit/HITL metadata
#   Used for: Langfuse trace, frontend modal, retrospective learning
#   Non-blocking — fail-tolerant, decision still enforces if this call fails
#
# The legacy POLICY_INTENT_SCHEMA (15 fields, 4 arrays) is kept as alias for
# backward-compatibility with existing self_consistency_vote callsite, but
# graph.py now invokes the two split schemas separately.
# ─────────────────────────────────────────────────────────────────────────────

POLICY_DECISION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["DROP", "log_only"],
            "description": "Policy action. DROP for P1/P2 threats. log_only for P3/P4 or low confidence.",
        },
        "src_ip": {"type": "string", "description": "CIDR e.g. 10.1.100.10/32. MUST contain alert.src_ip."},
        "dst_ip": {"type": "string", "description": "CIDR or empty string."},
        "dst_port": {"type": "integer"},
        "protocol": {"type": "string", "description": "tcp / udp / icmp / all"},
        "priority": {"type": "integer", "description": "MUST be 50 for agent rules."},
        "ttl_seconds": {"type": "integer", "description": "3600 for P1, 1800 for P2, 0 for log_only."},
        "comment": {"type": "string", "description": "Short rule description (under 80 chars)."},
        "confidence": {
            "type": "number",
            "minimum": 0.0, "maximum": 1.0,
            "description": "Calibrated confidence in this decision; gates enforcement at 0.85/0.70/0.50.",
        },
    },
    "required": ["action", "src_ip", "confidence"],
}


REASONING_TRACE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "primary_hypothesis": {
            "type": "string",
            "description": "Short name of the leading hypothesis that drove the action.",
        },
        "hypotheses": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "2-3 candidate hypotheses, each as one string: "
                "'<name> (probability=<0.X>) — <description>. Evidence: ... Counter: ...'."
            ),
        },
        "reasoning_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Step-by-step reasoning chain leading to the decision.",
        },
        "alternative_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Plan B entries as strings: 'if <condition> then <action> because <reason>'.",
        },
        "rollback_plan": {
            "type": "string",
            "description": "Trigger + action + monitor window if rule causes outage.",
        },
        "follow_up_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Things to monitor after enforce (kill-chain progression).",
        },
        "mitre_technique": {"type": "string", "description": "T-number, e.g. T1021."},
        "mitre_tactic": {"type": "string", "description": "TA-number, e.g. TA0008."},
    },
    "required": ["primary_hypothesis", "reasoning_steps"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Legacy combined schema — kept for self_consistency_vote backward compat
# ─────────────────────────────────────────────────────────────────────────────
POLICY_INTENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        # Primary action
        "action": {
            "type": "string",
            "enum": ["DROP", "log_only"],
            "description": "Policy action. DROP for P1/P2 threats. log_only for P3/P4 or low confidence.",
        },
        "src_ip": {"type": "string"},
        "dst_ip": {"type": "string"},
        "dst_port": {"type": "integer"},
        "protocol": {"type": "string"},
        "priority": {"type": "integer", "description": "MUST be 50."},
        "ttl_seconds": {"type": "integer", "description": "3600 for P1, 1800 for P2, 0 for log_only."},
        "comment": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reasoning_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Step-by-step reasoning chain.",
        },
        "mitre_technique": {"type": "string"},
        "mitre_tactic": {"type": "string"},

        # Hypothesis-driven reasoning (V2 — flat strings to keep Cerebras tool-call parser happy)
        "hypotheses": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "2-3 candidate hypotheses, each as a single string formatted: "
                "'<name> (probability=<0.X>) — <description>. Evidence: <supporting>. "
                "Counter: <disconfirming>'. Models engineer mental process of considering "
                "alternatives before deciding."
            ),
        },
        "primary_hypothesis": {
            "type": "string",
            "description": "Name of the chosen hypothesis that drives the action.",
        },
        "alternative_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Plan B if primary hypothesis turns out wrong. Each entry as string: "
                "'if <trigger_condition> then <action> because <rationale>'."
            ),
        },
        "rollback_plan": {
            "type": "string",
            "description": (
                "If the rule causes outage, how to revert. Format: "
                "'Trigger: <observable>. Action: <revoke command>. Monitor for <N>s.'"
            ),
        },
        "follow_up_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "What to monitor after enforcement (e.g., 'check at T+10min if SID 9000002 fires').",
        },
    },
    "required": ["action", "src_ip", "confidence", "reasoning_steps", "hypotheses", "primary_hypothesis"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Tool: get_alert_history (LLM-facing, kept for backward compat)
# ─────────────────────────────────────────────────────────────────────────────
async def execute_get_alert_history(redis: RedisStore, src_ip: str, limit: int = 10) -> dict:
    history = await redis.get_alert_history(src_ip, limit=limit)
    return {"src_ip": src_ip, "count": len(history), "history": history}


# ─────────────────────────────────────────────────────────────────────────────
# INVESTIGATION TOOLS — pre-fetched in parallel, injected into prompt
# ─────────────────────────────────────────────────────────────────────────────
async def query_asset_neighbors(ip: str) -> dict:
    """Tool 1: Map blast radius. What assets connect to this IP, what flows depend on it?

    Pure in-memory query against system_model + baselines. ~5ms.
    Used to inform LLM about consequences before block.
    """
    bare = ip.split("/")[0]
    asset = system_model.get_asset(bare)
    if asset is None:
        return {
            "ip": bare,
            "asset_known": False,
            "blast_radius_score": "unknown",
            "note": "IP not in asset inventory — cannot assess impact precisely.",
        }

    # Find baseline flows that depend on this IP (either as src or dst)
    flows_as_source = [b for b in baselines.ALL_BASELINES if b.src_ip == bare]
    flows_as_destination = [
        b for b in baselines.ALL_BASELINES
        if b.dst_ip == bare or (b.dst_ip == "rotating" and b.src_ip == "10.2.50.10")
    ]

    blast_radius = "low"
    if asset.criticality.value == "critical":
        blast_radius = "high"
    elif asset.criticality.value == "high":
        blast_radius = "medium"
    if len(flows_as_destination) >= 3:
        blast_radius = "high"

    return {
        "ip": bare,
        "asset_known": True,
        "hostname": asset.hostname,
        "tier": asset.tier,
        "criticality": asset.criticality.value,
        "expected_inbound_count": len(flows_as_destination),
        "expected_outbound_count": len(flows_as_source),
        "outbound_flows": [
            {"name": f.name, "criticality": f.criticality_to_business.value}
            for f in flows_as_source
        ],
        "inbound_flows": [
            {"name": f.name, "criticality": f.criticality_to_business.value}
            for f in flows_as_destination
        ],
        "blast_radius_score": blast_radius,
        "if_blocked": asset.if_blocked_impact,
    }


async def find_similar_past_incidents(
    postgres: PostgresStore,
    sid: int,
    src_zone: str | None,
    dst_zone: str | None,
    lookback_days: int = 90,
    limit: int = 5,
) -> dict:
    """Tool 2: Past experience lookup. How did agent decide for similar (sid, src_zone, dst_zone)
    in the past? Outcomes? Recurrence patterns?

    Postgres aggregation. ~30ms.
    """
    if postgres._engine is None:
        return {"match_count": 0, "note": "Postgres unavailable"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    from sqlalchemy.ext.asyncio import async_sessionmaker

    async with async_sessionmaker(postgres._engine, expire_on_commit=False)() as sess:
        # Count + outcome breakdown (zone filter optional — apply only if both known)
        base_filters = [DecisionRecord.alert_sid == sid, DecisionRecord.created_at >= cutoff]

        count_q = await sess.execute(
            select(func.count()).where(*base_filters)
        )
        match_count = count_q.scalar() or 0

        if match_count == 0:
            return {
                "sid": sid,
                "src_zone": src_zone,
                "dst_zone": dst_zone,
                "lookback_days": lookback_days,
                "match_count": 0,
                "note": "No similar past incidents — first time agent sees this pattern in window.",
            }

        outcome_q = await sess.execute(
            select(DecisionRecord.outcome, func.count())
            .where(*base_filters)
            .group_by(DecisionRecord.outcome)
        )
        outcome_breakdown = {row[0]: row[1] for row in outcome_q.all()}

        # Last N decisions full record
        last_q = await sess.execute(
            select(
                DecisionRecord.id,
                DecisionRecord.created_at,
                DecisionRecord.outcome,
                DecisionRecord.action,
                DecisionRecord.confidence,
            )
            .where(*base_filters)
            .order_by(DecisionRecord.created_at.desc())
            .limit(limit)
        )
        last_decisions = [
            {
                "id": r[0],
                "date": r[1].isoformat(),
                "outcome": r[2],
                "action": r[3],
                "confidence": r[4],
            }
            for r in last_q.all()
        ]

    enforced_count = outcome_breakdown.get("enforced", 0)
    accuracy_signal = "no signal"
    if enforced_count > 0:
        accuracy_signal = f"agent enforced {enforced_count}/{match_count} times — pattern is recurring threat"

    return {
        "sid": sid,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "lookback_days": lookback_days,
        "match_count": match_count,
        "outcome_breakdown": outcome_breakdown,
        "last_decisions": last_decisions,
        "pattern_assessment": accuracy_signal,
    }


async def simulate_block_impact(src_ip: str, dst_ip: str = "", dst_port: int = 0) -> dict:
    """Tool 3: Counterfactual reasoning. If we block this rule, what business flows break?

    Compare full-source-block vs targeted-block (src+dst+port). Helps LLM choose
    minimum-blast-radius rule.

    Pure Pydantic cross-reference. ~5ms.
    """
    bare_src = src_ip.split("/")[0]
    bare_dst = dst_ip.split("/")[0] if dst_ip else ""

    src_asset = system_model.get_asset(bare_src)
    dst_asset = system_model.get_asset(bare_dst) if bare_dst else None

    # Full source block — what breaks if we DROP all from src?
    affected_outbound = [b for b in baselines.ALL_BASELINES if b.src_ip == bare_src]
    affected_inbound = [
        b for b in baselines.ALL_BASELINES
        if b.dst_ip == bare_src or (b.dst_ip == "rotating" and bare_src in {"10.1.100.10", "10.2.100.10", "10.1.200.10"})
    ]

    # Targeted block (src + dst + port) — what breaks?
    targeted_match = baselines.match_baseline(bare_src, bare_dst, dst_port) if bare_dst and dst_port else None

    return {
        "src_ip": bare_src,
        "dst_ip": bare_dst,
        "dst_port": dst_port,

        "full_block_impact": {
            "rule_form": f"DROP all from {bare_src}",
            "outbound_flows_broken": [
                {"name": b.name, "criticality": b.criticality_to_business.value, "consequence": b.if_disrupted}
                for b in affected_outbound
            ],
            "inbound_flows_broken_count": len(affected_inbound),
            "asset_consequence": src_asset.if_blocked_impact if src_asset else "unknown impact",
        },

        "targeted_block_impact": {
            "rule_form": f"DROP {bare_src} → {bare_dst}:{dst_port}" if bare_dst else "(no dst — N/A)",
            "matches_legitimate_baseline": targeted_match is not None,
            "baseline_name": targeted_match.name if targeted_match else None,
            "narrow_scope": "Only this specific flow blocked — legitimate flows from same src preserved.",
        },

        "recommendation": (
            "TARGETED block (src+dst+port) preferred — preserves legitimate flows from same source. "
            "Use FULL block only if attacker pattern is multi-destination scanning."
            if dst_ip and dst_port else
            "Insufficient flow tuple for targeted block — only full-source available."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Aggregator — pre-fetch all 3 investigation tools in parallel
# ─────────────────────────────────────────────────────────────────────────────
async def prefetch_investigation_context(
    postgres: PostgresStore,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    sid: int,
) -> dict:
    """Run all 3 investigation tools in parallel. ~30ms total (limited by Postgres query)."""
    import asyncio

    src_zone = topology.ip_to_zone(src_ip)
    dst_zone = topology.ip_to_zone(dst_ip) if dst_ip else None

    neighbors, past, impact = await asyncio.gather(
        query_asset_neighbors(src_ip),
        find_similar_past_incidents(postgres, sid, src_zone, dst_zone),
        simulate_block_impact(src_ip, dst_ip, dst_port),
        return_exceptions=True,
    )

    # Kill chain stage match (in-memory, ~1ms)
    kc_matches = find_kill_chain_stage(sid)
    kill_chain_context = []
    for kc, stage in kc_matches:
        kill_chain_context.append({
            "kill_chain": kc.name,
            "stage": stage.stage,
            "tactic": stage.tactic,
            "expected_signals": stage.expected_signals,
            "indicator": stage.production_indicators,
            "intervention_point": kc.recommended_intervention_point,
            "containment_strategy": kc.containment_strategy,
        })

    return {
        "asset_neighbors": neighbors if not isinstance(neighbors, Exception) else {"error": str(neighbors)},
        "past_incidents": past if not isinstance(past, Exception) else {"error": str(past)},
        "block_impact": impact if not isinstance(impact, Exception) else {"error": str(impact)},
        "kill_chain_match": kill_chain_context,
    }
