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
# query_kg — read-only Cypher executor against the agent's knowledge graph.
#
# Designed to be exposed to the LLM via tool-calling. The agent decides which
# Cypher to write based on the alert + reasoning state. Server-side enforces:
#   - Read-only (rejects CREATE / DELETE / MERGE / SET / REMOVE / DROP / DETACH)
#   - Result size cap (50 records max — bounds prompt cost when fed back to LLM)
#   - Timeout (5s — Neo4j driver hard limit)
# ─────────────────────────────────────────────────────────────────────────────
import re as _re
# Word-boundary regex avoids false matches like "SET" inside "Asset".
_KG_WRITE_KEYWORD_RE = _re.compile(
    r"\b(CREATE|DELETE|MERGE|SET|REMOVE|DROP|DETACH|FOREACH|"
    r"LOAD\s+CSV|CALL\s+DBMS|CALL\s+APOC\.LOAD)\b",
    _re.IGNORECASE,
)
_KG_RESULT_LIMIT = 50
_KG_TIMEOUT_SECONDS = 5.0


async def execute_query_kg(driver, cypher: str) -> dict[str, Any]:
    """Run a read-only Cypher query and return rows + metadata.

    Driver: an open neo4j AsyncDriver (from app.state.neo4j_kg.driver).
    Returns: {ok: bool, rows: list[dict], row_count, truncated, error}.

    Safety: rejects any write keyword, caps row count, enforces timeout.
    The agent is expected to write valid Cypher against the schema documented
    in the tool description (see TOOL_DEFINITIONS below).
    """
    if driver is None:
        return {"ok": False, "rows": [], "row_count": 0, "truncated": False,
                "error": "Neo4j driver unavailable — KG offline."}

    write_match = _KG_WRITE_KEYWORD_RE.search(cypher)
    if write_match:
        return {"ok": False, "rows": [], "row_count": 0, "truncated": False,
                "error": f"Write operation '{write_match.group(0).upper()}' rejected — query_kg is read-only."}

    try:
        async with driver.session() as sess:
            result = await sess.run(cypher, timeout=_KG_TIMEOUT_SECONDS)
            rows: list[dict[str, Any]] = []
            truncated = False
            async for r in result:
                if len(rows) >= _KG_RESULT_LIMIT:
                    truncated = True
                    break
                # Convert Neo4j Node/Relationship to plain dict
                d: dict[str, Any] = {}
                for k, v in dict(r).items():
                    if hasattr(v, "items"):  # Node / Relationship
                        d[k] = {kk: vv for kk, vv in dict(v).items()
                                if kk not in ("kg_managed",)}
                    elif isinstance(v, (list, tuple)):
                        d[k] = list(v)
                    else:
                        d[k] = v
                rows.append(d)
        return {"ok": True, "rows": rows, "row_count": len(rows),
                "truncated": truncated, "error": None}
    except Exception as exc:
        return {"ok": False, "rows": [], "row_count": 0, "truncated": False,
                "error": f"Cypher error: {exc.__class__.__name__}: {exc}"}


# ─────────────────────────────────────────────────────────────────────────────
# LLM-callable tool definitions (exposed in chat_react)
# ─────────────────────────────────────────────────────────────────────────────
QUERY_KG_TOOL_DESCRIPTION = """Run a read-only Cypher query against the knowledge graph.

Use this when you need a specific fact about the datacenter that ISN'T in your
system prompt. Your prompt has high-level architecture + invariants — for any
specific entity (zone CIDR, asset blast radius, baseline match, kill chain
stage, SID detail), use this tool instead of guessing.

## SCHEMA

Nodes:
  (:Zone {name, cidr, leaf, vlan, svi_gateway, trust_level, criticality, purpose})
  (:Asset {ip, hostname, zone, tier, role, criticality, data_classification,
           owner_team, services_json, expected_inbound_sources,
           expected_outbound_destinations, if_compromised_impact, if_blocked_impact})
  (:Leaf {name, mgmt_ip, zones, role})
  (:Sid {sid, severity_p_level, signature_msg, production_description,
         mitre_tactic, mitre_technique, detection_logic, recommended_response,
         default_ttl_seconds, false_positive_likelihood, false_positive_scenarios})
  (:KillChain {name, production_description, typical_dwell,
               recommended_intervention, containment_strategy, stage_count})
  (:Baseline {name, src_zone, src_ip, dst_zone, dst_ip, dst_port, proto,
              cadence, expected_volume_per_hour, burst_anomaly_threshold,
              criticality_to_business, production_description, if_disrupted})
  (:NeverBlockEntry {cidr, rationale})
  (:KnowledgeMeta {key, ...})  — singletons (baseline_constants, rbac_contract, agent_invariants)

Edges:
  (:Asset)-[:MEMBER_OF]->(:Zone)
  (:Leaf)-[:ENFORCES]->(:Zone)
  (:Zone)-[:ALLOW]->(:Zone)   — policy matrix
  (:Zone)-[:DENY]->(:Zone)
  (:Sid)-[:EXPECTED_IN {stage, tactic, indicators, false_positive_sources}]->(:KillChain)

## EXAMPLES

Get full asset profile:
  MATCH (a:Asset {ip: '10.1.100.10'}) RETURN a

Find baselines involving a src IP (is this flow legitimate?):
  MATCH (b:Baseline) WHERE b.src_ip = '10.1.100.10' OR b.dst_ip = '10.1.100.10'
  RETURN b.name, b.src_ip, b.dst_ip, b.dst_port, b.proto, b.criticality_to_business

Find kill chains containing this SID + which stage:
  MATCH (s:Sid {sid: 9000001})-[r:EXPECTED_IN]->(k:KillChain)
  RETURN k.name, r.stage, r.tactic, r.indicators, k.containment_strategy

Get SID detail with FP scenarios:
  MATCH (s:Sid {sid: 9000001}) RETURN s

Check policy verdict between zones:
  MATCH (s:Zone {name: 'WEB'})-[r:ALLOW|DENY]->(d:Zone {name: 'DB'}) RETURN type(r)

Find all assets in same zone (lateral movement candidates):
  MATCH (a:Asset)-[:MEMBER_OF]->(z:Zone {name: 'DB'}) RETURN a.ip, a.hostname

## CONSTRAINTS

- Read-only: no CREATE/DELETE/MERGE/SET/REMOVE.
- Max 50 rows returned (truncated if more — refine your query).
- 5s timeout. Keep queries simple — no expensive cartesian products.
- Use exact node labels and property names from the schema above.
"""


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "query_kg",
            "description": QUERY_KG_TOOL_DESCRIPTION,
            "parameters": {
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "Read-only Cypher query against the schema above.",
                    },
                },
                "required": ["cypher"],
            },
        },
    },
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
    semantic_query_text: str = "",
    mitre_technique: str | None = None,
    redis: RedisStore | None = None,
) -> dict:
    """Tool 2: Past experience lookup with **multi-strategy retrieval**.

    Three retrieval paths run in parallel and merge:
      1. Exact SID match (recall pattern of identical signature)
      2. Semantic vector search over decision embeddings (catches same MITRE
         technique with different SID, or same kill-chain stage from different src)
      3. MITRE technique exact-match filter (catches T1021 across SID variants)

    Postgres aggregation + pgvector cosine search. ~50-150ms total.
    """
    if postgres._engine is None:
        return {"match_count": 0, "note": "Postgres unavailable"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    from sqlalchemy.ext.asyncio import async_sessionmaker
    import asyncio as _asyncio

    # ── Sentinel pre-flight: any decisions in window? ──────────────────────
    # Fast COUNT (uses created_at index, ~2-5ms). When `decisions` is empty
    # (eval_iid post-truncate, fresh deployment, cold src_ip on new install),
    # skip the expensive semantic+MITRE+exact paths entirely. Saves ~250ms of
    # wasted embedding compute + pgvector probes per cold call.
    async with async_sessionmaker(postgres._engine, expire_on_commit=False)() as _sess:
        any_q = await _sess.execute(
            select(func.count()).select_from(DecisionRecord)
            .where(DecisionRecord.created_at >= cutoff)
        )
        any_count = any_q.scalar() or 0
    if any_count == 0:
        return {
            "sid": sid,
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "lookback_days": lookback_days,
            "match_count": 0,
            "semantic_match_count": 0,
            "mitre_match_count": 0,
            "note": "No decisions in window — sentinel short-circuit (cold cache).",
        }

    # ── Path 1: exact SID match (existing behavior) ─────────────────────────
    async def _exact_sid_match() -> dict:
        async with async_sessionmaker(postgres._engine, expire_on_commit=False)() as sess:
            base_filters = [DecisionRecord.alert_sid == sid, DecisionRecord.created_at >= cutoff]
            count_q = await sess.execute(select(func.count()).where(*base_filters))
            match_count = count_q.scalar() or 0
            if match_count == 0:
                return {"match_count": 0, "outcome_breakdown": {}, "last_decisions": []}
            outcome_q = await sess.execute(
                select(DecisionRecord.outcome, func.count())
                .where(*base_filters)
                .group_by(DecisionRecord.outcome)
            )
            outcome_breakdown = {row[0]: row[1] for row in outcome_q.all()}
            last_q = await sess.execute(
                select(
                    DecisionRecord.id, DecisionRecord.created_at, DecisionRecord.outcome,
                    DecisionRecord.action, DecisionRecord.confidence,
                ).where(*base_filters).order_by(DecisionRecord.created_at.desc()).limit(limit)
            )
            return {
                "match_count": match_count,
                "outcome_breakdown": outcome_breakdown,
                "last_decisions": [
                    {"id": r[0], "date": r[1].isoformat(), "outcome": r[2],
                     "action": r[3], "confidence": r[4]}
                    for r in last_q.all()
                ],
            }

    # ── Path 2: semantic vector search ──────────────────────────────────────
    async def _semantic_match() -> list[dict]:
        if not semantic_query_text:
            return []
        from ..storage.embedder import embed_text
        # Warm-cache embedding compute by hash(query_text). Embedder is
        # deterministic, so reusing across runs of the same scenario is safe.
        # Saves the ~150-200ms CPU embed compute on repeat queries.
        vec: list[float] | None = None
        cache_key: str | None = None
        if redis is not None:
            import hashlib
            cache_key = hashlib.sha1(semantic_query_text.encode("utf-8")).hexdigest()
            vec = await redis.get_cached_embedding(cache_key)
        if vec is None:
            vec = await embed_text(semantic_query_text)
            if vec is None:
                return []
            if redis is not None and cache_key is not None:
                await redis.cache_embedding(cache_key, vec)
        return await postgres.search_similar_by_embedding(
            embedding=vec,
            lookback_days=lookback_days,
            limit=limit,
            min_similarity=0.30,
        )

    # ── Path 3: MITRE technique exact match (different SID, same technique) ─
    async def _mitre_match() -> list[dict]:
        if not mitre_technique:
            return []
        async with async_sessionmaker(postgres._engine, expire_on_commit=False)() as sess:
            q = await sess.execute(
                select(
                    DecisionRecord.id, DecisionRecord.alert_sid,
                    DecisionRecord.created_at, DecisionRecord.outcome,
                    DecisionRecord.action, DecisionRecord.confidence,
                    DecisionRecord.primary_hypothesis,
                ).where(
                    DecisionRecord.mitre_technique == mitre_technique,
                    DecisionRecord.alert_sid != sid,           # exclude exact-SID overlap
                    DecisionRecord.created_at >= cutoff,
                ).order_by(DecisionRecord.created_at.desc()).limit(limit)
            )
            return [
                {"id": r[0], "alert_sid": r[1], "date": r[2].isoformat(),
                 "outcome": r[3], "action": r[4], "confidence": r[5],
                 "primary_hypothesis": r[6]}
                for r in q.all()
            ]

    exact, semantic, mitre = await _asyncio.gather(
        _exact_sid_match(), _semantic_match(), _mitre_match(),
        return_exceptions=True,
    )
    if isinstance(exact, Exception):
        exact = {"match_count": 0, "outcome_breakdown": {}, "last_decisions": []}
    if isinstance(semantic, Exception):
        semantic = []
    if isinstance(mitre, Exception):
        mitre = []

    exact_match_count = exact.get("match_count", 0)
    semantic_count = len(semantic)
    mitre_count = len(mitre)
    total_signals = exact_match_count + semantic_count + mitre_count

    if total_signals == 0:
        return {
            "sid": sid,
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "lookback_days": lookback_days,
            "match_count": 0,
            "semantic_match_count": 0,
            "mitre_match_count": 0,
            "note": "No similar past incidents — first time agent sees this pattern in window.",
        }

    enforced_count = exact.get("outcome_breakdown", {}).get("enforced", 0)
    accuracy_signal = "no signal"
    if enforced_count > 0:
        accuracy_signal = f"agent enforced {enforced_count}/{exact_match_count} times — pattern is recurring threat"
    if semantic_count > 0:
        accuracy_signal += f"; +{semantic_count} semantically-similar prior incident(s)"
    if mitre_count > 0:
        accuracy_signal += f"; +{mitre_count} MITRE {mitre_technique} match(es)"

    return {
        "sid": sid,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "lookback_days": lookback_days,
        "match_count": exact_match_count,
        "semantic_match_count": semantic_count,
        "mitre_match_count": mitre_count,
        "outcome_breakdown": exact.get("outcome_breakdown", {}),
        "last_decisions": exact.get("last_decisions", []),
        "semantic_matches": semantic[:limit],
        "mitre_matches": mitre[:limit],
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
    signature: str = "",
    redis: RedisStore | None = None,
) -> dict:
    """Run all 3 investigation tools in parallel. ~30-150ms total (limited by Postgres + pgvector)."""
    import asyncio

    src_zone = topology.ip_to_zone(src_ip)
    dst_zone = topology.ip_to_zone(dst_ip) if dst_ip else None

    # Compose semantic query for past-incident multi-strategy retrieval (P2)
    sid_info = None
    try:
        from ..core.threat_playbook import get_sid_detection
        sid_info = get_sid_detection(sid)
    except Exception:
        pass
    semantic_text = ""
    mitre_t = None
    if sid_info is not None:
        mitre_t = sid_info.mitre_technique.split()[0] if sid_info.mitre_technique else None
        semantic_text = (
            f"SID {sid} {sid_info.signature_msg} "
            f"flow {src_zone or '?'} to {dst_zone or '?'} "
            f"MITRE {sid_info.mitre_technique} {sid_info.mitre_tactic}"
        ).strip()
    elif signature:
        semantic_text = f"SID {sid} {signature} flow {src_zone or '?'} to {dst_zone or '?'}"

    neighbors, past, impact = await asyncio.gather(
        query_asset_neighbors(src_ip),
        find_similar_past_incidents(
            postgres, sid, src_zone, dst_zone,
            semantic_query_text=semantic_text,
            mitre_technique=mitre_t,
            redis=redis,
        ),
        simulate_block_impact(src_ip, dst_ip, dst_port),
        return_exceptions=True,
    )

    # Kill-chain pre-fetch removed: handing the agent "SID X = stage Y of playbook Z"
    # turns reasoning into pattern-matching against the test scenario itself
    # (data leakage). Agent must instead INFER multi-stage attacks from primitives:
    # baseline violation, MITRE technique, blast radius. If the agent decides it
    # genuinely needs kill-chain context (e.g., correlated alert sequence
    # suggests a campaign), it can call query_kg to traverse
    #   (Sid)-[:EXPECTED_IN]->(KillChain)
    # explicitly — that's a deliberate investigation step, not pre-baked answer.
    return {
        "asset_neighbors": neighbors if not isinstance(neighbors, Exception) else {"error": str(neighbors)},
        "past_incidents": past if not isinstance(past, Exception) else {"error": str(past)},
        "block_impact": impact if not isinstance(impact, Exception) else {"error": str(impact)},
    }
