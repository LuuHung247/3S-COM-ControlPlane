"""LangGraph node functions. Each takes AgentState and returns a state patch."""
import asyncio
import structlog

from ..models.alert import SuricataAlert
from ..models.decision import (
    PolicyIntent, PolicyAction, DecisionOutcome,
    Hypothesis, AlternativeAction, RollbackPlan,
)
from ..core.topology import ip_to_zone
from ..core.knowledge_loader import KnowledgeLoader
from ..core.asset_reputation import fetch_reputation, AssetReputation
from ..storage.redis import RedisStore
from ..storage.operational_memory import OperationalMemory
from .llm.interface import LLMClient
from .safety.validators import validate_intent
from .safety.consistency import self_consistency_vote
from .safety.confidence import evaluate_confidence, ConfidenceOutcome
from .tools import (
    POLICY_INTENT_SCHEMA,
    POLICY_DECISION_SCHEMA,
    REASONING_TRACE_SCHEMA,
    execute_get_alert_history,
    fetch_recent_alerts_all,
    prefetch_investigation_context,
)
from .response_cache import ResponseCache, rebind_cached_intent
from ..storage.postgres import PostgresStore
from .prompts import (
    build_system_prompt,
    build_classify_prompt,
    build_reason_prompt,
    build_policy_decision_prompt,
    build_reasoning_trace_prompt,
)
from .state import AgentState

log = structlog.get_logger()


async def node_load_context(
    state: AgentState,
    knowledge: KnowledgeLoader,
) -> dict:
    """Build alert-conditioned system prompt: only zones/SIDs/baselines relevant
    to this alert + always-on invariants + enforcement contract summary.
    Cuts prompt size ~52% vs full knowledge dump.
    """
    alert: SuricataAlert = state["alert"]
    system_prompt = await knowledge.build_alert_specific_prompt(
        sid=alert.sid,
        src_ip=alert.src_ip,
        dst_ip=alert.dest_ip,
    )
    return {"context_snapshot": system_prompt}


async def node_classify_alert(
    state: AgentState,
    fast_llm: LLMClient,
) -> dict:
    alert: SuricataAlert = state["alert"]
    src_zone = ip_to_zone(alert.src_ip)
    system = build_system_prompt(state.get("context_snapshot", ""))
    user = build_classify_prompt(alert, src_zone)
    try:
        from ..core import evidence
        user += "\n" + evidence.render_for_alert(alert.raw)
    except Exception as exc:
        log.warning("classify_evidence_failed", error=str(exc))

    # L1+ prompt-injection scan on attacker-controllable fields. Pure logging here —
    # build_*_prompt already sanitizes before LLM sees the text.
    from .safety.prompt_injection import sanitize_alert_fields
    _, _, injection_meta = sanitize_alert_fields(alert.signature, alert.category)
    if injection_meta.get("signature_flagged") or injection_meta.get("category_flagged"):
        log.warning("prompt_injection_flagged",
                    sid=alert.sid, src_ip=alert.src_ip, **injection_meta)

    try:
        result = await fast_llm.chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
        )
        raw = (result["content"] or "").strip().lower()
        classification = raw if raw in ("benign", "suspicious", "threat") else "suspicious"
    except Exception as exc:
        log.warning("classify_failed", error=str(exc))
        classification = "suspicious"

    log.info("alert_classified", sid=alert.sid, src_ip=alert.src_ip, classification=classification)
    return {
        "classification": classification,
        "safety_checks": {"prompt_injection": injection_meta},
    }


async def node_log_and_end(state: AgentState) -> dict:
    alert: SuricataAlert = state["alert"]
    log.info("alert_benign", sid=alert.sid, src_ip=alert.src_ip)
    return {
        "outcome": DecisionOutcome.BENIGN,
        "intent": None,
        "rejection_reason": "classified as benign",
        "safety_checks": {},
    }


async def node_gather_context(
    state: AgentState,
    redis: RedisStore,
    memory: OperationalMemory,
    knowledge: KnowledgeLoader,
    postgres: PostgresStore,
) -> dict:
    """Build per-alert context: Redis recent history + operational memory aggregated
    summary + Tier 3 alert-specific knowledge render + investigation tools (parallel)."""
    import asyncio

    alert: SuricataAlert = state["alert"]
    # alert history is pushed in DecisionAgent.run before classification

    # Run all data fetches in parallel — operational memory + investigation tools + reputation
    history_task = execute_get_alert_history(redis, alert.src_ip, limit=10)
    summary_task = memory.get_ip_summary(alert.src_ip, window_days=30)
    correlation_task = memory.get_recent_alerts_for_correlation(alert.src_ip, window_minutes=10)
    investigation_task = prefetch_investigation_context(
        postgres=postgres,
        src_ip=alert.src_ip,
        dst_ip=alert.dest_ip,
        dst_port=alert.dest_port,
        sid=alert.sid,
        signature=alert.signature or "",
        redis=redis,
    )
    reputation_task = fetch_reputation(postgres, alert.src_ip, window_hours=1)

    history, ip_summary, correlation, investigation, reputation = await asyncio.gather(
        history_task, summary_task, correlation_task, investigation_task, reputation_task,
        return_exceptions=True,
    )

    # Coerce exceptions to None — keep pipeline robust
    if isinstance(history, Exception):
        log.warning("alert_history_fetch_failed", error=str(history))
        history = {"history": []}
    if isinstance(ip_summary, Exception):
        log.warning("ip_summary_failed", error=str(ip_summary))
        ip_summary = None
    if isinstance(correlation, Exception):
        log.warning("correlation_failed", error=str(correlation))
        correlation = None
    if isinstance(investigation, Exception):
        log.warning("investigation_failed", error=str(investigation))
        investigation = None
    if isinstance(reputation, Exception):
        log.warning("reputation_fetch_failed", error=str(reputation))
        reputation = None

    # Tier 3 alert-specific context (now includes investigation + reputation)
    alert_context = knowledge.render_alert_context(
        src_ip=alert.src_ip,
        dst_ip=alert.dest_ip,
        dst_port=alert.dest_port,
        proto=alert.proto.lower() if alert.proto else "tcp",
        sid=alert.sid,
        alert_history_summary=ip_summary,
        investigation=investigation,
        reputation=reputation,
    )

    # Multi-hop graph analytics (containment collateral, attack paths, pivot chain).
    # Deterministic and read-only: informs the decision, never authorizes it.
    recent_all: list[dict] = []
    graph_signals: dict | None = None
    try:
        from ..core import graph_analytics
        recent_all = await fetch_recent_alerts_all(redis)
        alert_context += "\n\n" + graph_analytics.render_for_alert(
            alert.src_ip, alert.dest_ip, alert.dest_port, recent_all,
        )
        graph_signals = graph_analytics.escalation_signals(
            alert.src_ip, alert.dest_ip, alert.dest_port, recent_all)
        log.info("graph_escalation_signals", src_ip=alert.src_ip, dst_ip=alert.dest_ip,
                 dst_port=alert.dest_port, sid=alert.sid, n_recent=len(recent_all),
                 **graph_signals)
    except Exception as exc:
        log.warning("graph_analytics_failed", error=str(exc))

    # Observed IDS evidence: ruleset metadata, flow volume vs baseline B, and sanitized
    # application-layer fields (HTTP/DNS/TLS/payload) as untrusted data.
    try:
        from ..core import evidence
        alert_context += "\n\n" + evidence.render_for_alert(alert.raw, recent_all)
    except Exception as exc:
        log.warning("evidence_render_failed", error=str(exc))

    return {
        "alert_history": history.get("history", []),
        "ip_summary": ip_summary,
        "correlation": correlation,
        "alert_context": alert_context,
        "graph_signals": graph_signals,
        "reputation": reputation.to_dict() if isinstance(reputation, AssetReputation) else None,
    }


async def node_check_response_cache(
    state: AgentState,
    response_cache: ResponseCache,
) -> dict:
    """Check Redis for cached PolicyIntent matching this alert's threat shape.
    On hit: rebind src_ip to current alert and skip LLM call. On miss: continue.
    """
    alert: SuricataAlert = state["alert"]

    # Flow-level idempotency: if a DROP is already active for this flow (any SID,
    # any correlation state), suppress this duplicate BEFORE the LLM — no re-reason,
    # no re-enforce. This collapses defense-in-depth multi-SID bursts + sustained
    # attacks into one reasoned decision; repeats become cheap log-only suppressions.
    active_rule = await response_cache.active_block_for_alert(
        alert.src_ip, alert.dest_ip or "", alert.dest_port or 0
    )
    if active_rule:
        log.info("alert_suppressed_active_rule", sid=alert.sid, src_ip=alert.src_ip,
                 dst_ip=alert.dest_ip, dst_port=alert.dest_port, marker=active_rule)
        return {
            "outcome": DecisionOutcome.SUPPRESSED,
            "intent": None,
            "rejection_reason": f"duplicate suppressed — flow already covered by active agent rule ({active_rule.split(':')[-1]})",
            "safety_checks": {"dedup": {"suppressed": True, "active_marker": active_rule}},
        }

    correlation = state.get("correlation") or {}
    correlation_signal = correlation.get("kill_chain_signal", "")

    cache_key = ResponseCache.compute_key(
        sid=alert.sid,
        src_ip=alert.src_ip,
        dst_ip=alert.dest_ip or "",
        dst_port=alert.dest_port or 0,
        protocol=alert.proto.lower() if alert.proto else "tcp",
        correlation_signal=correlation_signal,
    )

    cached = await response_cache.get(cache_key)
    if cached is None:
        return {"cache_key": cache_key, "cache_hit": False}

    intent = rebind_cached_intent(cached, alert)
    if intent is None:
        return {"cache_key": cache_key, "cache_hit": False}

    log.info(
        "response_cache_hit",
        cache_key=cache_key[-16:],
        sid=alert.sid,
        src_ip=alert.src_ip,
        cached_at=cached.get("cached_at"),
    )
    return {
        "cache_key": cache_key,
        "cache_hit": True,
        "intent": intent,
        "safety_checks": {"cache": {"hit": True, "key": cache_key[-16:],
                                     "cached_at": cached.get("cached_at")}},
    }


async def node_reason_and_decide(
    state: AgentState,
    primary_llm: LLMClient,
    settings,  # Settings object
) -> dict:
    alert: SuricataAlert = state["alert"]
    src_zone = ip_to_zone(alert.src_ip)
    dst_zone = ip_to_zone(alert.dest_ip)
    history = state.get("alert_history", [])
    system = build_system_prompt(state.get("context_snapshot", ""))
    user = build_reason_prompt(
        alert,
        src_zone,
        dst_zone,
        history,
        alert_context=state.get("alert_context", ""),
        correlation=state.get("correlation"),
    )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    # L2: Self-consistency for P1/P2
    if alert.severity <= 2:
        result, sc_error = await self_consistency_vote(
            client=primary_llm,
            messages=messages,
            schema=POLICY_INTENT_SCHEMA,
            n_runs=settings.agent_self_consistency_runs,
            min_agree=settings.agent_self_consistency_min_agree,
        )
        if sc_error:
            return {
                "outcome": DecisionOutcome.REJECTED,
                "intent": None,
                "rejection_reason": sc_error,
                "safety_checks": {"self_consistency": sc_error},
            }
    else:
        try:
            result = await primary_llm.chat_json(messages=messages, schema=POLICY_INTENT_SCHEMA)
        except Exception as exc:
            return {
                "outcome": DecisionOutcome.REJECTED,
                "intent": None,
                "rejection_reason": f"LLM error: {exc}",
                "safety_checks": {"llm_error": str(exc)},
            }

    if result is None:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": "LLM returned null result",
            "safety_checks": {},
        }

    # Map string action to enum
    try:
        action = PolicyAction(result.get("action", "log_only"))
    except ValueError:
        action = PolicyAction.LOG_ONLY

    # Parse V2 hypothesis fields — schema uses flat strings (Cerebras tool-call parser
    # cannot reliably handle nested objects). Strings are persisted as-is.
    hypotheses_raw = result.get("hypotheses") or []
    hypotheses: list[Hypothesis] = []
    for h in hypotheses_raw:
        try:
            if isinstance(h, str):
                # Try to extract probability from formatted string like:
                # "name (probability=0.6) — description. Evidence: ..."
                import re as _re
                prob_match = _re.search(r"probability\s*=\s*([0-9.]+)", h)
                prob = float(prob_match.group(1)) if prob_match else 0.5
                # Name = text before first '(' if present
                name = h.split("(")[0].strip() or "unnamed"
                hypotheses.append(Hypothesis(
                    name=name[:80], description=h, probability=min(max(prob, 0.0), 1.0),
                ))
            elif isinstance(h, dict):
                hypotheses.append(Hypothesis(
                    name=h.get("name", "unnamed"),
                    description=h.get("description", ""),
                    probability=float(h.get("probability", 0.5)),
                    supporting_evidence=h.get("supporting_evidence", []) or [],
                    disconfirming_evidence=h.get("disconfirming_evidence", []) or [],
                ))
        except Exception:
            continue

    alt_raw = result.get("alternative_actions") or []
    alternatives: list[AlternativeAction] = []
    for a in alt_raw:
        try:
            if isinstance(a, str):
                # Format: "if <trigger> then <action> because <rationale>"
                action_word = "log_only"
                if "DROP" in a.upper():
                    action_word = "DROP"
                elif "ESCALATE" in a.upper():
                    action_word = "ESCALATE_HUMAN"
                alternatives.append(AlternativeAction(
                    trigger_condition=a, action=action_word, rationale=a,
                ))
            elif isinstance(a, dict):
                alternatives.append(AlternativeAction(
                    trigger_condition=a.get("trigger_condition", ""),
                    action=a.get("action", "log_only"),
                    rationale=a.get("rationale", ""),
                ))
        except Exception:
            continue

    rollback_raw = result.get("rollback_plan")
    if isinstance(rollback_raw, dict):
        rollback = RollbackPlan(
            trigger=rollback_raw.get("trigger", ""),
            action=rollback_raw.get("action", ""),
            monitor_seconds=int(rollback_raw.get("monitor_seconds", 300)),
        )
    elif isinstance(rollback_raw, str):
        rollback = RollbackPlan(trigger=rollback_raw, action=rollback_raw, monitor_seconds=300)
    else:
        rollback = RollbackPlan()

    try:
        intent = PolicyIntent(
            action=action,
            src_ip=result.get("src_ip", alert.src_ip),
            dst_ip=result.get("dst_ip", ""),
            dst_port=int(result.get("dst_port", 0)),
            protocol=result.get("protocol", "tcp"),
            priority=int(result.get("priority", 50)),
            ttl_seconds=int(result.get("ttl_seconds", 3600)),
            comment=result.get("comment", ""),
            confidence=float(result.get("confidence", 0.0)),
            reasoning_steps=result.get("reasoning_steps", []),
            mitre_technique=result.get("mitre_technique", ""),
            mitre_tactic=result.get("mitre_tactic", ""),
            hypotheses=hypotheses,
            primary_hypothesis=result.get("primary_hypothesis", ""),
            alternative_actions=alternatives,
            rollback_plan=rollback,
            follow_up_actions=result.get("follow_up_actions", []) or [],
        )
    except Exception as exc:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": f"L1 schema validation failed: {exc}",
            "safety_checks": {"schema_error": str(exc)},
        }

    return {"intent": intent, "safety_checks": {}}


# ─────────────────────────────────────────────────────────────────────────────
# V3: Split decide_and_reason into two LLM calls
#   node_decide_policy   — Call 1, blocking, scalar-only schema, ~0% parser fail
#   node_collect_reasoning — Call 2, fail-tolerant, audit metadata only
# ─────────────────────────────────────────────────────────────────────────────

_SCOPE_RANK = {"flow": 0, "pair": 1, "host": 2}
_SCOPE_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "containment_scope": {"type": "string", "enum": ["flow", "pair", "host"]},
        "rationale": {"type": "string"},
    },
    "required": ["containment_scope", "rationale"],
}


def _signal_scope(sig: dict | None) -> str:
    if not sig:
        return "flow"
    spreading = sig.get("pivot") == "yes" or int(sig.get("distinct_targets") or 0) >= 2
    if spreading and sig.get("crown_jewel_path_open_under_flow_scope") == "yes":
        return "host"
    return "pair" if int(sig.get("ports_on_this_target") or 0) >= 2 else "flow"


async def _review_scope(llm: LLMClient, alert: SuricataAlert, state: AgentState,
                        chosen: str, suggested: str) -> dict | None:
    from ..core import graph_analytics
    opts = graph_analytics.containment_options(alert.src_ip, alert.dest_ip, alert.dest_port)
    collateral = "; ".join(
        f"{o['scope']}: cuts {o['n_cut']} legit flows (max {o['max_cut_criticality']}), "
        f"crown jewels still reachable: {', '.join(o['crown_jewels_still_reachable']) or 'none'}"
        for o in opts)
    prompt = (
        f"You chose containment_scope={chosen} for a DROP against {alert.src_ip}.\n"
        f"Graph escalation signals: {state.get('graph_signals')}\n"
        f"Collateral per scope: {collateral}\n"
        "Scope policy: host when the source is spreading (pivot=yes or distinct_targets>=2) and a "
        "crown-jewel path stays open under flow scope; pair when several ports on one target are "
        f"probed; flow for a single violation. The signals point to {suggested}.\n"
        "Reconsider once. Keep your choice only if the evidence above justifies it; otherwise "
        "switch. The target stays the alert source either way. Answer with containment_scope "
        "and a one-sentence rationale."
    )
    try:
        return await llm.chat_json(messages=[{"role": "user", "content": prompt}],
                                   schema=_SCOPE_REVIEW_SCHEMA)
    except Exception as exc:
        log.warning("scope_review_failed", error=str(exc)[:140])
        return None


async def node_decide_policy(
    state: AgentState,
    primary_llm: LLMClient,
    settings,
    redis: "RedisStore | None" = None,
    neo4j_driver=None,
) -> dict:
    """V3 Stage 1: produce just the rule fields needed to enforce. Cerebras-friendly
    schema (9 scalar fields, 0 arrays). Blocking — pipeline stops if this fails.

    If `neo4j_driver` is set, the agent runs ReAct: it can call `query_kg(cypher)`
    against the knowledge graph and `get_alert_history(src_ip)` against Redis to
    gather facts dynamically before emitting the final structured decision. The
    static prompt becomes minimal (architecture overview + invariants + tool docs);
    knowledge specifics are fetched on demand.
    """
    alert: SuricataAlert = state["alert"]
    src_zone = ip_to_zone(alert.src_ip)
    dst_zone = ip_to_zone(alert.dest_ip)
    history = state.get("alert_history", [])
    system = build_system_prompt(state.get("context_snapshot", ""))
    user = build_policy_decision_prompt(
        alert, src_zone, dst_zone, history,
        alert_context=state.get("alert_context", ""),
        correlation=state.get("correlation"),
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    # ReAct path — only if Neo4j driver is wired in
    use_react = neo4j_driver is not None
    if use_react:
        from .tools import (
            TOOL_DEFINITIONS, execute_query_kg, execute_get_alert_history,
        )

        async def _kg_handler(cypher: str) -> str:
            res = await execute_query_kg(neo4j_driver, cypher)
            return str(res)

        async def _history_handler(src_ip: str, limit: int = 10) -> str:
            if redis is None:
                return str({"error": "Redis unavailable"})
            res = await execute_get_alert_history(redis, src_ip, limit=limit)
            return str(res)

        def _containment_handler(src_ip: str, dst_ip: str = "", dst_port: int = 0) -> str:
            from ..core import graph_analytics
            return str(graph_analytics.containment_options(src_ip, dst_ip, int(dst_port or 0)))

        def _paths_handler(src_ip: str) -> str:
            from ..core import graph_analytics
            return str(graph_analytics.attack_surface(src_ip))

        tool_handlers = {
            "query_kg": _kg_handler,
            "get_alert_history": _history_handler,
            "graph_containment_options": _containment_handler,
            "graph_attack_paths": _paths_handler,
        }
        try:
            result = await primary_llm.chat_react(
                messages=messages,
                tools=TOOL_DEFINITIONS,
                tool_handlers=tool_handlers,
                final_schema=POLICY_DECISION_SCHEMA,
                max_iterations=4,
            )
        except Exception as exc:
            log.warning("react_failed_falling_back_to_chat_json",
                        error=f"{type(exc).__name__}: {str(exc)[:140]}")
            result = None
    else:
        result = None

    # Stage 1 fallback / non-ReAct path: chat_json with retries
    if result is None:
        last_err = ""
        for attempt in range(3):
            try:
                result = await primary_llm.chat_json(messages=messages, schema=POLICY_DECISION_SCHEMA)
                break
            except Exception as exc:
                last_err = f"{type(exc).__name__}: {str(exc)[:140]}"
                log.warning("policy_decision_attempt_failed", attempt=attempt + 1, error=last_err)
                await asyncio.sleep(0.5 * (attempt + 1))

    if result is None:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": f"L1: policy_decision LLM failed after retries — {last_err}",
            "safety_checks": {"policy_decision_error": last_err},
        }

    try:
        action = PolicyAction(result.get("action", "log_only"))
    except ValueError:
        action = PolicyAction.LOG_ONLY

    # V3 — user-facing notification (Stage 1 emits flat fields; we lift into nested object)
    from ..models.decision import UserNotification, NotificationSeverity
    try:
        severity_str = (result.get("notification_severity") or "info").lower()
        notif_severity = NotificationSeverity(severity_str) if severity_str in {s.value for s in NotificationSeverity} else NotificationSeverity.INFO
    except Exception:
        notif_severity = NotificationSeverity.INFO
    user_notification = UserNotification(
        title=(result.get("notification_title") or "")[:120],
        body=(result.get("notification_body") or "")[:400],
        severity=notif_severity,
    )

    # Scope self-review: when the graph signals point to a broader scope than the one
    # chosen, the model reconsiders once with the signals and collateral side by side.
    scope = (result.get("containment_scope") or "flow").lower()
    scope_review = None
    if action == PolicyAction.DROP:
        suggested = _signal_scope(state.get("graph_signals"))
        if _SCOPE_RANK.get(suggested, 0) > _SCOPE_RANK.get(scope, 0):
            scope_review = await _review_scope(primary_llm, alert, state, scope, suggested)
            if scope_review and scope_review.get("containment_scope") in _SCOPE_RANK:
                result["containment_scope"] = scope_review["containment_scope"]

    # Map the explicit containment scope onto the rule tuple deterministically.
    scope = (result.get("containment_scope") or "flow").lower()
    dst_ip = result.get("dst_ip", "") or ""
    dst_port = int(result.get("dst_port", 0) or 0)
    if scope == "host":
        dst_ip, dst_port = "", 0
    elif scope == "pair":
        dst_ip, dst_port = dst_ip or f"{alert.dest_ip}/32", 0

    try:
        intent = PolicyIntent(
            action=action,
            src_ip=result.get("src_ip", alert.src_ip),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=result.get("protocol", "tcp"),
            priority=int(result.get("priority", 50)),
            ttl_seconds=int(result.get("ttl_seconds", 3600)),
            comment=result.get("comment", ""),
            confidence=float(result.get("confidence", 0.0)),
            reasoning_steps=[],            # Will be populated by Call 2
            mitre_technique="",            # Will be populated by Call 2
            mitre_tactic="",               # Will be populated by Call 2
            hypotheses=[],
            primary_hypothesis="",
            alternative_actions=[],
            rollback_plan=RollbackPlan(),
            follow_up_actions=[],
            user_notification=user_notification,
        )
    except Exception as exc:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": f"L1 policy schema validation failed: {exc}",
            "safety_checks": {"schema_error": str(exc)},
        }

    return {"intent": intent,
            "safety_checks": {"scope_review": scope_review} if scope_review else {}}


async def node_collect_reasoning(
    state: AgentState,
    primary_llm: LLMClient,
    settings,
) -> dict:
    """V3 Stage 2: explain the decision after it's been made. Fail-tolerant —
    on any error, returns empty reasoning patch and the decision still enforces.
    Designed to run in parallel with enforce, after Call 1 success."""
    intent: PolicyIntent | None = state.get("intent")
    if intent is None:
        return {}

    alert: SuricataAlert = state["alert"]
    src_zone = ip_to_zone(alert.src_ip)
    dst_zone = ip_to_zone(alert.dest_ip)
    history = state.get("alert_history", [])
    system = build_system_prompt(state.get("context_snapshot", ""))
    user = build_reasoning_trace_prompt(
        alert, src_zone, dst_zone, history,
        alert_context=state.get("alert_context", ""),
        correlation=state.get("correlation"),
        decided_action=intent.action.value,
        decided_src_ip=intent.src_ip,
        decided_dst_ip=intent.dst_ip,
        decided_dst_port=intent.dst_port,
        decided_confidence=intent.confidence,
        decided_ttl=intent.ttl_seconds,
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    last_err = ""
    result: dict | None = None
    for attempt in range(2):
        try:
            result = await primary_llm.chat_json(messages=messages, schema=REASONING_TRACE_SCHEMA)
            break
        except Exception as exc:
            last_err = str(exc)[:200]
            log.warning("reasoning_trace_attempt_failed", attempt=attempt + 1, error=last_err)
            await asyncio.sleep(0.5)

    if result is None or not isinstance(result, dict):
        log.warning("reasoning_trace_failed", error=last_err or "non-dict result")
        return {"reasoning_complete": False, "reasoning_error": last_err or "non-dict result"}

    # Parse hypotheses / alternatives — same as before, string format
    hypotheses_raw = result.get("hypotheses") or []
    hypotheses: list[Hypothesis] = []
    import re as _re
    for h in hypotheses_raw:
        try:
            if isinstance(h, str):
                prob_match = _re.search(r"probability\s*=\s*([0-9.]+)", h)
                prob = float(prob_match.group(1)) if prob_match else 0.5
                name = h.split("(")[0].strip() or "unnamed"
                hypotheses.append(Hypothesis(
                    name=name[:80], description=h, probability=min(max(prob, 0.0), 1.0),
                ))
            elif isinstance(h, dict):
                hypotheses.append(Hypothesis(
                    name=h.get("name", "unnamed"),
                    description=h.get("description", ""),
                    probability=float(h.get("probability", 0.5)),
                    supporting_evidence=h.get("supporting_evidence", []) or [],
                    disconfirming_evidence=h.get("disconfirming_evidence", []) or [],
                ))
        except Exception:
            continue

    alt_raw = result.get("alternative_actions") or []
    alternatives: list[AlternativeAction] = []
    for a in alt_raw:
        try:
            if isinstance(a, str):
                action_word = "log_only"
                if "DROP" in a.upper():
                    action_word = "DROP"
                elif "ESCALATE" in a.upper():
                    action_word = "ESCALATE_HUMAN"
                alternatives.append(AlternativeAction(trigger_condition=a, action=action_word, rationale=a))
            elif isinstance(a, dict):
                alternatives.append(AlternativeAction(
                    trigger_condition=a.get("trigger_condition", ""),
                    action=a.get("action", "log_only"),
                    rationale=a.get("rationale", ""),
                ))
        except Exception:
            continue

    rollback_raw = result.get("rollback_plan")
    if isinstance(rollback_raw, dict):
        rollback = RollbackPlan(
            trigger=rollback_raw.get("trigger", ""),
            action=rollback_raw.get("action", ""),
            monitor_seconds=int(rollback_raw.get("monitor_seconds", 300)),
        )
    elif isinstance(rollback_raw, str):
        rollback = RollbackPlan(trigger=rollback_raw, action=rollback_raw, monitor_seconds=300)
    else:
        rollback = RollbackPlan()

    # Deterministic graph facts head the audit trace so the root cause and chosen scope
    # are recorded verbatim, independent of how the model paraphrases them.
    steps = list(result.get("reasoning_steps", []) or [])
    sig = state.get("graph_signals") or {}
    if sig.get("pivot") == "yes":
        steps.insert(0, f"[graph] Pivot detected: {alert.src_ip} was previously targeted; "
                        f"upstream root-cause source {sig.get('root_cause')}.")
    if intent.action.value == "DROP":
        scope = ("host" if not (intent.dst_ip or "").split("/")[0]
                 else "pair" if not intent.dst_port else "flow")
        steps.insert(0, f"[graph] Containment scope: {scope} "
                        f"(distinct_targets={sig.get('distinct_targets')}, "
                        f"ports_on_this_target={sig.get('ports_on_this_target')}, "
                        f"crown_jewel_path_open_under_flow_scope={sig.get('crown_jewel_path_open_under_flow_scope')}).")

    # Patch the existing intent with reasoning fields (mutate in place)
    object.__setattr__(intent, "reasoning_steps", steps)
    object.__setattr__(intent, "hypotheses", hypotheses)
    object.__setattr__(intent, "primary_hypothesis", result.get("primary_hypothesis", ""))
    object.__setattr__(intent, "alternative_actions", alternatives)
    object.__setattr__(intent, "rollback_plan", rollback)
    object.__setattr__(intent, "follow_up_actions", result.get("follow_up_actions", []) or [])
    object.__setattr__(intent, "mitre_technique", result.get("mitre_technique", ""))
    object.__setattr__(intent, "mitre_tactic", result.get("mitre_tactic", ""))

    return {"reasoning_complete": True, "intent": intent}


SEMANTIC_OVERRIDE_RATE_KEY = "agent:semantic_override:count"
SEMANTIC_OVERRIDE_MAX_PER_WINDOW = 5
SEMANTIC_OVERRIDE_WINDOW_S = 300


async def node_validate_decision(
    state: AgentState,
    settings,
    redis: "RedisStore | None" = None,
) -> dict:
    intent: PolicyIntent | None = state.get("intent")
    if intent is None:
        return {}  # Already rejected upstream

    alert: SuricataAlert = state["alert"]
    safety_checks: dict = dict(state.get("safety_checks", {}))

    # L1+L3+L4+L4b+L5+L6 validators (L4b = off-target enforcement check)
    val_result = validate_intent(
        intent,
        sid=alert.sid,
        ttl_min=settings.safety_ttl_min_seconds,
        ttl_max=settings.safety_ttl_max_seconds,
        alert_src_ip=alert.src_ip,
        alert_dst_ip=alert.dest_ip,
        alert_severity=alert.severity,
        alert_initiator_ip=str((alert.raw.get("flow") or {}).get("src_ip") or ""),
    )
    safety_checks["validators"] = {
        "errors": val_result.errors,
        "warnings": val_result.warnings,
    }

    if not val_result.ok:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": intent,
            "rejection_reason": "; ".join(val_result.errors),
            "safety_checks": safety_checks,
        }

    # Semantic overrides of permitted paths are budgeted: fail closed when the
    # window budget is spent or the counter is unavailable.
    if val_result.semantic_override:
        safety_checks["semantic_override"] = True
        used = None
        if redis is not None:
            try:
                used = await redis.client.incr(SEMANTIC_OVERRIDE_RATE_KEY)
                if used == 1:
                    await redis.client.expire(SEMANTIC_OVERRIDE_RATE_KEY, SEMANTIC_OVERRIDE_WINDOW_S)
            except Exception:
                used = None
        if used is None or used > SEMANTIC_OVERRIDE_MAX_PER_WINDOW:
            return {
                "outcome": DecisionOutcome.REJECTED,
                "intent": intent,
                "rejection_reason": "L3-SO: semantic override budget exhausted or unavailable",
                "safety_checks": safety_checks,
            }

    # L7: Confidence gate
    conf_outcome, conf_reason = evaluate_confidence(
        intent.confidence,
        auto_enforce_threshold=settings.agent_confidence_auto_enforce,
        notify_threshold=settings.agent_confidence_notify,
        hold_threshold=settings.agent_confidence_hold,
    )
    safety_checks["confidence"] = {"score": intent.confidence, "outcome": conf_outcome}

    if conf_outcome == ConfidenceOutcome.HOLD:
        return {
            "outcome": DecisionOutcome.HELD,
            "intent": intent,
            "rejection_reason": conf_reason,
            "safety_checks": safety_checks,
        }
    if conf_outcome == ConfidenceOutcome.REJECT:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": intent,
            "rejection_reason": conf_reason,
            "safety_checks": safety_checks,
        }

    # log_only actions don't need enforcement — done here
    if intent.action == PolicyAction.LOG_ONLY:
        return {
            "outcome": DecisionOutcome.BENIGN,
            "intent": intent,
            "rejection_reason": "action=log_only — no enforcement needed",
            "safety_checks": safety_checks,
        }

    return {"intent": intent, "safety_checks": safety_checks}
