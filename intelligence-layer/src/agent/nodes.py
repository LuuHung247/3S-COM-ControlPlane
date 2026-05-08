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
    await redis.push_alert_history(alert.src_ip, alert.raw)

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
        alert_history_summary=ip_summary,
        investigation=investigation,
        reputation=reputation,
    )

    return {
        "alert_history": history.get("history", []),
        "ip_summary": ip_summary,
        "correlation": correlation,
        "alert_context": alert_context,
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

async def node_decide_policy(
    state: AgentState,
    primary_llm: LLMClient,
    settings,
) -> dict:
    """V3 Stage 1: produce just the rule fields needed to enforce. Cerebras-friendly
    schema (9 scalar fields, 0 arrays). Blocking — pipeline stops if this fails."""
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

    # Stage 1 retries on transient parser failures. No self-consistency vote here —
    # the simple schema rarely fails; if it fails, retry is more useful than vote.
    last_err = ""
    result: dict | None = None
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
            reasoning_steps=[],            # Will be populated by Call 2
            mitre_technique="",            # Will be populated by Call 2
            mitre_tactic="",               # Will be populated by Call 2
            hypotheses=[],
            primary_hypothesis="",
            alternative_actions=[],
            rollback_plan=RollbackPlan(),
            follow_up_actions=[],
        )
    except Exception as exc:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": f"L1 policy schema validation failed: {exc}",
            "safety_checks": {"schema_error": str(exc)},
        }

    return {"intent": intent, "safety_checks": {}}


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

    # Patch the existing intent with reasoning fields (mutate in place)
    object.__setattr__(intent, "reasoning_steps", result.get("reasoning_steps", []) or [])
    object.__setattr__(intent, "hypotheses", hypotheses)
    object.__setattr__(intent, "primary_hypothesis", result.get("primary_hypothesis", ""))
    object.__setattr__(intent, "alternative_actions", alternatives)
    object.__setattr__(intent, "rollback_plan", rollback)
    object.__setattr__(intent, "follow_up_actions", result.get("follow_up_actions", []) or [])
    object.__setattr__(intent, "mitre_technique", result.get("mitre_technique", ""))
    object.__setattr__(intent, "mitre_tactic", result.get("mitre_tactic", ""))

    return {"reasoning_complete": True, "intent": intent}


async def node_validate_decision(
    state: AgentState,
    settings,
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
