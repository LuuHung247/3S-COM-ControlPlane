"""LangGraph node functions. Each takes AgentState and returns a state patch."""
import json
import structlog

from ..models.alert import SuricataAlert
from ..models.decision import PolicyIntent, PolicyAction, DecisionOutcome
from ..core.topology import ip_to_zone
from ..core.snapshot import ContextSnapshot
from ..storage.redis import RedisStore
from .llm.interface import LLMClient
from .safety.guardrails import check_never_block, check_allowed_action
from .safety.validators import validate_intent
from .safety.consistency import self_consistency_vote
from .safety.confidence import evaluate_confidence, ConfidenceOutcome
from .safety.rate_limiter import RateLimiter
from .safety.circuit_breaker import CircuitBreaker
from .tools import (
    POLICY_INTENT_SCHEMA,
    execute_get_alert_history,
    execute_query_mitre_kb,
)
from .prompts import build_system_prompt, build_classify_prompt, build_reason_prompt
from .state import AgentState

log = structlog.get_logger()


async def node_load_context(
    state: AgentState,
    snapshot: ContextSnapshot,
) -> dict:
    await snapshot.refresh_rules()
    return {"context_snapshot": snapshot.render_for_prompt()}


async def node_classify_alert(
    state: AgentState,
    fast_llm: LLMClient,
) -> dict:
    alert: SuricataAlert = state["alert"]
    src_zone = ip_to_zone(alert.src_ip)
    system = build_system_prompt(state.get("context_snapshot", ""))
    user = build_classify_prompt(alert, src_zone)

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
    return {"classification": classification}


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
) -> dict:
    alert: SuricataAlert = state["alert"]
    history = await execute_get_alert_history(redis, alert.src_ip, limit=10)
    # Push current alert to history for future lookups
    await redis.push_alert_history(alert.src_ip, alert.raw)
    return {"alert_history": history.get("history", [])}


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
    user = build_reason_prompt(alert, src_zone, dst_zone, history)

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
        )
    except Exception as exc:
        return {
            "outcome": DecisionOutcome.REJECTED,
            "intent": None,
            "rejection_reason": f"L1 schema validation failed: {exc}",
            "safety_checks": {"schema_error": str(exc)},
        }

    return {"intent": intent, "safety_checks": {}}


async def node_validate_decision(
    state: AgentState,
    settings,
) -> dict:
    intent: PolicyIntent | None = state.get("intent")
    if intent is None:
        return {}  # Already rejected upstream

    alert: SuricataAlert = state["alert"]
    safety_checks: dict = dict(state.get("safety_checks", {}))

    # L1+L3+L4+L5+L6 validators
    val_result = validate_intent(
        intent,
        sid=alert.sid,
        ttl_min=settings.safety_ttl_min_seconds,
        ttl_max=settings.safety_ttl_max_seconds,
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
