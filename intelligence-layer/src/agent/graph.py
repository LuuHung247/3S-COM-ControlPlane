"""LangGraph StateGraph: load_context → classify → [gather/reason/validate] → enforce → record."""
import asyncio
import time
import structlog

from ..models.alert import SuricataAlert
from ..models.decision import PolicyDecision, PolicyAction, DecisionOutcome
from ..core.knowledge_loader import KnowledgeLoader
from ..core.topology import ip_to_zone
from ..storage.redis import RedisStore
from ..storage.postgres import PostgresStore
from ..storage.operational_memory import OperationalMemory
from .llm.interface import LLMClient
from .safety.rate_limiter import RateLimiter
from .safety.circuit_breaker import CircuitBreaker
from .state import AgentState
from .nodes import (
    node_load_context,
    node_classify_alert,
    node_log_and_end,
    node_gather_context,
    node_check_response_cache,
    node_reason_and_decide,
    node_decide_policy,
    node_collect_reasoning,
    node_validate_decision,
)
from .response_cache import ResponseCache
from ..observability.langfuse_tracer import LangfuseTracer

log = structlog.get_logger()


class DecisionAgent:
    """
    Orchestrates the full decision pipeline for a single alert.
    LangGraph StateGraph emulated via explicit async pipeline for clarity and debuggability.
    """

    def __init__(
        self,
        knowledge: KnowledgeLoader,
        fast_llm: LLMClient,
        primary_llm: LLMClient,
        redis: RedisStore,
        postgres: PostgresStore,
        operational_memory: OperationalMemory,
        rate_limiter: RateLimiter,
        circuit_breaker: CircuitBreaker,
        enforcement_backend,  # EnforcementBackend ABC
        response_cache: ResponseCache,
        tracer: LangfuseTracer,
        settings,
        dry_run: bool = True,
    ) -> None:
        self._knowledge = knowledge
        self._fast_llm = fast_llm
        self._primary_llm = primary_llm
        self._redis = redis
        self._postgres = postgres
        self._memory = operational_memory
        self._rate_limiter = rate_limiter
        self._circuit_breaker = circuit_breaker
        self._enforcement = enforcement_backend
        self._response_cache = response_cache
        self._tracer = tracer
        self._settings = settings
        self._dry_run = dry_run

    async def process(self, alert: SuricataAlert) -> PolicyDecision:
        t0 = time.monotonic()
        state: AgentState = {"alert": alert}

        # Root trace per alert. session_id = src_ip lets Langfuse group all traces from
        # the same attacker IP into a single session (visible as kill-chain in UI).
        trace = self._tracer.trace(
            name="agent.process",
            session_id=alert.src_ip,
            tags=[f"sid:{alert.sid}", f"severity:P{alert.severity}"],
            metadata={
                "alert_sid": alert.sid,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dest_ip,
                "dst_port": alert.dest_port,
                "severity": alert.severity,
                "signature": alert.signature[:200],
            },
            input={"alert": alert.raw},
        )
        state["trace_id"] = getattr(trace, "id", "") or ""
        state["_trace"] = trace

        try:
            # ── Node 1: load context ──────────────────────────────────────
            with self._tracer.span(trace, "load_context") as sp:
                patch = await node_load_context(state, self._knowledge)
                state.update(patch)
                sp.update(metadata={"prompt_tokens_estimate": len(state.get("context_snapshot", "")) // 4})

            # ── Node 2: classify ─────────────────────────────────────────
            with self._tracer.span(trace, "classify_alert"):
                patch = await node_classify_alert(state, self._fast_llm)
                state.update(patch)

            if state.get("classification") == "benign":
                patch = await node_log_and_end(state)
                state.update(patch)
                return self._finalize(state, alert, t0)

            # ── Node 3: gather context (parallel investigation tools) ────
            with self._tracer.span(trace, "gather_context") as sp:
                patch = await node_gather_context(
                    state, self._redis, self._memory, self._knowledge, self._postgres
                )
                state.update(patch)
                inv = patch.get("alert_context") or ""
                sp.update(metadata={
                    "alert_context_tokens": len(inv) // 4,
                    "ip_summary_alerts": (state.get("ip_summary") or {}).get("total_alerts", 0),
                    "correlation_signal": (state.get("correlation") or {}).get("kill_chain_signal", ""),
                })

            # ── Node 3.5: response cache lookup ──────────────────────────
            with self._tracer.span(trace, "cache_lookup") as sp:
                patch = await node_check_response_cache(state, self._response_cache)
                state.update(patch)
                sp.update(metadata={"cache_hit": bool(state.get("cache_hit"))})

            # ── Node 4 (V3): policy decision — Stage 1, BLOCKING ─────────
            # Cerebras-friendly schema (9 scalar fields, 0 arrays). Reasoning
            # trace (Stage 2) runs in parallel with enforce after this returns.
            if not state.get("cache_hit"):
                with self._tracer.span(trace, "policy_decision"):
                    patch = await node_decide_policy(state, self._primary_llm, self._settings)
                    state.update(patch)

            if state.get("outcome") in (DecisionOutcome.REJECTED, DecisionOutcome.HELD):
                return self._finalize(state, alert, t0)

            # ── Node 5: validate ─────────────────────────────────────────
            with self._tracer.span(trace, "validate_decision") as sp:
                patch = await node_validate_decision(state, self._settings)
                state.update(patch)
                val = (state.get("safety_checks") or {}).get("validators", {})
                sp.update(metadata={
                    "errors": val.get("errors", []),
                    "warnings": val.get("warnings", []),
                })

            if state.get("outcome") in (DecisionOutcome.REJECTED, DecisionOutcome.HELD, DecisionOutcome.BENIGN):
                return self._finalize(state, alert, t0)

            # ── Node 6 (V3): PARALLEL FORK — enforce + reasoning trace ──
            # Enforce runs on critical path (push SF rule).
            # Reasoning trace runs concurrently — fail-tolerant; if it fails,
            # the decision is still enforced, just without rich audit metadata.
            # Cache hit decisions skip Call 2 (reasoning was already cached).
            async def _enforce_path():
                with self._tracer.span(trace, "enforce"):
                    await self._enforce(state)

            async def _reasoning_path():
                if state.get("cache_hit"):
                    return  # Cached decision already has reasoning
                with self._tracer.span(trace, "reasoning_trace"):
                    patch = await node_collect_reasoning(
                        state, self._primary_llm, self._settings
                    )
                    if patch:
                        state.update(patch)

            await asyncio.gather(
                _enforce_path(),
                _reasoning_path(),
                return_exceptions=True,
            )

        except Exception as exc:
            log.error("agent_pipeline_error", error=str(exc), sid=alert.sid)
            state["outcome"] = DecisionOutcome.ERROR
            state["rejection_reason"] = str(exc)

        return self._finalize(state, alert, t0)

    async def _enforce(self, state: AgentState) -> None:
        intent = state.get("intent")
        if intent is None or intent.action != PolicyAction.DROP:
            return

        safety_checks = dict(state.get("safety_checks", {}))

        # L8: Circuit breaker
        is_open, cb_reason = await self._circuit_breaker.is_open()
        if is_open:
            state["outcome"] = DecisionOutcome.REJECTED
            state["rejection_reason"] = cb_reason
            safety_checks["circuit_breaker"] = cb_reason
            state["safety_checks"] = safety_checks
            return

        # L5: Rate limiter
        rl_error = await self._rate_limiter.check_and_consume(intent.src_ip)
        if rl_error:
            state["outcome"] = DecisionOutcome.REJECTED
            state["rejection_reason"] = rl_error
            safety_checks["rate_limiter"] = rl_error
            state["safety_checks"] = safety_checks
            return

        if self._dry_run:
            log.info(
                "dry_run_decision",
                action=intent.action,
                src_ip=intent.src_ip,
                dst_ip=intent.dst_ip,
                confidence=intent.confidence,
            )
            state["outcome"] = DecisionOutcome.DRY_RUN
            return

        # Live enforcement
        try:
            result = await self._enforcement.enforce(intent)
            if result.success:
                await self._circuit_breaker.record_success()
                state["outcome"] = DecisionOutcome.ENFORCED
                safety_checks["enforcement"] = {"backend": result.backend, "rule_id": result.rule_id}
                # Cache the enforced template for fast reuse on identical-shape alerts.
                # Only cache on successful enforcement (post all safety layers + LEAF apply).
                # Skip caching if this decision itself came from cache (avoid double-stale).
                if not state.get("cache_hit") and state.get("cache_key"):
                    try:
                        await self._response_cache.set(state["cache_key"], intent)
                    except Exception as exc:
                        log.warning("response_cache_set_failed", error=str(exc))
            else:
                await self._circuit_breaker.record_failure()
                state["outcome"] = DecisionOutcome.ERROR
                state["rejection_reason"] = result.error
                safety_checks["enforcement"] = {"error": result.error}
        except Exception as exc:
            await self._circuit_breaker.record_failure()
            state["outcome"] = DecisionOutcome.ERROR
            state["rejection_reason"] = str(exc)

        state["safety_checks"] = safety_checks

    def _finalize(self, state: AgentState, alert: SuricataAlert, t0: float) -> PolicyDecision:
        latency_ms = (time.monotonic() - t0) * 1000
        decision = PolicyDecision(
            alert_sid=alert.sid,
            alert_src_ip=alert.src_ip,
            intent=state.get("intent"),
            outcome=state.get("outcome", DecisionOutcome.ERROR),
            rejection_reason=state.get("rejection_reason", ""),
            safety_checks=state.get("safety_checks", {}),
            latency_ms=latency_ms,
            trace_id=state.get("trace_id", "") or "",
        )

        # Close root trace with full decision payload for observability.
        trace = state.get("_trace")
        if trace is not None:
            try:
                intent_summary = None
                if decision.intent:
                    intent_summary = {
                        "action": decision.intent.action.value,
                        "src_ip": decision.intent.src_ip,
                        "dst_ip": decision.intent.dst_ip,
                        "dst_port": decision.intent.dst_port,
                        "rule_id": decision.intent.rule_id,
                        "ttl_seconds": decision.intent.ttl_seconds,
                        "confidence": decision.intent.confidence,
                        "primary_hypothesis": decision.intent.primary_hypothesis,
                        "reasoning_steps": decision.intent.reasoning_steps,
                    }
                trace.update(
                    output={
                        "decision_id": decision.id,
                        "outcome": decision.outcome.value,
                        "intent": intent_summary,
                        "rejection_reason": decision.rejection_reason,
                        "latency_ms": round(latency_ms, 1),
                        "cache_hit": bool(state.get("cache_hit")),
                    },
                    metadata={
                        "decision_id": decision.id,
                        "outcome": decision.outcome.value,
                        "latency_ms": round(latency_ms, 1),
                        "cache_hit": bool(state.get("cache_hit")),
                        "confidence": decision.intent.confidence if decision.intent else None,
                    },
                    level="ERROR" if decision.outcome == DecisionOutcome.ERROR else "DEFAULT",
                )
            except Exception as exc:
                log.warning("trace_finalize_failed", error=str(exc))
        log.info(
            "decision_made",
            decision_id=decision.id,
            outcome=decision.outcome,
            sid=alert.sid,
            src_ip=alert.src_ip,
            latency_ms=round(latency_ms, 1),
        )
        return decision
