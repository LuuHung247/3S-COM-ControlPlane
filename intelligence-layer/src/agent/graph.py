"""LangGraph StateGraph: load_context → classify → [gather/reason/validate] → enforce → record."""
import time
import structlog

from ..models.alert import SuricataAlert
from ..models.decision import PolicyDecision, PolicyAction, DecisionOutcome
from ..core.snapshot import ContextSnapshot
from ..core.topology import ip_to_zone
from ..storage.redis import RedisStore
from ..storage.postgres import PostgresStore
from .llm.interface import LLMClient
from .safety.rate_limiter import RateLimiter
from .safety.circuit_breaker import CircuitBreaker
from .state import AgentState
from .nodes import (
    node_load_context,
    node_classify_alert,
    node_log_and_end,
    node_gather_context,
    node_reason_and_decide,
    node_validate_decision,
)

log = structlog.get_logger()


class DecisionAgent:
    """
    Orchestrates the full decision pipeline for a single alert.
    LangGraph StateGraph emulated via explicit async pipeline for clarity and debuggability.
    """

    def __init__(
        self,
        snapshot: ContextSnapshot,
        fast_llm: LLMClient,
        primary_llm: LLMClient,
        redis: RedisStore,
        postgres: PostgresStore,
        rate_limiter: RateLimiter,
        circuit_breaker: CircuitBreaker,
        enforcement_backend,  # EnforcementBackend ABC
        settings,
        dry_run: bool = True,
    ) -> None:
        self._snapshot = snapshot
        self._fast_llm = fast_llm
        self._primary_llm = primary_llm
        self._redis = redis
        self._postgres = postgres
        self._rate_limiter = rate_limiter
        self._circuit_breaker = circuit_breaker
        self._enforcement = enforcement_backend
        self._settings = settings
        self._dry_run = dry_run

    async def process(self, alert: SuricataAlert) -> PolicyDecision:
        t0 = time.monotonic()
        state: AgentState = {"alert": alert}

        try:
            # ── Node 1: load context ──────────────────────────────────────
            patch = await node_load_context(state, self._snapshot)
            state.update(patch)

            # ── Node 2: classify ─────────────────────────────────────────
            patch = await node_classify_alert(state, self._fast_llm)
            state.update(patch)

            if state.get("classification") == "benign":
                patch = await node_log_and_end(state)
                state.update(patch)
                return self._finalize(state, alert, t0)

            # ── Node 3: gather context ───────────────────────────────────
            patch = await node_gather_context(state, self._redis)
            state.update(patch)

            # ── Node 4: reason & decide ──────────────────────────────────
            patch = await node_reason_and_decide(state, self._primary_llm, self._settings)
            state.update(patch)

            if state.get("outcome") in (DecisionOutcome.REJECTED, DecisionOutcome.HELD):
                return self._finalize(state, alert, t0)

            # ── Node 5: validate ─────────────────────────────────────────
            patch = await node_validate_decision(state, self._settings)
            state.update(patch)

            if state.get("outcome") in (DecisionOutcome.REJECTED, DecisionOutcome.HELD, DecisionOutcome.BENIGN):
                return self._finalize(state, alert, t0)

            # ── Node 6: enforce ──────────────────────────────────────────
            await self._enforce(state)

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
        )
        log.info(
            "decision_made",
            decision_id=decision.id,
            outcome=decision.outcome,
            sid=alert.sid,
            src_ip=alert.src_ip,
            latency_ms=round(latency_ms, 1),
        )
        return decision
