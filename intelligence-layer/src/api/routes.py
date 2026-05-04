"""FastAPI routes: /health, /alerts, /decisions, /decisions/{id}/revoke, /stream."""
import asyncio
import json
from collections import deque
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from ..models.alert import SuricataAlert
from .schemas import AlertIngest, DecisionResponse, HealthResponse, RevokeResponse

router = APIRouter()

# In-memory recent decisions ring buffer for SSE streaming
_recent_decisions: deque[dict[str, Any]] = deque(maxlen=200)
_sse_queues: list[asyncio.Queue] = []


def _push_decision(decision_dict: dict[str, Any]) -> None:
    _recent_decisions.appendleft(decision_dict)
    for q in list(_sse_queues):
        try:
            q.put_nowait(decision_dict)
        except asyncio.QueueFull:
            pass


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    agent = request.app.state.agent
    ids_ok = await request.app.state.enforcement_backend.ping()
    cb_stats = await agent._circuit_breaker.get_stats()
    rl_stats = await agent._rate_limiter.get_stats()
    return HealthResponse(
        status="ok",
        ids_agent="connected" if ids_ok else "unreachable",
        dry_run=agent._dry_run,
        circuit_breaker=cb_stats,
        rate_limiter=rl_stats,
    )


@router.post("/alerts", response_model=DecisionResponse)
async def ingest_alert(body: AlertIngest, request: Request) -> DecisionResponse:
    """Inject a raw Suricata alert JSON for synchronous processing."""
    agent = request.app.state.agent
    gate = request.app.state.gate
    redis = request.app.state.redis
    postgres = request.app.state.postgres
    settings = request.app.state.settings

    alert = SuricataAlert.from_raw(body.data)
    should, reason = await gate.should_process(alert)
    if not should:
        return DecisionResponse(
            id="filtered",
            alert_sid=alert.sid,
            alert_src_ip=alert.src_ip,
            outcome="filtered",
            rejection_reason=reason,
        )

    decision = await agent.process(alert)

    decision_dict = {
        "id": decision.id,
        "alert_sid": decision.alert_sid,
        "alert_src_ip": decision.alert_src_ip,
        "outcome": decision.outcome.value,
        "action": decision.intent.action.value if decision.intent else None,
        "src_ip": decision.intent.src_ip if decision.intent else None,
        "dst_ip": decision.intent.dst_ip if decision.intent else None,
        "confidence": decision.intent.confidence if decision.intent else None,
        "rejection_reason": decision.rejection_reason,
        "safety_checks": decision.safety_checks,
        "latency_ms": decision.latency_ms,
        "dry_run": agent._dry_run,
    }

    # Persist
    await postgres.save_decision(decision_dict)
    await redis.cache_decision(decision.id, decision_dict)
    _push_decision(decision_dict)

    return DecisionResponse(**{k: v for k, v in decision_dict.items() if k != "safety_checks"})


@router.get("/decisions")
async def list_decisions(request: Request, limit: int = 50) -> list[dict]:
    postgres = request.app.state.postgres
    return await postgres.list_decisions(limit=limit)


@router.delete("/decisions/{rule_id}", response_model=RevokeResponse)
async def revoke_decision(rule_id: str, request: Request) -> RevokeResponse:
    """Emergency revert — delete a rule from the dataplane."""
    backend = request.app.state.enforcement_backend
    result = await backend.revoke(rule_id)
    return RevokeResponse(success=result.success, rule_id=rule_id, error=result.error)


@router.get("/policy-history")
async def policy_history(request: Request, limit: int = 100) -> list[dict]:
    """
    Timeline of AI agent policy decisions with full intent details.
    Includes both dry_run (would-have-enforced) and enforced outcomes.
    Use this to audit what the agent decided and why.
    """
    postgres = request.app.state.postgres
    all_decisions = await postgres.list_decisions(limit=limit)
    history = []
    for d in all_decisions:
        if d.get("outcome") not in ("enforced", "dry_run"):
            continue
        sc = d.get("safety_checks") or {}
        history.append({
            "id": d["id"],
            "timestamp": d["created_at"],
            "alert_sid": d["alert_sid"],
            "attacker_ip": d["alert_src_ip"],
            "decision": d["outcome"],
            "dry_run": d["dry_run"],
            "action": d.get("action"),
            "block_src": d.get("src_ip"),
            "block_dst": d.get("dst_ip"),
            "confidence": (sc.get("confidence") or {}).get("score") or d.get("confidence"),
            "latency_ms": round(d.get("latency_ms") or 0, 1),
        })
    return history


@router.post("/admin/reset")
async def admin_reset(request: Request) -> dict:
    """Reset in-memory safety state between eval runs (rate limiter + circuit breaker counters)."""
    agent = request.app.state.agent
    await agent._rate_limiter.reset()
    return {"ok": True, "reset": ["rate_limiter"]}


@router.get("/stream")
async def stream_decisions(request: Request) -> StreamingResponse:
    """SSE stream of decision events for real-time monitoring."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_queues.append(queue)

    async def event_generator():
        yield "data: {\"type\":\"connected\"}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(item)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            _sse_queues.remove(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
