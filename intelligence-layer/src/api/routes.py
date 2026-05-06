"""FastAPI routes: /health, /alerts, /decisions, /decisions/{id}/revoke, /stream."""
import asyncio
import json
from collections import deque
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse, HTMLResponse, Response

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
    intent = decision.intent
    from datetime import datetime as _dt, timezone as _tz
    reasoning_done = bool(intent and intent.reasoning_steps)

    decision_dict = {
        "id": decision.id,
        "alert_sid": decision.alert_sid,
        "alert_src_ip": decision.alert_src_ip,
        "outcome": decision.outcome.value,
        "action": intent.action.value if intent else None,
        "src_ip": intent.src_ip if intent else None,
        "dst_ip": intent.dst_ip if intent else None,
        "dst_port": intent.dst_port if intent else None,
        "confidence": intent.confidence if intent else None,
        "rejection_reason": decision.rejection_reason,
        "safety_checks": decision.safety_checks,
        "reasoning": intent.reasoning_steps if intent else [],
        "hypotheses": [h.model_dump() for h in intent.hypotheses] if intent else [],
        "rollback_plan": intent.rollback_plan.model_dump() if intent else {},
        "rule_id": intent.rule_id if intent else None,
        "ttl_seconds": intent.ttl_seconds if intent else None,
        "latency_ms": decision.latency_ms,
        "dry_run": agent._dry_run,
        "trace_id": getattr(decision, "trace_id", "") or "",
        "primary_hypothesis": intent.primary_hypothesis if intent else None,
        "alternative_actions": [a.model_dump() for a in intent.alternative_actions] if intent else [],
        "follow_up_actions": intent.follow_up_actions if intent else [],
        "mitre_technique": intent.mitre_technique if intent else None,
        "mitre_tactic": intent.mitre_tactic if intent else None,
        "reasoning_completed_at": _dt.now(_tz.utc) if reasoning_done else None,
    }

    # Persist
    await postgres.save_decision(decision_dict)
    await redis.cache_decision(decision.id, decision_dict)
    _push_decision(decision_dict)

    # P2: embed-on-write background task (semantic indexing for past-decision retrieval)
    if decision.intent is not None:
        from ..core.topology import ip_to_zone
        from ..storage.embedder import embed_text, build_decision_text
        intent = decision.intent
        doc = build_decision_text(
            sid=decision.alert_sid,
            src_zone=ip_to_zone(decision.alert_src_ip),
            dst_zone=ip_to_zone(intent.dst_ip) if intent.dst_ip else None,
            primary_hypothesis=intent.primary_hypothesis or "",
            reasoning_first_step=(intent.reasoning_steps[0] if intent.reasoning_steps else "")[:200],
            mitre_technique=intent.mitre_technique or "",
        )

        async def _embed_in_bg(doc_text: str, did: str) -> None:
            try:
                vec = await embed_text(doc_text)
                if vec is None:
                    import structlog
                    structlog.get_logger().warning("embed_skipped_null_vec", decision_id=did)
                    return
                ok = await postgres.write_embedding(did, vec)
                import structlog
                structlog.get_logger().info(
                    "embed_written", decision_id=did, dim=len(vec), ok=ok,
                )
            except Exception as exc:
                import structlog
                structlog.get_logger().warning(
                    "embed_failed", decision_id=did, error=str(exc),
                )

        # Hold task reference in app state to prevent GC of pending tasks
        bg_set = getattr(request.app.state, "_bg_embed_tasks", None)
        if bg_set is None:
            bg_set = set()
            request.app.state._bg_embed_tasks = bg_set
        task = asyncio.create_task(_embed_in_bg(doc, decision.id))
        bg_set.add(task)
        task.add_done_callback(bg_set.discard)

    return DecisionResponse(**{k: v for k, v in decision_dict.items() if k != "safety_checks"})


@router.get("/decisions")
async def list_decisions(request: Request, limit: int = 50) -> list[dict]:
    """List recent decisions for FE display. Reads from `decisions_history`
    so eval-run truncates of the workspace table don't erase audit visibility."""
    postgres = request.app.state.postgres
    return await postgres.list_decisions_history(limit=limit)


@router.get("/decisions/{decision_id}")
async def get_decision(decision_id: str, request: Request) -> dict:
    """Full decision detail incl V3 reasoning trace fields. Used by frontend
    'Reasoning' modal. Reads from `decisions_history` so decisions made during
    prior eval runs remain inspectable."""
    postgres = request.app.state.postgres
    record = await postgres.get_decision_history(decision_id)
    if record is None:
        # Fallback to workspace table for very-fresh decisions where history
        # write may still be in flight (extremely unlikely with sync dual-write,
        # but defensive against any edge case)
        record = await postgres.get_decision(decision_id)
    if record is None:
        raise HTTPException(status_code=404, detail="decision not found")
    return record


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
    all_decisions = await postgres.list_decisions_history(limit=limit)
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


@router.get("/events")
async def get_events(
    request: Request,
    since: str = "",
    limit: int = 600,
    kind: str = "all",
) -> list[dict]:
    """Fetch buffered events (alerts + flows) from Redis DB 1 (7-day retention).

    `since` accepts:
      - empty string → return last `limit` events newest-first
      - integer string → unix epoch milliseconds
      - ISO 8601 timestamp → parsed to ms
    `kind` is one of all | violation | flow.
    """
    store = request.app.state.events_store
    since_ms = 0
    if since:
        try:
            since_ms = int(since)
        except ValueError:
            try:
                from datetime import datetime
                since_ms = int(datetime.fromisoformat(since.replace("Z", "+00:00")).timestamp() * 1000)
            except Exception:
                since_ms = 0
    return await store.get_events(since_ms=since_ms, limit=min(limit, 2000), kind=kind)


@router.get("/events/stats")
async def events_stats(request: Request) -> dict:
    store = request.app.state.events_store
    return await store.stats()


@router.get("/cache/stats")
async def response_cache_stats(request: Request) -> dict:
    """Hit/miss counters for the LLM response cache (Phase B)."""
    cache = request.app.state.response_cache
    return await cache.stats()


@router.post("/cache/reset")
async def response_cache_reset(request: Request) -> dict:
    """Reset cache counters (does NOT flush cached entries — TTL handles those)."""
    cache = request.app.state.response_cache
    await cache.reset_stats()
    return {"ok": True, "reset": "stats"}


@router.get("/prompt/preview")
async def prompt_preview(
    request: Request,
    sid: int = 9000001,
    src_ip: str = "10.1.100.10",
    dst_ip: str = "10.1.200.10",
) -> dict:
    """Inspect the alert-scoped system prompt for a given alert shape.
    Useful to verify Part A dynamic knowledge selection is working."""
    knowledge = request.app.state.knowledge
    prompt = await knowledge.build_alert_specific_prompt(sid=sid, src_ip=src_ip, dst_ip=dst_ip)
    full = knowledge.render_static_core()
    return {
        "alert": {"sid": sid, "src_ip": src_ip, "dst_ip": dst_ip},
        "alert_scoped_prompt_chars": len(prompt),
        "alert_scoped_tokens_approx": len(prompt) // 4,
        "full_prompt_chars_for_comparison": len(full),
        "full_tokens_approx": len(full) // 4,
        "reduction_percent": round(100 * (1 - len(prompt) / max(len(full), 1)), 1),
        "prompt": prompt,
    }


@router.get("/kg/visualize", response_class=HTMLResponse)
async def visualize_knowledge_graph() -> HTMLResponse:
    """Render the agent's knowledge graph as interactive HTML.

    Shows: zones, assets, leafs, SIDs, kill chains, baselines, and relationships
    (membership, enforcement, policy ALLOW/DENY, kill-chain stages, traffic flows).
    Open in browser to inspect what the agent 'knows'.
    """
    from ..core.kg_visualizer import render_html_string
    html = render_html_string()
    return HTMLResponse(content=html)


@router.get("/kg/stats")
async def knowledge_graph_stats() -> dict:
    """Lightweight summary of KG contents — counts of each node type and edges."""
    from ..core.kg_visualizer import build_knowledge_graph
    G = build_knowledge_graph()
    type_counts: dict[str, int] = {}
    for _, attrs in G.nodes(data=True):
        t = attrs.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "by_type": type_counts,
    }


@router.get("/kg/json")
async def knowledge_graph_json() -> dict:
    """KG in Cytoscape.js elements format: {nodes: [...], edges: [...]}.

    Each node carries `data: {id, type, label, title, ...}` and each edge
    `data: {id, source, target, label, kind}` for client-side styling.
    """
    from ..core.kg_visualizer import build_knowledge_graph
    G = build_knowledge_graph()

    nodes = []
    for nid, attrs in G.nodes(data=True):
        nodes.append({
            "data": {
                "id": str(nid),
                "type": attrs.get("type", "unknown"),
                "label": attrs.get("label", str(nid)),
                "title": attrs.get("title", ""),
                "shape": attrs.get("shape", "ellipse"),
            }
        })

    edges = []
    seen_eids: set[str] = set()
    for u, v, k, attrs in G.edges(keys=True, data=True):
        label = attrs.get("label", "")
        eid = f"{u}->{v}#{k}"
        if eid in seen_eids:
            continue
        seen_eids.add(eid)
        kind = "policy" if label in ("ALLOW", "DENY") else (
            "membership" if label in ("member_of", "enforces") else (
                "stage" if str(label).startswith("stage") else (
                    "flow" if label in ("originates",) or str(label).startswith(":") else "other"
                )
            )
        )
        edges.append({
            "data": {
                "id": eid,
                "source": str(u),
                "target": str(v),
                "label": str(label),
                "kind": kind,
                "color": attrs.get("color", ""),
                "dashes": bool(attrs.get("dashes", False)),
            }
        })

    return {"nodes": nodes, "edges": edges}


@router.get("/kg/export/graphml")
async def knowledge_graph_export_graphml() -> Response:
    """Export KG as GraphML — open in yEd / Gephi / Cytoscape Desktop for figures."""
    import io
    import networkx as nx
    from ..core.kg_visualizer import build_knowledge_graph
    G = build_knowledge_graph()

    # GraphML doesn't support multi-edges with same key cleanly; convert to DiGraph
    H = nx.DiGraph()
    for n, attrs in G.nodes(data=True):
        H.add_node(n, **{k: str(v) for k, v in attrs.items()})
    for u, v, attrs in G.edges(data=True):
        if H.has_edge(u, v):
            existing = H[u][v].get("label", "")
            H[u][v]["label"] = f"{existing}|{attrs.get('label', '')}".strip("|")
        else:
            H.add_edge(u, v, **{k: str(v_) for k, v_ in attrs.items() if k != "dashes"})

    buf = io.BytesIO()
    nx.write_graphml(H, buf)
    return Response(
        content=buf.getvalue(),
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=zerotrust-kg.graphml"},
    )


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
