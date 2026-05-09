"""FastAPI application entry point with full lifespan wiring."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from .config import get_settings
from .observability.logging import configure_logging
from .observability.langfuse_tracer import LangfuseTracer, set_global_tracer
from .storage.redis import RedisStore
from .storage.postgres import PostgresStore
from .storage.operational_memory import OperationalMemory
from .storage.incident_memory import IncidentLabeler
from .storage.events_store import EventsStore
from .storage.neo4j_kg import Neo4jKG
from .core.knowledge_loader import KnowledgeLoader
from .pipeline.gate import AlertGate
from .pipeline.consumer import SSEConsumer
from .agent.llm.factory import get_llm_client
from .agent.safety.rate_limiter import RateLimiter
from .agent.safety.circuit_breaker import CircuitBreaker
from .agent.graph import DecisionAgent
from .agent.response_cache import ResponseCache
from .enforcement import get_backend
from .api.routes import router

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)

    log.info(
        "intelligence_layer_starting",
        dry_run=settings.agent_dry_run,
        enforcement="ids_agent_proxy",
    )

    # Langfuse tracer (initialize early so LLM client picks up via global)
    tracer = LangfuseTracer(
        host=settings.langfuse_host,
        public_key=settings.langfuse_public_key,
        secret_key=settings.langfuse_secret_key,
        enabled=settings.langfuse_enabled,
    )
    set_global_tracer(tracer)

    # Storage — DB 0 for agent state (eval-flushable), DB 1 for events (NOT flushed)
    redis = RedisStore(settings.redis_url, dedup_window=settings.filter_dedup_window_seconds)
    await redis.connect()

    events_store = EventsStore(
        settings.redis_events_url,
        retention_days=settings.events_retention_days,
        max_total=settings.events_max_total,
    )
    await events_store.connect()

    postgres = PostgresStore(settings.postgres_url)
    await postgres.connect()

    # Neo4j Knowledge Graph — ETL Pydantic models on startup. Best-effort:
    # if Neo4j unreachable (cold start ordering), agent still works using the
    # in-memory Pydantic source-of-truth; KG endpoints will return empty.
    neo4j_kg: Neo4jKG | None = None
    try:
        neo4j_kg = Neo4jKG(
            uri=settings.neo4j_uri,
            user=settings.neo4j_user,
            password=settings.neo4j_password,
        )
        await neo4j_kg.connect()
        await neo4j_kg.reload_from_models()
    except Exception as exc:
        log.warning("neo4j_kg_unavailable_continuing_without", error=str(exc))
        neo4j_kg = None

    # Knowledge loader (3-tier cache) + operational memory
    knowledge = KnowledgeLoader(settings.ids_agent_url, semi_dynamic_ttl=30)
    knowledge.render_static_core()         # Eagerly load Tier 1 at startup
    await knowledge.refresh_semi_dynamic(force=True)
    operational_memory = OperationalMemory(postgres)

    # Phase 4: incident memory background labeler
    incident_labeler = IncidentLabeler(
        postgres=postgres,
        ids_agent_url=settings.ids_agent_url,
        scan_interval_seconds=300,    # every 5 min
        label_age_minutes=30,         # only label decisions older than 30 min
    )
    await incident_labeler.start()

    # LLM clients
    fast_llm = get_llm_client("fast", settings)
    primary_llm = get_llm_client("primary", settings)

    # Safety subsystems
    rate_limiter = RateLimiter(
        max_per_minute=settings.safety_max_rules_per_minute,
        max_total=settings.safety_max_total_agent_rules,
        max_per_ip=settings.safety_max_rules_per_ip,
        per_ip_window=settings.safety_per_ip_window_seconds,
    )
    circuit_breaker = CircuitBreaker(
        fail_threshold=settings.safety_circuit_fail_threshold,
        halt_seconds=settings.safety_circuit_halt_seconds,
    )

    # Enforcement backend
    enforcement_backend = get_backend(settings)

    # Response cache — Redis-backed PolicyIntent cache (Phase B)
    response_cache = ResponseCache(
        redis=redis,
        ttl_seconds=settings.response_cache_ttl_seconds,
        enabled=settings.response_cache_enabled,
    )

    # Decision agent
    agent = DecisionAgent(
        knowledge=knowledge,
        fast_llm=fast_llm,
        primary_llm=primary_llm,
        redis=redis,
        postgres=postgres,
        operational_memory=operational_memory,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
        enforcement_backend=enforcement_backend,
        response_cache=response_cache,
        tracer=tracer,
        settings=settings,
        dry_run=settings.agent_dry_run,
    )

    # Alert gate (pre-LLM filters)
    gate = AlertGate(
        redis=redis,
        min_severity=settings.filter_severity_min,
        whitelist_ips=settings.filter_whitelist_ip_list,
    )

    # Wire into app state
    app.state.settings = settings
    app.state.agent = agent
    app.state.gate = gate
    app.state.redis = redis
    app.state.postgres = postgres
    app.state.enforcement_backend = enforcement_backend
    app.state.knowledge = knowledge
    app.state.incident_labeler = incident_labeler
    app.state.response_cache = response_cache
    app.state.tracer = tracer
    app.state.events_store = events_store
    app.state.neo4j_kg = neo4j_kg

    # SSE consumer — subscribe to ids-agent events
    import asyncio as _asyncio
    async def on_alert(alert):
        should, reason = await gate.should_process(alert)
        if not should:
            return
        from .api.routes import _push_decision
        decision = await agent.process(alert)
        from datetime import datetime as _dt, timezone as _tz
        intent = decision.intent
        # V3: reasoning fields are populated async by Stage 2 LLM call. If Stage 2
        # didn't finish or failed, these are empty/None — UI shows "loading".
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
            "dry_run": settings.agent_dry_run,
            "trace_id": getattr(decision, "trace_id", "") or "",
            # V3 reasoning trace fields
            "primary_hypothesis": intent.primary_hypothesis if intent else None,
            "alternative_actions": [a.model_dump() for a in intent.alternative_actions] if intent else [],
            "follow_up_actions": intent.follow_up_actions if intent else [],
            "mitre_technique": intent.mitre_technique if intent else None,
            "mitre_tactic": intent.mitre_tactic if intent else None,
            "reasoning_completed_at": _dt.now(_tz.utc) if reasoning_done else None,
        }
        await postgres.save_decision(decision_dict)
        await redis.cache_decision(decision.id, decision_dict)
        _push_decision(decision_dict)

        # P2: embed-on-write — semantic indexing for past-decision retrieval.
        # Background task so we don't block the SSE pipeline. Idempotent.
        if intent is not None:
            from .core.topology import ip_to_zone
            from .storage.embedder import embed_text, build_decision_text
            doc = build_decision_text(
                sid=decision.alert_sid,
                src_zone=ip_to_zone(decision.alert_src_ip),
                dst_zone=ip_to_zone(intent.dst_ip) if intent.dst_ip else None,
                signature="",
                primary_hypothesis=intent.primary_hypothesis or "",
                reasoning_first_step=(intent.reasoning_steps[0] if intent.reasoning_steps else "")[:200],
                mitre_technique=intent.mitre_technique or "",
            )

            async def _embed_in_bg(doc_text: str, did: str) -> None:
                try:
                    vec = await embed_text(doc_text)
                    if vec is None:
                        log.warning("embed_skipped_null_vec", decision_id=did)
                        return
                    ok = await postgres.write_embedding(did, vec)
                    log.info("embed_written", decision_id=did, dim=len(vec), ok=ok)
                except Exception as exc:
                    log.warning("embed_failed", decision_id=did, error=str(exc))

            bg_set = getattr(app.state, "_bg_embed_tasks", None)
            if bg_set is None:
                bg_set = set()
                app.state._bg_embed_tasks = bg_set
            task = _asyncio.create_task(_embed_in_bg(doc, decision.id))
            bg_set.add(task)
            task.add_done_callback(bg_set.discard)

    consumer = SSEConsumer(
        ids_agent_url=settings.ids_agent_url,
        on_alert=on_alert,
        events_store=events_store,
    )
    await consumer.start()

    # Background prune coroutine — every hour, drop events older than retention
    async def _prune_events_loop():
        while True:
            try:
                await _asyncio.sleep(3600)
                stats = await events_store.prune()
                log.info("events_prune_done", **stats)
            except _asyncio.CancelledError:
                return
            except Exception as exc:
                log.warning("events_prune_error", error=str(exc))
    prune_task = _asyncio.create_task(_prune_events_loop())

    log.info("intelligence_layer_ready", ids_agent=settings.ids_agent_url)

    yield

    # Shutdown
    prune_task.cancel()
    try:
        await prune_task
    except (BaseException, _asyncio.CancelledError):
        pass
    await consumer.stop()
    await incident_labeler.stop()
    await events_store.close()
    tracer.flush()
    tracer.shutdown()
    await redis.close()
    await postgres.close()
    if neo4j_kg is not None:
        await neo4j_kg.close()
    log.info("intelligence_layer_stopped")


app = FastAPI(
    title="Intelligence Layer",
    description="Zero Trust AI Policy Decision Engine",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
