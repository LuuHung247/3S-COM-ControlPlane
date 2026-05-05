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

    # Storage
    redis = RedisStore(settings.redis_url, dedup_window=settings.filter_dedup_window_seconds)
    await redis.connect()

    postgres = PostgresStore(settings.postgres_url)
    await postgres.connect()

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

    # SSE consumer — subscribe to ids-agent events
    async def on_alert(alert):
        should, reason = await gate.should_process(alert)
        if not should:
            return
        from .api.routes import _push_decision
        decision = await agent.process(alert)
        decision_dict = {
            "id": decision.id,
            "alert_sid": decision.alert_sid,
            "alert_src_ip": decision.alert_src_ip,
            "outcome": decision.outcome.value,
            "action": decision.intent.action.value if decision.intent else None,
            "src_ip": decision.intent.src_ip if decision.intent else None,
            "dst_ip": decision.intent.dst_ip if decision.intent else None,
            "dst_port": decision.intent.dst_port if decision.intent else None,
            "confidence": decision.intent.confidence if decision.intent else None,
            "rejection_reason": decision.rejection_reason,
            "safety_checks": decision.safety_checks,
            "reasoning": decision.intent.reasoning_steps if decision.intent else [],
            "hypotheses": [h.model_dump() for h in decision.intent.hypotheses] if decision.intent else [],
            "rollback_plan": decision.intent.rollback_plan.model_dump() if decision.intent else {},
            "rule_id": decision.intent.rule_id if decision.intent else None,
            "ttl_seconds": decision.intent.ttl_seconds if decision.intent else None,
            "latency_ms": decision.latency_ms,
            "dry_run": settings.agent_dry_run,
            "trace_id": getattr(decision, "trace_id", "") or "",
        }
        await postgres.save_decision(decision_dict)
        await redis.cache_decision(decision.id, decision_dict)
        _push_decision(decision_dict)

    consumer = SSEConsumer(ids_agent_url=settings.ids_agent_url, on_alert=on_alert)
    await consumer.start()
    log.info("intelligence_layer_ready", ids_agent=settings.ids_agent_url)

    yield

    # Shutdown
    await consumer.stop()
    await incident_labeler.stop()
    tracer.flush()
    tracer.shutdown()
    await redis.close()
    await postgres.close()
    log.info("intelligence_layer_stopped")


app = FastAPI(
    title="Intelligence Layer",
    description="Zero Trust AI Policy Decision Engine",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router)
