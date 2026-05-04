"""FastAPI application entry point with full lifespan wiring."""
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from .config import get_settings
from .observability.logging import configure_logging
from .storage.redis import RedisStore
from .storage.postgres import PostgresStore
from .storage.operational_memory import OperationalMemory
from .core.knowledge_loader import KnowledgeLoader
from .pipeline.gate import AlertGate
from .pipeline.consumer import SSEConsumer
from .agent.llm.factory import get_llm_client
from .agent.safety.rate_limiter import RateLimiter
from .agent.safety.circuit_breaker import CircuitBreaker
from .agent.graph import DecisionAgent
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
            "confidence": decision.intent.confidence if decision.intent else None,
            "rejection_reason": decision.rejection_reason,
            "safety_checks": decision.safety_checks,
            "latency_ms": decision.latency_ms,
            "dry_run": settings.agent_dry_run,
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
