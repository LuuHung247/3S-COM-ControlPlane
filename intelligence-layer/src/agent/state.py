"""LangGraph agent state — TypedDict shared across all nodes."""
from typing import Any, TypedDict

from ..models.alert import SuricataAlert
from ..models.decision import PolicyIntent, DecisionOutcome


class AgentState(TypedDict, total=False):
    # Input
    alert: SuricataAlert
    context_snapshot: str          # Rendered KG snapshot injected into system prompt

    # Intermediate
    classification: str            # "benign" | "suspicious" | "threat"
    alert_history: list[dict]      # From Redis (raw events)
    ip_summary: dict | None        # Operational memory aggregated summary (30d window)
    correlation: dict | None       # Short-window kill-chain correlation (10min)
    alert_context: str             # Tier 3 alert-specific knowledge render

    # Cache (Phase B — response cache)
    cache_key: str
    cache_hit: bool

    # Tracing (Langfuse)
    trace_id: str
    _trace: Any   # Langfuse trace handle (or no-op stub)

    # Output
    intent: PolicyIntent | None
    outcome: DecisionOutcome
    rejection_reason: str
    safety_checks: dict[str, Any]
    error: str
