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
    alert_history: list[dict]      # From Redis
    mitre_context: str             # From ChromaDB RAG (optional)

    # Output
    intent: PolicyIntent | None
    outcome: DecisionOutcome
    rejection_reason: str
    safety_checks: dict[str, Any]
    error: str
