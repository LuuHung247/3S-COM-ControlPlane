from enum import Enum
from typing import Any
from pydantic import BaseModel, Field
import uuid


class PolicyAction(str, Enum):
    DROP = "DROP"
    LOG_ONLY = "log_only"
    HOLD = "hold"
    REJECT = "reject"


class PolicyIntent(BaseModel):
    """Structured output forced via LLM function calling (L1 Schema)."""
    rule_id: str = Field(default_factory=lambda: f"agent-{uuid.uuid4().hex[:8]}")
    action: PolicyAction
    src_ip: str  # CIDR notation e.g. 10.1.100.10/32
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "tcp"
    priority: int = 50
    ttl_seconds: int = 3600
    comment: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning_steps: list[str] = Field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""


class DecisionOutcome(str, Enum):
    ENFORCED = "enforced"
    DRY_RUN = "dry_run"
    REJECTED = "rejected"
    HELD = "held"
    BENIGN = "benign"
    ERROR = "error"


class PolicyDecision(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_sid: int
    alert_src_ip: str
    intent: PolicyIntent | None = None
    outcome: DecisionOutcome
    rejection_reason: str = ""
    safety_checks: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0
    created_at: str = ""
