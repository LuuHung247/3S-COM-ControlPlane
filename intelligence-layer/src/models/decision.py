import hashlib
import uuid
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, model_validator


class PolicyAction(str, Enum):
    DROP = "DROP"
    LOG_ONLY = "log_only"
    HOLD = "hold"
    REJECT = "reject"


def _deterministic_rule_id(src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> str:
    """Idempotent rule_id: same flow tuple → same id → SF rejects/replaces dup."""
    key = f"{src_ip}|{dst_ip}|{dst_port}|{protocol}".lower()
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]
    return f"agent-{digest}"


class Hypothesis(BaseModel):
    """A candidate explanation the LLM considered before deciding."""
    name: str
    description: str = ""
    probability: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    disconfirming_evidence: list[str] = Field(default_factory=list)


class AlternativeAction(BaseModel):
    """Plan B if primary hypothesis turns out wrong."""
    trigger_condition: str
    action: str  # "DROP" | "log_only" | "ESCALATE_HUMAN"
    rationale: str = ""


class RollbackPlan(BaseModel):
    """How to revert this rule if it causes outage."""
    trigger: str = ""
    action: str = ""
    monitor_seconds: int = 300


class PolicyIntent(BaseModel):
    """Structured output forced via LLM function calling (L1 Schema).

    V2: includes hypothesis-driven reasoning + alternative actions + rollback plan.
    """
    rule_id: str = ""  # Set by validator from flow tuple — deterministic for idempotency
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

    # V2 — hypothesis-driven reasoning
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    primary_hypothesis: str = ""

    # V2 — alternative actions if conditions change
    alternative_actions: list[AlternativeAction] = Field(default_factory=list)

    # V2 — rollback safety net
    rollback_plan: RollbackPlan = Field(default_factory=RollbackPlan)

    # V2 — follow-up monitoring
    follow_up_actions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _set_deterministic_rule_id(self) -> "PolicyIntent":
        if not self.rule_id:
            object.__setattr__(
                self,
                "rule_id",
                _deterministic_rule_id(self.src_ip, self.dst_ip, self.dst_port, self.protocol),
            )
        return self


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
    trace_id: str = ""
