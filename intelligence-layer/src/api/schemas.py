"""API request/response Pydantic schemas."""
from typing import Any
from pydantic import BaseModel


class AlertIngest(BaseModel):
    """POST /alerts — inject a raw Suricata alert for processing."""
    data: dict[str, Any]


class DecisionResponse(BaseModel):
    id: str
    alert_sid: int
    alert_src_ip: str
    outcome: str
    action: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    confidence: float | None = None
    rejection_reason: str = ""
    latency_ms: float = 0.0
    dry_run: bool = True


class HealthResponse(BaseModel):
    status: str
    ids_agent: str
    dry_run: bool
    circuit_breaker: dict[str, Any]
    rate_limiter: dict[str, Any]


class RevokeResponse(BaseModel):
    success: bool
    rule_id: str
    error: str = ""
