"""Agent tools and forced-output schema."""
from typing import Any

from ..storage.redis import RedisStore


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_alert_history",
            "description": "Retrieve the recent alert history for a given source IP from cache.",
            "parameters": {
                "type": "object",
                "properties": {
                    "src_ip": {"type": "string", "description": "Source IP address to look up"},
                    "limit": {"type": "integer", "description": "Max records to return", "default": 10},
                },
                "required": ["src_ip"],
            },
        },
    },
]

# generate_policy_intent is the forced output schema — not a tool call but function calling output
POLICY_INTENT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["DROP", "log_only"],
            "description": "Policy action. DROP for P1/P2 threats. log_only for P3/P4.",
        },
        "src_ip": {
            "type": "string",
            "description": "Source IP in CIDR notation (e.g. 10.1.100.10/32)",
        },
        "dst_ip": {
            "type": "string",
            "description": "Destination IP in CIDR notation, empty string if not applicable",
        },
        "dst_port": {
            "type": "integer",
            "description": "Destination port, 0 if not applicable",
        },
        "protocol": {
            "type": "string",
            "description": "Protocol (tcp, udp, icmp)",
        },
        "priority": {
            "type": "integer",
            "description": "Rule priority (lower = higher priority). Use 50 for agent rules.",
        },
        "ttl_seconds": {
            "type": "integer",
            "description": "Time-to-live in seconds. 3600 for P1, 1800 for P2.",
        },
        "comment": {
            "type": "string",
            "description": "Human-readable summary of reasoning (>20 chars)",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
            "description": "Confidence score [0-1] in this decision",
        },
        "reasoning_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Step-by-step reasoning chain leading to this decision",
        },
        "mitre_technique": {"type": "string", "description": "MITRE technique ID e.g. T1021"},
        "mitre_tactic": {"type": "string", "description": "MITRE tactic ID e.g. TA0008"},
    },
    "required": ["action", "src_ip", "confidence", "reasoning_steps"],
}


async def execute_get_alert_history(redis: RedisStore, src_ip: str, limit: int = 10) -> dict:
    history = await redis.get_alert_history(src_ip, limit=limit)
    return {"src_ip": src_ip, "count": len(history), "history": history}
