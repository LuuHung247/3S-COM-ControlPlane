"""3 agent tools: get_alert_history, query_mitre_kb, generate_policy_intent."""
from typing import Any

from ..storage.redis import RedisStore

# ChromaDB client — optional import
try:
    import chromadb
    _CHROMA_AVAILABLE = True
except ImportError:
    _CHROMA_AVAILABLE = False

_chroma_client = None
_mitre_collection = None


def init_chroma(host: str, port: int, collection_mitre: str) -> None:
    global _chroma_client, _mitre_collection
    if not _CHROMA_AVAILABLE:
        return
    try:
        _chroma_client = chromadb.HttpClient(host=host, port=port)
        _mitre_collection = _chroma_client.get_or_create_collection(collection_mitre)
    except Exception:
        _chroma_client = None
        _mitre_collection = None


# ── Tool definitions for function calling ────────────────────────────────────

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
    {
        "type": "function",
        "function": {
            "name": "query_mitre_kb",
            "description": "Semantic search of MITRE ATT&CK knowledge base for technique context.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Natural language query about the technique"},
                    "n_results": {"type": "integer", "description": "Number of results", "default": 3},
                },
                "required": ["query"],
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


# ── Tool executors ────────────────────────────────────────────────────────────

async def execute_get_alert_history(redis: RedisStore, src_ip: str, limit: int = 10) -> dict:
    history = await redis.get_alert_history(src_ip, limit=limit)
    return {"src_ip": src_ip, "count": len(history), "history": history}


async def execute_query_mitre_kb(query: str, n_results: int = 3) -> dict:
    if _mitre_collection is None:
        return {"query": query, "results": [], "note": "ChromaDB unavailable"}
    try:
        results = _mitre_collection.query(query_texts=[query], n_results=n_results)
        docs = results.get("documents", [[]])[0]
        return {"query": query, "results": docs}
    except Exception as exc:
        return {"query": query, "results": [], "error": str(exc)}
