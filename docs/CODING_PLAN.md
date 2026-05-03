# Coding Plan — Intelligence Layer cho Zero Trust Microsegmentation (Revised)

> **Phạm vi:** Build LLM Agent làm Intelligence Layer, tích hợp vào hệ thống hiện có.
> **Ngôn ngữ:** Python 3.12. Tích hợp qua SSE với Go IDS Agent, REST với Secure Framework.

---

## Những quyết định thiết kế đã xác nhận

### 1. Go IDS Agent — giữ nguyên, không thay đổi
- Vai trò: SSE/WebSocket bridge từ Suricata → Next.js dashboard
- Intelligence-layer subscribe SSE tại `GET :8766/events`
- Khi intelligence-layer **start** → `POST :8766/autoblock/disable` (lấy quyền enforce)
- Khi intelligence-layer **stop** → `POST :8766/autoblock/enable` (trả quyền lại, IDS Agent làm fallback)

### 2. Trigger mechanism — pure event-driven SSE
consumer.py parse SSE stream, lọc 3 loại line:
- `data: {"type":"connected"}` → skip (handshake)
- `: ping` → skip (15s keep-alive comment từ IDS Agent)
- `data: {suricata_alert_json}` → đây mới trigger filter chain

Auto-reconnect với exponential backoff khi connection drop.

### 3. Knowledge Architecture — Hybrid KG + RAG

**KG (NetworkX in-memory)** cho structured lookup:
- Topology: zones, hosts, LEAFs, relationships
- Policy matrix: zone-to-zone ALLOW/DENY (12 flows)
- SID→MITRE mapping: 9 Suricata SIDs → technique + tactic + recommended action
- Active SF rules: refresh mỗi 30s từ `GET SF_API_URL/api/rules`

**RAG (ChromaDB)** cho semantic search:
- MITRE ATT&CK full technique descriptions
- Dùng khi agent cần deeper threat context (tool: `query_mitre_kb`)

**KG nodes (16 nodes, ~25 edges):**
```
Zones (4):  WEB · DB · APP · MGT
Hosts (4):  Alpine-1 · Alpine-2 · Alpine-3 · Alpine-5
LEAFs (2):  LEAF-1 (WEB+DB) · LEAF-2 (APP+MGT)
IDS (1):    Suricata (monitor only, không enforce)
SIDs (9):   9000001 → 9000020
```
**KHÔNG đưa vào KG:** NAT1, NAT2, SONIC-SPINE (infrastructure/transit).

### 4. System Prompt Strategy — KG snapshot inject
- `core/snapshot.py` render KG → text string ~2-4K tokens
- Inject vào system prompt tại startup (cached, refresh 30s)
- Agent không cần gọi tool cho topology/policy/SID lookup
- **Target: < 2 tool calls per decision**

### 5. Tools — chỉ 3 (không phải 6 như plan gốc)
Topology + policy đã có trong system prompt → không cần làm tools riêng.

| Tool | Khi nào gọi |
|------|-------------|
| `get_alert_history(src_ip)` | IP này đã làm gì trước đó (Redis warm cache) |
| `query_mitre_kb(query)` | Deeper context về technique (ChromaDB semantic search) |
| `generate_policy_intent(...)` | Output cuối cùng của reasoning — **luôn luôn** |

### 6. Enforcement — sf_rest là primary
- `sf_rest.py`: `POST SF_API_URL/api/rules` với `source=agent`
- `ssh.py`: fallback khi SF không reach được (asyncssh → iptables trực tiếp)
- Check idempotency trước khi push (nếu rule đã tồn tại → skip, log "already_applied")

---

## Project Structure

```
intelligence-layer/
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── src/
│   ├── __init__.py
│   ├── config.py                  # Pydantic Settings — tất cả env vars
│   ├── main.py                    # FastAPI app + lifespan
│   │
│   ├── models/                    # Centralized Pydantic domain types
│   │   ├── __init__.py
│   │   ├── alert.py               # SuricataAlert, AlertSeverity
│   │   ├── decision.py            # PolicyDecision, PolicyIntent, Decision
│   │   ├── topology.py            # Zone, Host, TopologySnapshot
│   │   └── enforcement.py         # EnforcementResult, VerificationResult
│   │
│   ├── core/                      # Domain knowledge — KG + pure logic, no I/O
│   │   ├── __init__.py
│   │   ├── topology.py            # NetworkX DiGraph, ip_to_zone(), ip_to_leaf()
│   │   ├── policy.py              # POLICY_MATRIX dict, check_policy(), detect_conflict()
│   │   ├── knowledge.py           # SID→{mitre_id, technique, tactic, action} mapping
│   │   └── snapshot.py            # ContextSnapshot: KG + active rules → render_for_prompt()
│   │
│   ├── pipeline/                  # Alert intake pipeline
│   │   ├── __init__.py
│   │   ├── consumer.py            # SSE consumer + reconnect, start()/stop() lifecycle
│   │   ├── filters.py             # SeverityFilter, DedupFilter, RateLimiter, WhitelistFilter
│   │   └── gate.py                # Orchestrates filter chain → bool
│   │
│   ├── agent/                     # LangGraph agent core
│   │   ├── __init__.py
│   │   ├── state.py               # AgentState TypedDict
│   │   ├── graph.py               # LangGraph StateGraph wiring
│   │   ├── nodes.py               # 8 node functions (validation inline, không tách package)
│   │   ├── prompts.py             # build_system_prompt(snapshot) → str
│   │   ├── llm_client.py          # OpenAI-compatible wrapper + fallback + tenacity retry
│   │   └── tools.py               # 3 tools: get_alert_history, query_mitre_kb, generate_policy_intent
│   │
│   ├── enforcement/               # Enforcement backends
│   │   ├── __init__.py            # get_backend(settings) factory
│   │   ├── interface.py           # Abstract EnforcementBackend ABC
│   │   ├── sf_rest.py             # Primary: POST /api/rules source=agent (httpx async)
│   │   ├── ssh.py                 # Fallback: asyncssh → iptables -I FORWARD 1 -s <ip> -j DROP
│   │   ├── mock.py                # Tests: log actions, return success
│   │   └── onap.py                # Stub: NotImplementedError (future)
│   │
│   ├── storage/                   # Data persistence
│   │   ├── __init__.py
│   │   ├── redis.py               # Warm cache: alert history, decision cache, rate counters
│   │   └── postgres.py            # Cold storage: audit log, full ReAct trace
│   │
│   ├── api/                       # FastAPI endpoints
│   │   ├── __init__.py
│   │   ├── routes.py              # POST /alerts, GET /decisions, GET /health,
│   │   │                          # GET /stream/decisions (SSE), GET /stats,
│   │   │                          # POST /human/review/{id}
│   │   └── schemas.py             # API request/response Pydantic schemas
│   │
│   └── observability/
│       ├── __init__.py
│       ├── logging.py             # structlog JSON renderer
│       └── tracing.py             # OpenTelemetry + LangSmith env config
│
├── tests/
│   ├── fixtures/
│   │   ├── alerts.json            # 5 Suricata EVE alerts (P1×2, P2×2, P3×1)
│   │   └── topology.json          # Concrete topology từ DATAPLANE.md
│   ├── unit/
│   │   ├── test_filters.py
│   │   ├── test_validators.py
│   │   └── test_tools.py
│   └── integration/
│       ├── test_agent_flow.py     # Full graph run với mock LLM + mock enforcement
│       └── test_api.py            # FastAPI TestClient: tất cả endpoints
│
└── scripts/
    ├── init_db.py                 # Tạo Postgres tables via SQLAlchemy async
    ├── load_topology.py           # Load topology.json → KG + log snapshot
    ├── seed_mitre_kb.py           # MITRE ATT&CK JSON → embed → ChromaDB
    └── benchmark_agent.py         # Replay alerts.json, đo latency/throughput
```

---

## Concrete Topology Data (từ DATAPLANE.md + GNS3 lab)

```python
# src/core/topology.py
ZONES = {
    "WEB": {"cidr": "10.1.100.0/24", "leaf": "LEAF-1", "vlan": 100, "svi": "10.1.100.1"},
    "DB":  {"cidr": "10.1.200.0/24", "leaf": "LEAF-1", "vlan": 200, "svi": "10.1.200.1"},
    "APP": {"cidr": "10.2.100.0/24", "leaf": "LEAF-2", "vlan": 100, "svi": "10.2.100.1"},
    "MGT": {"cidr": "10.2.50.0/24",  "leaf": "LEAF-2", "vlan": 300, "svi": "10.2.50.1"},
}
HOSTS = {
    "Alpine-Linux-1": {"ip": "10.1.100.10", "zone": "WEB"},
    "Alpine-Linux-2": {"ip": "10.1.200.10", "zone": "DB"},
    "Alpine-Linux-3": {"ip": "10.2.100.10", "zone": "APP"},
    "Alpine-Linux-5": {"ip": "10.2.50.10",  "zone": "MGT"},
}
LEAFS = {
    "LEAF-1": {"zones": ["WEB", "DB"]},
    "LEAF-2": {"zones": ["APP", "MGT"]},
}

# src/core/policy.py
POLICY_MATRIX = {
    ("WEB", "DB"):  "DENY",   ("WEB", "APP"): "ALLOW", ("WEB", "MGT"): "DENY",
    ("DB",  "WEB"): "DENY",   ("DB",  "APP"): "DENY",  ("DB",  "MGT"): "DENY",
    ("APP", "WEB"): "DENY",   ("APP", "DB"):  "ALLOW", ("APP", "MGT"): "DENY",
    ("MGT", "WEB"): "ALLOW",  ("MGT", "DB"):  "ALLOW", ("MGT", "APP"): "ALLOW",
}

# src/core/knowledge.py — SID → MITRE + recommended action
SID_KNOWLEDGE = {
    9000001: {"severity": 1, "desc": "WEB direct to DB",         "tactic": "TA0008", "technique": "T1021", "action": "block"},
    9000002: {"severity": 1, "desc": "DB initiating outbound",   "tactic": "TA0010", "technique": "T1041", "action": "block"},
    9000006: {"severity": 1, "desc": "APP direct to DB lateral", "tactic": "TA0008", "technique": "T1021", "action": "block"},
    9000003: {"severity": 2, "desc": "APP reverse call WEB",     "tactic": "TA0008", "technique": "T1021", "action": "block"},
    9000004: {"severity": 2, "desc": "WEB to MGT escalation",    "tactic": "TA0004", "technique": "T1078", "action": "block"},
    9000005: {"severity": 2, "desc": "APP to MGT escalation",    "tactic": "TA0004", "technique": "T1078", "action": "block"},
    9000010: {"severity": 3, "desc": "ICMP ping sweep",          "tactic": "TA0043", "technique": "T1018", "action": "log_only"},
    9000011: {"severity": 3, "desc": "TCP port scan",            "tactic": "TA0043", "technique": "T1046", "action": "log_only"},
    9000020: {"severity": 4, "desc": "MGT zone access audit",    "tactic": "TA0007", "technique": "T1082", "action": "log_only"},
}
```

---

## AgentState Schema

```python
# src/agent/state.py
class AgentState(TypedDict):
    # Input
    alert: dict
    alert_id: str
    trigger_time: str

    # Context (từ KG snapshot, pre-loaded)
    context_snapshot: str          # rendered text từ ContextSnapshot
    active_rules: list             # SF rules hiện tại

    # Dynamic context (từ tools)
    alert_history: list
    recent_decisions: list

    # Agent workflow
    messages: Annotated[Sequence[BaseMessage], add_messages]
    classification: str | None     # "benign" | "suspicious" | "threat"
    policy_decision: dict | None   # PolicyIntent từ generate_policy_intent tool

    # Validation
    validation_passed: bool
    validation_errors: list
    confidence_score: float
    requires_human_review: bool

    # Enforcement
    enforcement_status: str | None  # "pending" | "applied" | "failed" | "already_applied"
    enforcement_details: dict | None
```

---

## LangGraph Workflow

```
[START]
   ↓
[load_context]       ← ContextSnapshot từ KG (hot cache, ~0ms)
   ↓
[classify_alert]     ← LLM fast model: benign / suspicious / threat
   ↓
{router: is_threat?}
   ├─ no  → [log_and_end]
   └─ yes → [gather_context]    ← get_alert_history tool call
              ↓
          [reason_and_decide]   ← LLM primary model
              ↓                    (query_mitre_kb nếu cần, generate_policy_intent)
          [validate_decision]   ← schema + policy conflict + confidence (inline trong node)
              ↓
          {router: validation_passed?}
              ├─ no (retry < 2) → [reason_and_decide]
              ├─ no (retry >= 2) → [escalate_human]
              └─ yes → [enforce_policy]   ← sf_rest.py (idempotent)
                         ↓
                     [record_decision]   ← Postgres + Redis + SSE broadcast
                         ↓
                     [END]
```

---

## API Endpoints

```
POST /alerts                    # Nhận alert trực tiếp (alternative to SSE)
GET  /decisions                 # List recent decisions
GET  /decisions/{id}            # Decision detail + full ReAct trace
GET  /health                    # Health check (DB + Redis + LLM status)
GET  /stream/decisions          # SSE stream cho dashboard
GET  /stats                     # decisions/min, avg latency, enforcement rate
POST /human/review/{id}         # Human approve/reject escalated decision
```

---

## Environment Variables (.env.example)

```bash
# LLM Provider (OpenAI-compatible)
LLM_API_KEY=
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_MODEL_PRIMARY=llama-3.3-70b-versatile
LLM_MODEL_FAST=llama-3.1-8b-instant
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048
LLM_TIMEOUT_SECONDS=10

# Fallback LLM
LLM_FALLBACK_API_KEY=
LLM_FALLBACK_BASE_URL=https://openrouter.ai/api/v1
LLM_FALLBACK_MODEL=

# Infrastructure
REDIS_URL=redis://localhost:6379/0
POSTGRES_URL=postgresql+asyncpg://ztuser:ztpass@localhost:5432/zerotrust
CHROMA_HOST=localhost
CHROMA_PORT=8001
CHROMA_COLLECTION=mitre_attack

# Integration
IDS_AGENT_URL=http://ids-agent:8766
SF_API_URL=http://10.10.6.238:9090

# Agent behavior
AGENT_CONFIDENCE_THRESHOLD=0.7
AGENT_MAX_RETRIES=2

# Trigger filters
FILTER_SEVERITY_MIN=2
FILTER_DEDUP_WINDOW_SECONDS=30
FILTER_RATE_LIMIT_PER_MINUTE=30
FILTER_WHITELIST_IPS=

# Enforcement
ENFORCEMENT_BACKEND=sf_rest
SSH_LEAF1_HOST=192.168.122.20
SSH_LEAF1_USER=admin
SSH_LEAF1_PASSWORD=YourPaSsWoRd
SSH_LEAF2_HOST=192.168.122.21
SSH_LEAF2_USER=admin
SSH_LEAF2_PASSWORD=YourPaSsWoRd

# Observability
LANGSMITH_API_KEY=
LANGSMITH_PROJECT=zerotrust-agent
LOG_LEVEL=INFO
```

---

## Implementation Order

| Bước | Files | Acceptance |
|------|-------|-----------|
| 1 | `config.py`, `observability/` | import không lỗi |
| 2 | `models/` | tất cả Pydantic types |
| 3 | `core/` | KG build được, `ip_to_zone("10.1.100.10") == "WEB"` |
| 4 | `storage/` | Redis + Postgres connect |
| 5 | `pipeline/` | Filter chain pass/reject đúng |
| 6 | `agent/` | Graph chạy end-to-end với mock LLM |
| 7 | `enforcement/` | sf_rest push rule thành công |
| 8 | `api/` + `main.py` | `curl /health` → 200 |
| 9 | `scripts/` | DB init + MITRE seed |
| 10 | `tests/` | unit + integration pass |

---

## Acceptance Criteria

1. Alert P1 → Agent reason → validate → sf_rest push DROP rule → rule tồn tại trên SF
2. Confidence < 0.5 → escalate, không tự enforce
3. Duplicate block → idempotent, không lỗi
4. IDS Agent auto-block disabled khi intelligence-layer running
5. `curl /health` trả đủ status của DB, Redis, LLM
6. `GET /stream/decisions` SSE stream broadcast realtime khi có decision mới
7. Median latency alert→decision < 3s (bao gồm LLM call)

---

## Verification Commands

```bash
cd /home/dis/deploy/zerotrust/intelligence-layer

# Start infra
docker compose up -d redis postgres chroma

# Init
uv run python scripts/init_db.py
uv run python scripts/seed_mitre_kb.py

# Start service
uv run uvicorn src.main:app --port 8767 --reload

# Test
curl http://localhost:8767/health
uv run pytest tests/unit/ -v
uv run pytest tests/integration/ -v
```
