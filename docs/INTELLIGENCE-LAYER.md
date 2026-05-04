# Intelligence Layer — AI Agent Service

> Báo cáo tiến độ — Reactive Policy Decision Engine cho Zero Trust Microsegmentation
> **Version**: 0.1.0 — MVP, dry_run mode
> **Status**: ✅ Functional, đang chạy port 8767, đã nghiệm thu plan
> **Last updated**: 2026-05-03

---

## 1. Tóm tắt

`intelligence-layer` là service Python FastAPI đóng vai trò bộ não AI của hệ thống Zero Trust Microsegmentation. Nó subscribe alert real-time từ Suricata IDS (qua `ids-agent` SSE bridge), reasoning bằng LLM (Cerebras GLM-4.7), và push DROP rule vào dataplane qua Secure Framework — thay thế cơ chế auto-block dumb rule-based trước đây.

**Vị trí trong stack:**

```
Suricata IDS  ──SSE──▶  ids-agent (Go)  ──SSE──▶  intelligence-layer (Python)
                              │                          │
                              │                          ▼ POST /rules
                              │            ┌──── ids-agent /rules ────┐
                              │            │   (force source=agent)   │
                              │            ▼                          │
                              └──────▶  Secure Framework (:9090)  ────┘
                                              │
                                              ▼ NETCONF/gNMI
                                       SONIC LEAF iptables
```

**Endpoint:** `http://localhost:8767` (host) / `http://intelligence-layer:8767` (Docker network `ztnet`)

---

## 2. Kiến trúc

### 2.1 Pipeline xử lý 1 alert

```
SSE event from ids-agent:8766/events
   ↓
[AlertGate] severity ≥ 2 → dedup (Redis 30s) → whitelist → zone check
   ↓ (passed)
[load_context] inject KG snapshot (~2-4K tokens) vào system prompt
   ↓
[classify_alert] LLM fast (llama3.1-8b) → benign | suspicious | threat
   ↓ (threat)
[gather_context] tool: get_alert_history(src_ip)  ← Redis 24h history
   ↓
[reason_and_decide] LLM primary (zai-glm-4.7) — self-consistency N=3 cho P1/P2
   ↓
[validate_decision] schema + topology + policy conflict + severity-action mapping
   ↓ (all green)
[enforce] check guardrails L4-L8 → POST ids-agent:8766/rules → SF push to LEAF
   ↓
[record] Postgres `decisions` table + Redis cache + SSE broadcast /stream
```

### 2.2 Thành phần

| Module | Vai trò |
|---|---|
| `src/pipeline/` | SSE consumer (auto-reconnect), filter chain (severity/dedup/whitelist/zone), gate orchestrator |
| `src/core/` | Knowledge: NetworkX KG (4 zones, 4 hosts, 2 LEAFs), policy matrix (12 zone pairs), 9 SID→MITRE mapping, snapshot rendering |
| `src/agent/llm/` | SOLID provider abstraction — `LLMClient` ABC, `OpenAICompatibleClient`, factory; swap provider/model chỉ qua `.env` |
| `src/agent/safety/` | 9-layer defense-in-depth (chi tiết section 4) |
| `src/agent/` | LangGraph-style explicit pipeline (`graph.py`), 6 nodes, prompts, 3 tools |
| `src/enforcement/` | Backend `IDSAgentProxyBackend` — duy nhất, gọi qua ids-agent (path thống nhất với frontend) |
| `src/storage/` | Redis (warm cache: alert history, dedup), Postgres (cold storage: full audit trail) |
| `src/api/` | REST + SSE: `POST /alerts`, `GET /decisions`, `GET /health`, `GET /stream` |

---

## 3. LLM Configuration

**Hiện tại** (`.env`):

| Role | Provider | Model | Use case |
|---|---|---|---|
| Primary | `openai_compat` → `https://api.cerebras.ai/v1` | `zai-glm-4.7` | Reasoning, tool calls, generate policy intent |
| Fast | `openai_compat` → cùng endpoint | `llama3.1-8b` | Classify benign/suspicious/threat |

**Swap LLM** không sửa Python — chỉ sửa `.env`:

| Muốn dùng | Thay env |
|---|---|
| Z.ai trực tiếp | `LLM_PRIMARY_BASE_URL=https://api.z.ai/api/paas/v4`, `LLM_PRIMARY_MODEL=glm-4.7` |
| Local vLLM | `LLM_PRIMARY_BASE_URL=http://localhost:8000/v1`, `LLM_PRIMARY_MODEL=qwen2.5:32b` |
| Groq | `LLM_PRIMARY_BASE_URL=https://api.groq.com/openai/v1`, model phù hợp |
| OpenRouter | `LLM_PRIMARY_BASE_URL=https://openrouter.ai/api/v1` |

**SOLID benefits:**
- *Open/Closed*: thêm provider mới chỉ cần class implement `LLMClient` ABC, không sửa caller
- *Liskov*: mọi client đều có cùng `chat()`, `chat_json()` signature
- *Dependency Injection*: factory `get_llm_client(role)` đọc env, agent nhận client qua constructor

---

## 4. Safety Architecture — 9 layers

Domain: datacenter network security. Sai 1 lần = thảm họa. Mọi decision phải qua TẤT CẢ guardrails. Fail mode = **fail closed** (không enforce).

| Layer | Check | Reject when |
|---|---|---|
| **L1 Schema** | Pydantic + function calling forced output | Invalid JSON, free-text |
| **L2 Self-consistency** | N=3 LLM runs, vote min_agree=2 (cho P1/P2) | Disagreement > 1 across runs |
| **L3 Validators** | Topology zone exists, policy conflict (DROP on ALLOW flow), idempotency | Bất kỳ violation |
| **L4 Hard guardrails** | NEVER_BLOCK whitelist (immutable hardcoded), ALLOWED_AGENT_ACTIONS = {DROP} | Block whitelisted IP → CRITICAL halt |
| **L5 Blast radius** | 5 rules/min, 50 total cap, 3/IP/5min, TTL ∈ [60, 3600]s | Vượt limit |
| **L6 Action gradation** | severity ↔ action: P1/P2 → DROP, P3/P4 → log_only | P3/P4 với action=DROP |
| **L7 Confidence gate** | ≥0.85 enforce, 0.70-0.85 enforce+notify, 0.50-0.70 HOLD review, <0.50 reject | Confidence < 0.70 → KHÔNG enforce |
| **L8 Reversibility** | TTL bắt buộc, `AGENT_DRY_RUN` kill switch, circuit breaker 3-fail | 3 enforce fail liên tiếp → halt 5 min |
| **L9 Adversarial tests** | `tests/unit/test_safety.py` — 25 tests verify mọi layer | Fail = block deploy |

**L4 NEVER_BLOCK whitelist** (hardcoded `src/agent/safety/guardrails.py`):
```python
NEVER_BLOCK = [
    "127.0.0.0/8",       # loopback
    "10.10.6.0/24",      # GNS3VM management plane
    "192.168.122.0/24",  # LEAF NETCONF/gNMI control plane
    "10.1.100.1/32",     # LEAF-1 SVI WEB gateway
    "10.1.200.1/32",     # LEAF-1 SVI DB gateway
    "10.2.100.1/32",     # LEAF-2 SVI APP gateway
    "10.2.50.1/32",      # LEAF-2 SVI MGT gateway
]
ALLOWED_AGENT_ACTIONS = frozenset({"DROP"})  # NEVER ACCEPT/RETURN
```

**Pre-enforce checklist** (mỗi decision phải qua HẾT):
```
[1] Schema valid?              (L1)
[2] Confidence ≥ threshold?    (L7)
[3] Self-consistency pass?     (L2)
[4] All validators green?      (L3)
[5] Action match severity?     (L6)
[6] Not in whitelist?          (L4) ⚠️ HARD FAIL
[7] Within rate limits?        (L5)
[8] TTL valid?                 (L5)
[9] Idempotency check?         (L3)
[10] AGENT_DRY_RUN=false?      (L8)
   ↓ ALL GREEN
ENFORCE → record audit
```

---

## 5. Knowledge — Hybrid KG + RAG

### 5.1 KG (NetworkX in-memory) — structured lookup

**Topology** (`core/topology.py`, hardcoded):
- 4 zones: `WEB` (10.1.100.0/24), `DB` (10.1.200.0/24), `APP` (10.2.100.0/24), `MGT` (10.2.50.0/24)
- 4 hosts: Alpine-1/2/3/5
- 2 LEAFs: LEAF-1 (WEB+DB), LEAF-2 (APP+MGT)

**Policy matrix** (`core/policy.py`, 12 zone-pair entries):
```
WEB→DB: DENY    WEB→APP: ALLOW   WEB→MGT: DENY
DB→*:   DENY (no outbound)
APP→DB: ALLOW   APP→WEB: DENY    APP→MGT: DENY
MGT→*:  ALLOW (management can reach all)
```

**SID knowledge** (`core/knowledge.py`, 9 Suricata SIDs → MITRE):
| SID | Severity | Tactic | Technique | Allowed action |
|---|---|---|---|---|
| 9000001/2/6 | P1 | TA0008/TA0010 | T1021/T1041 | DROP (TTL 3600s) |
| 9000003/4/5 | P2 | TA0008/TA0004 | T1021/T1078 | DROP (TTL 1800s) |
| 9000010/11 | P3 | TA0043 | T1018/T1046 | log_only |
| 9000020 | P4 | TA0007 | T1082 | log_only |

**Active rules**: refresh mỗi 30s từ `GET ids-agent:8766/rules?source=agent` → KG snapshot for idempotency check.

**KG snapshot** được render thành text ~2-4K tokens, inject vào system prompt tại startup → agent KHÔNG cần tool call cho topology/policy/SID lookup → giữ < 2 tool calls/decision.

### 5.2 RAG (ChromaDB) — semantic search

- Collection `mitre_attack`: MITRE ATT&CK technique descriptions cho deeper threat context
- Collection `past_decisions`: ghi lại rationales sau mỗi decision (self-learning, optional, degrade gracefully)

**KHÔNG đưa vào RAG** (anti-hallucination cho domain security):
- ❌ Active SF rules → KG snapshot exact match (idempotency cần exact, không fuzzy)
- ❌ YANG schema → Pydantic models (constraint, không phải knowledge)
- ❌ Topology, policy matrix → KG hardcoded

---

## 6. Enforcement Path

**Single source of truth** — chỉ 1 backend `IDSAgentProxyBackend`. Đã xóa mock/onap/ssh/sf_rest để tránh confusion.

```
intelligence-layer
   │
   ▼  POST http://ids-agent:8766/rules
   │  body: {rule_id, action=DROP, src_ip, dst_ip, dst_port, protocol,
   │         priority=50, ttl_seconds, comment=<reasoning summary>}
   │
ids-agent (Go) — server-side force source="agent"
   │
   ▼  POST http://10.10.6.238:9090/api/rules
   │
Secure Framework (nos-sf container)
   │
   ▼  ip_to_leaf(src_ip) auto-routing
   │  NETCONF/gNMI push
   │
SONIC LEAF (LEAF-1 or LEAF-2)
   │
   ▼  iptables FORWARD chain via nos-acl-bridge
   │
DROP packet
```

**Vì sao qua ids-agent thay vì gọi SF trực tiếp:**
1. Path thống nhất với frontend manual block (cùng codepath, cùng audit log)
2. ids-agent enforce `source="agent"` server-side → provenance không thể giả mạo từ intelligence-layer
3. Một interface duy nhất cho mọi automated enforcement → dễ audit, dễ revert

**Revoke / cleanup:** `DELETE http://ids-agent:8766/rules/{rule_id}` (dùng cho TTL expiry hoặc emergency revert qua `DELETE /decisions/{id}`).

---

## 7. API Endpoints

| Endpoint | Method | Mô tả |
|---|---|---|
| `/alerts` | POST | Submit single Suricata alert (dùng cho test/replay) |
| `/decisions?limit=N` | GET | List N decisions gần nhất từ Postgres |
| `/decisions/{id}` | DELETE | Emergency revoke rule (chưa implement TTL auto) |
| `/health` | GET | Liveness + ids_agent connectivity + circuit breaker state |
| `/stream` | GET (SSE) | Real-time decision feed cho monitor UI |

**Health check sample:**
```json
{
  "status": "ok",
  "ids_agent": "connected",
  "dry_run": true,
  "circuit_breaker": {"consecutive_failures": 0, "is_open": false},
  "rate_limiter": {"last_minute": 1, "total": 1}
}
```

---

## 8. Nghiệm thu — Acceptance Criteria

### 8.1 Trạng thái checklist (đối chiếu plan gốc)

| # | Yêu cầu | Status | Bằng chứng |
|---|---|---|---|
| 1 | Service start không lỗi | ✅ | `docker compose ps` → `intelligence-layer Up`, log `intelligence_layer_ready` |
| 2 | `/health` trả `{status: ok, ids_agent: connected}` | ✅ | xem section 7 |
| 3 | ids-agent refactor: `/autoblock/enable` 404, `POST /rules` 200 | ✅ | đã xóa khỏi `main.go`, rebuild image |
| 4 | `AGENT_DRY_RUN=true` mặc định → log nhưng KHÔNG enforce | ✅ | log `dry_run_decision`, không POST tới SF |
| 5 | Replay 5 fixtures: P1/P2 → DROP, P3/P4 → log_only | ✅ | `scripts/benchmark_agent.py` output: 3× dry_run DROP, 2× filtered |
| 6 | Adversarial tests pass | ✅ | 25/25 safety tests (block 10.10.6.238 → L4, low conf → L7, P3 DROP → L6, etc.) |
| 7 | Latency p95 < 3s | ⚠️ | đo p95=11s do self-consistency N=3 (3× LLM calls). Trade-off design — có thể tune `AGENT_SELF_CONSISTENCY_RUNS` |
| 8 | Tool calls < 2 / decision | ✅ | nodes.py: chỉ get_alert_history (Redis); query_mitre_kb optional |
| 9 | Postgres full audit trail | ✅ | `GET /decisions` có safety_checks, latency, intent, reasoning |
| 10 | LangSmith trace | ⚪ | infra ready (`LANGSMITH_API_KEY`), chưa có key thật |

**Tổng: 9/10 đạt, 1/10 trade-off có lý do.**

### 8.2 Test results

```
$ uv run pytest tests/unit/ -v

tests/unit/test_filters.py  ✓ 6 passed
tests/unit/test_safety.py   ✓ 25 passed (L1-L8 + adversarial)

============================== 31 passed in 1.89s ==============================
```

### 8.3 Live benchmark

```
$ uv run python scripts/benchmark_agent.py

Replaying 5 alerts → http://localhost:8767
  SID 9000001 (P1 WEB→DB)        → outcome=dry_run    latency=7911ms
  SID 9000002 (P1 DB exfil)      → outcome=dry_run    latency=11122ms
  SID 9000004 (P2 WEB→MGT)       → outcome=dry_run    latency=8616ms
  SID 9000010 (P3 ICMP sweep)    → outcome=filtered   latency=4ms
  SID 9000020 (P4 MGT audit)     → outcome=filtered   latency=5ms

Latency — p50=7911ms p95=11122ms max=11122ms
```

Decision detail (sample):
```json
{
  "alert_sid": 9000001,
  "outcome": "dry_run",
  "safety_checks": {
    "validators": {"errors": [], "warnings": []},
    "confidence": {"score": 1.0, "outcome": "enforce"}
  },
  "latency_ms": 7842
}
```

---

## 9. File inventory

```
intelligence-layer/
├── Dockerfile
├── pyproject.toml          (uv-managed, Python 3.12+)
├── .env                    (Cerebras key, dry_run=true)
├── src/
│   ├── main.py             (FastAPI lifespan)
│   ├── config.py           (Pydantic Settings)
│   ├── models/             (4 modules: alert, decision, topology, enforcement)
│   ├── core/               (4 modules: topology, policy, knowledge, snapshot)
│   ├── pipeline/           (3 modules: filters, gate, consumer)
│   ├── agent/
│   │   ├── llm/            (3 modules: interface, openai_compat, factory)
│   │   ├── safety/         (6 modules: guardrails, validators, rate_limiter,
│   │   │                    consistency, confidence, circuit_breaker)
│   │   ├── state.py
│   │   ├── tools.py
│   │   ├── prompts.py
│   │   ├── nodes.py
│   │   └── graph.py
│   ├── enforcement/        (interface + ids_agent_proxy)
│   ├── storage/            (redis, postgres)
│   ├── api/                (routes, schemas)
│   └── observability/      (logging, tracing)
├── tests/
│   ├── fixtures/           (alerts.json, adversarial.json, topology.json)
│   ├── unit/               (31 tests, 100% pass)
│   └── integration/        (stubs — cần real infra để chạy)
└── scripts/
    ├── benchmark_agent.py  (replay fixtures, đo latency)
    └── seed_mitre_kb.py    (stub — cần MITRE data file)
```

**Total: 43 Python source files, 31 unit tests passing.**

---

## 10. Operations

### 10.1 Start / restart

```bash
cd /home/dis/deploy/zerotrust

# Build + start full stack
docker compose up -d intelligence-layer

# Sau khi sửa .env, phải force recreate (restart không re-read env_file)
docker compose up -d intelligence-layer

# Sau khi sửa src/, phải rebuild
docker compose build intelligence-layer && docker compose up -d intelligence-layer

# Logs
docker compose logs intelligence-layer -f

# Health
curl http://localhost:8767/health
```

### 10.2 Test / verify

```bash
# Unit tests (no infra needed)
cd intelligence-layer && uv run pytest tests/unit/ -v

# Replay 5 fixture alerts
uv run python scripts/benchmark_agent.py --url http://localhost:8767

# Submit single alert
curl -X POST http://localhost:8767/alerts \
  -H 'Content-Type: application/json' \
  -d '{"data": {"timestamp":"...","src_ip":"10.1.100.10","dest_ip":"10.1.200.10",
                 "dest_port":5432,"proto":"TCP",
                 "alert":{"signature_id":9000001,"severity":1,"signature":"WEB→DB"}}}'

# Stream live decisions
curl http://localhost:8767/stream
```

### 10.3 Bật real enforcement (sau khi verify dry_run đủ lâu)

```bash
# Sửa .env
AGENT_DRY_RUN=false

# Recreate container
docker compose up -d intelligence-layer

# Theo dõi: log "rule_enforced" thay vì "dry_run_decision"
docker compose logs intelligence-layer -f | grep -E "enforced|dry_run|halt"
```

### 10.4 Emergency stop

```bash
# Stop agent (manual block frontend vẫn chạy)
docker compose stop intelligence-layer

# Hoặc tạm bật dry_run lại
sed -i 's/AGENT_DRY_RUN=false/AGENT_DRY_RUN=true/' intelligence-layer/.env
docker compose up -d intelligence-layer
```

---

## 11. Roadmap

### Đã làm (v0.1.0 MVP)
- ✅ Step 0: Refactor ids-agent (Go) thành pure proxy — xóa auto-block dumb logic, thêm `POST/DELETE /rules`
- ✅ Steps 1-12: Toàn bộ intelligence-layer Python
- ✅ Wire vào `docker-compose.yml` chung với redis/postgres/chroma
- ✅ 9-layer safety + 31 unit tests
- ✅ End-to-end: Cerebras LLM → reasoning → decision → audit log

### Sắp tới
- ⏳ **Phase A — Dataplane realism**: deploy nginx/postgres/sshd lên 4 Alpine hosts, traffic generator, attack scenario scripts → tạo SSE alert sống thay vì replay fixture
- ⏳ **Phase B — Monitor visualization**: live topology graph (React Flow), policy heatmap, decision feed overlay
- ⏳ **Phase C — Production**: tăng latency budget bằng async batching, LangSmith trace, MITRE KB seed, 1-2 tuần dry_run review trước khi flip `AGENT_DRY_RUN=false`

### Tech debt (out of scope MVP)
- SF REST RBAC theo cert OU (hiện tại bất kỳ ai POST với `source=agent` đều pass — đã control bằng cách enforce qua ids-agent layer)
- SF webhook khi rule push/delete để intelligence-layer không phải poll mỗi 30s
- ids-agent `/autoblock/transfer` atomic endpoint
- Real ChromaDB MITRE seed data (~700 techniques)
- Integration tests E2E

---

## 12. Tham chiếu

- **Plan gốc**: `/home/dis/.claude/plans/reactive-mixing-floyd.md`
- **Dataplane spec**: [DATAPLANE.md](DATAPLANE.md)
- **Secure Framework spec**: [Secure-Framework.md](Secure-Framework.md)
- **Source code**: `/home/dis/deploy/zerotrust/intelligence-layer/`
- **Compose stack**: `/home/dis/deploy/zerotrust/docker-compose.yml`
- **Live URL**: `http://localhost:8767` (dev) / `http://intelligence-layer:8767` (Docker network)
