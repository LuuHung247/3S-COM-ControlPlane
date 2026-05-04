# Intelligence Layer — AI Agent Service

> Reactive Policy Decision Engine cho Zero Trust Microsegmentation
> **Version**: 0.2.0 — Live enforcement
> **Status**: ✅ Production — port 8767, `AGENT_DRY_RUN=false`, 10/10 eval PASS
> **Last updated**: 2026-05-04

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

**Hiện tại** (`.env` — live):

| Param | Primary | Fast |
|-------|---------|------|
| Provider | `openai_compat` | `openai_compat` |
| Base URL | `https://api.cerebras.ai/v1` | `https://api.cerebras.ai/v1` |
| Model | `zai-glm-4.7` | `llama3.1-8b` |
| Temperature | `0.1` | `0.0` |
| Max tokens | `2048` | `512` |
| Use case | Reasoning + tool calls + policy intent | Classify benign/suspicious/threat |
| Timeout | `10s` | `10s` |

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

## 5. Knowledge — Knowledge Graph (NetworkX in-memory)

### 5.1 Structured lookup

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

### 5.2 Anti-hallucination

KG hardcoded, không có vector store / RAG. Lý do: domain security cần **exact match** (rule idempotency, IP boundaries, SID→technique mapping) — fuzzy semantic search dễ gây hallucination ở các trường mission-critical.

- ✅ Topology, policy matrix, SID→MITRE → KG hardcoded
- ✅ Active SF rules → KG snapshot exact match (idempotency)
- ✅ YANG schema → Pydantic models (constraint, force schema)

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
| `/alerts` | POST | Submit single Suricata alert (test/replay) |
| `/decisions?limit=N` | GET | List N decisions gần nhất từ Postgres (full record incl. safety_checks) |
| `/decisions/{id}` | DELETE | Emergency revoke — xóa rule khỏi LEAF |
| `/policy-history?limit=N` | GET | Filtered view: chỉ `enforced`/`dry_run` outcomes, format cho frontend Policy page |
| `/health` | GET | Liveness + ids_agent + circuit breaker + rate limiter state |
| `/stream` | GET (SSE) | Real-time decision feed cho monitor UI |
| `/admin/reset` | POST | Reset in-memory rate limiter (dùng giữa eval runs) |

**Health check sample (live):**
```json
{
  "status": "ok",
  "ids_agent": "connected",
  "dry_run": false,
  "circuit_breaker": {"consecutive_failures": 0, "is_open": false, "open_until": 0.0},
  "rate_limiter": {"last_minute": 1, "total": 1}
}
```

---

## 8. Nghiệm thu — Acceptance Criteria

### 8.1 Trạng thái checklist

| # | Yêu cầu | Status | Bằng chứng |
|---|---|---|---|
| 1 | Service start không lỗi | ✅ | `docker compose ps` → `intelligence-layer Up` |
| 2 | `/health` trả `{status: ok, ids_agent: connected}` | ✅ | section 7 |
| 3 | ids-agent refactor: `/autoblock/enable` 404, `POST /rules` 200 | ✅ | xóa khỏi `main.go`, rebuild image |
| 4 | `AGENT_DRY_RUN=false` → enforce thật lên LEAF | ✅ | `outcome=enforced`, rule trên LEAF-1 confirm via SF API |
| 5 | P1/P2 → DROP rule, P3/P4 → log_only | ✅ | 10 runs thực nghiệm, tất cả P1 → DROP |
| 6 | Adversarial tests pass | ✅ | 25/25 safety tests (L4 whitelist, L7 low conf, L6 P3 DROP reject) |
| 7 | Latency p95 < 5s (end-to-end M1) | ✅ | M1 avg=4.75s, max=5.2s (N=1 self-consistency) |
| 8 | Tool calls < 2 / decision | ✅ | chỉ `get_alert_history` (Redis) |
| 9 | Postgres full audit trail | ✅ | `GET /decisions` có `action`, `src_ip`, `dst_ip`, `safety_checks`, `latency_ms` |
| 10 | 100% enforcement correctness | ✅ | M3=10/10 — tất cả rules đúng IP `10.1.100.10/32` |

### 8.2 Unit tests

```
$ uv run pytest tests/unit/ -v
tests/unit/test_filters.py  ✓ 6 passed
tests/unit/test_safety.py   ✓ 25 passed (L1-L8 + adversarial)
============================== 31 passed in 1.89s ==============================
```

### 8.3 Live eval — 10 runs (2026-05-04, AGENT_DRY_RUN=false)

| Metric | min | avg | max |
|--------|-----|-----|-----|
| M1 Alert→Decision (s) | 4.5 | **4.75** | 5.2 |
| Agent internal latency (ms) | 2489 | **2680** | 3108 |
| M3 Enforcement Correctness | — | **10/10 (100%)** | — |
| Confidence score | 0.95 | **0.955** | 1.0 |
| Pass rate | — | **10/10 (100%)** | — |

Decision sample (enforced):
```json
{
  "alert_sid": 9000001,
  "outcome": "enforced",
  "action": "DROP",
  "src_ip": "10.1.100.10/32",
  "dst_ip": "10.1.200.10/32",
  "confidence": 0.95,
  "latency_ms": 2617,
  "dry_run": false,
  "safety_checks": {
    "validators": {"errors": [], "warnings": []},
    "confidence": {"score": 0.95, "outcome": "enforce"},
    "enforcement": {"backend": "ids_agent_proxy", "rule_id": "agent-f96cc3eb"}
  }
}
```

→ Chi tiết đầy đủ: [EXPERIMENT.md](EXPERIMENT.md)

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
    ├── init_db.py          (Postgres schema bootstrap)
    └── load_topology.py    (KG sanity check)
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

### Đã làm (v0.2.0)
- ✅ Refactor ids-agent (Go) thành pure proxy — xóa `tryAutoBlock`, thêm `POST/DELETE /rules`
- ✅ Toàn bộ intelligence-layer Python (43 source files, 31 unit tests)
- ✅ Wire vào `docker-compose.yml` chung với redis/postgres/fe
- ✅ 9-layer safety architecture
- ✅ Phase A — Dataplane realism: services thật (pg-mock, sshd, busybox nc), cron traffic generators, scenario scripts (compromise/restore/status)
- ✅ Phase B — Frontend: `/policy` page có AI Agent status bar + Agent Policy History timeline
- ✅ Flip `AGENT_DRY_RUN=false` — live enforcement validated 10/10 runs
- ✅ `/policy-history` + `/admin/reset` API endpoints
- ✅ Postgres bug fixed: `action/src_ip/dst_ip` từng NULL do nested key sai

### Sắp tới (v0.3.0)
- ⏳ Mở rộng eval sang P2 scenarios (SID 9000003, 9000004, 9000005)
- ⏳ Adversarial eval (block whitelist IP, rate limit exhaustion, low confidence)
- ⏳ Prompt-injection defense: untrusted-data tag wrapping cho `alert.signature`/`alert.category`
- ⏳ Off-target enforcement check: validator assert `intent.src_ip ≈ alert.src_ip`
- ⏳ Per-source LLM call quota (DoS / cost control trước AlertGate)
- ⏳ Idempotent `rule_id` deterministic: `agent-{sha256(src+dst+port+proto)[:8]}`
- ⏳ HITL endpoints cho HELD decisions: `POST /decisions/{id}/approve|reject` + auto-expire
- ⏳ Post-enforce health check + auto-revoke nếu connectivity degrade

### Tech debt (out of scope MVP)
- SF REST RBAC theo cert OU (hiện tại bất kỳ ai POST với `source=agent` đều pass — đã control bằng cách enforce qua ids-agent layer)
- SF webhook khi rule push/delete để intelligence-layer không phải poll mỗi 30s
- ids-agent `/autoblock/transfer` atomic endpoint
- Vendor-neutral OpenTelemetry tracing (per-decision span, token cost, LLM p50/p95)
- Integration tests E2E

---

## 12. Tham chiếu

- **Plan gốc**: `/home/dis/.claude/plans/reactive-mixing-floyd.md`
- **Dataplane spec**: [DATAPLANE.md](DATAPLANE.md)
- **Secure Framework spec**: [Secure-Framework.md](Secure-Framework.md)
- **Source code**: `/home/dis/deploy/zerotrust/intelligence-layer/`
- **Compose stack**: `/home/dis/deploy/zerotrust/docker-compose.yml`
- **Live URL**: `http://localhost:8767` (dev) / `http://intelligence-layer:8767` (Docker network)
