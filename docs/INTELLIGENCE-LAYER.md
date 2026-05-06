# Intelligence Layer — AI Security Agent

> Reactive Policy Decision Engine cho Zero Trust Microsegmentation
> **Version**: 0.4.0 — V3 schema split + Langfuse observability + EventsStore
> **Status**: ✅ Production — port 8767, `AGENT_DRY_RUN=false`, 10/10 eval PASS (2026-05-05)
> **Last updated**: 2026-05-05

---

## 1. Tóm tắt

`intelligence-layer` là service Python FastAPI đóng vai trò **bộ não AI** của hệ thống Zero Trust Microsegmentation. Nó subscribe alert real-time từ Suricata IDS, reasoning bằng LLM với **knowledge graph + hypothesis-driven decision**, và push DROP rule vào dataplane qua Secure Framework.

**Vị trí trong stack**:
```
Suricata IDS ──SSE──▶ ids-agent (Go) ──SSE──▶ intelligence-layer (Python, :8767)
                            │                       │
                            │                       ├──▶ Cerebras LLM (GLM-4.7 + llama3.1-8b)
                            │                       ├──▶ Redis DB 0 (agent state)
                            │                       ├──▶ Redis DB 1 (events buffer)
                            │                       ├──▶ Postgres (decisions audit)
                            │                       └──▶ Langfuse (LLM observability)
                            │                       │
                            │                       ▼ POST /rules (force source=agent)
                            └──▶ Secure Framework (:9090) ──gNMI──▶ SONIC LEAF iptables
```

**Endpoint**: `http://localhost:8767` (host) / `http://intelligence-layer:8767` (network `ztnet`)

---

## 2. Pipeline V3 — 8 nodes với Stage 1+2 parallel

```
SSE event từ ids-agent:8766/events
   ↓
[AlertGate]                  severity ≥ 2 → dedup (Redis 30s) → whitelist → zone check
   ↓ (passed)
[load_context]               build alert-scoped system prompt (~3000 tokens, V3 dynamic selection)
   ↓
[classify_alert]             LLM fast (llama3.1-8b) → benign | suspicious | threat
   ↓ (threat/suspicious)
[gather_context]             4 tasks parallel:
                              • get_alert_history (Redis)
                              • get_ip_summary (Postgres 30-day aggregate)
                              • get_recent_alerts_for_correlation (10-min window)
                              • prefetch_investigation_context:
                                  - query_asset_neighbors (blast radius)
                                  - find_similar_past_incidents (Postgres 90-day)
                                  - simulate_block_impact (counterfactual)
                                  - kill_chain_match
   ↓
[cache_lookup]               Redis response cache (60s TTL) keyed by decision-shape features
   ↓ (hit) → skip LLM, rebind src_ip → enforce
   ↓ (miss)
[policy_decision]            ★ V3 Stage 1 BLOCKING — LLM primary
                              POLICY_DECISION_SCHEMA (9 scalar fields, 0 arrays)
                              → action, src_ip, dst_ip, dst_port, protocol, priority,
                                ttl_seconds, comment, confidence
                              ~3s, parser fail rate ~0%, 3 retries on transient
   ↓
[validate_decision]          9 safety layers (L1+L3+L4+L4b+L5+L6+L7+L9+L2-semantic-entropy)
   ↓ (passed)
   ╔═══ FORK PARALLEL ═══╗
   ║                     ║
   ▼                     ▼
[enforce]            [reasoning_trace]   ★ V3 Stage 2 NON-BLOCKING — LLM primary
SF POST /api/rules    REASONING_TRACE_SCHEMA (4 arrays + 4 scalars)
  ↓                   → primary_hypothesis, hypotheses, reasoning_steps,
  Rule on LEAF          alternative_actions, rollback_plan, follow_up_actions,
                        mitre_technique, mitre_tactic
                       ~1.5-2s, fail-tolerant — decision still enforces if this fails
   ╚═════════════════════╝
   ↓
[record_decision]    Postgres `decisions` (full audit trail) + Redis cache + SSE /stream
```

**Key V3 innovation**: tách 1 LLM call (15 fields, 4 arrays — Cerebras parser fail ~5-10%) thành 2 calls — Stage 1 critical path đơn giản (parser fail ~0%), Stage 2 enrichment chạy parallel với enforce.

---

## 3. Knowledge Architecture — 5 lớp

KG render alert-scoped (chỉ phần liên quan alert hiện tại) → giảm prompt từ 5851 tokens → 2970 tokens (-49%).

| Lớp | File | Nội dung | Render |
|-----|------|----------|--------|
| **Datacenter system model** | `src/core/system_model.py` | 4 zones, 4 hosts, 2 LEAFs, criticality, services, blast radius | `render_for_alert(src_ip, dst_ip)` — chỉ zones/assets liên quan |
| **Production traffic baselines** | `src/core/baselines.py` | 8 legitimate flows (web→app proxy, app→db OLTP, mgt audit/scrape/logpull) | `render_for_alert(src_ip, dst_ip)` — chỉ baselines involve các IP này |
| **Threat playbook** | `src/core/threat_playbook.py` | 8 SID detections + 4 kill chains (presentation-tier-breach, app-tier-breach, mgt-credential-compromise, db-direct-exfil) | `render_for_alert(sid)` — full SID detail + matching kill chains |
| **Enforcement plane contract** | `src/core/enforcement_plane.py` | SF REST API, RBAC matrix (sdnc/auto OU), 6 critical gotchas, 6 failure modes | `render_summary()` — compact gotchas + invariants |
| **Network invariants** | `src/core/invariants.py` | NEVER_BLOCK CIDR list (8 entries), allowed actions, priority bounds, TTL bounds | always full inject (~500 tokens) |

**Source of truth chính** (production language, đọc được human):
- `intelligence-layer/knowledge/01-DATAPLANE.md`
- `intelligence-layer/knowledge/02-SECURE-FRAMEWORK.md`

→ Pydantic models trong `src/core/` mirror các .md docs này. Khi datacenter thay đổi: update .md trước, sync Pydantic data sau.

---

## 4. Investigation Tools (V3 — 3 tools, pre-fetched parallel)

Agent CHỈ có 1 action capability = push DROP rule. Investigation tools là **read-only data fetchers** giúp LLM hiểu context trước khi quyết định. Tất cả pre-fetched trong `node_gather_context` (~30ms parallel).

| Tool | Source | Output | Vai trò |
|------|--------|--------|---------|
| `query_asset_neighbors(ip)` | NetworkX in-mem + system_model | Asset profile, blast radius score, expected inbound/outbound flows, if_blocked impact | Trước block: biết hậu quả |
| `find_similar_past_incidents(sid, src_zone, dst_zone, lookback=90d)` | Postgres aggregation | Match count, outcome breakdown, last 5 decisions, pattern assessment | Học từ quá khứ — recurrence pattern |
| `simulate_block_impact(src_ip, dst_ip, dst_port)` | Pydantic cross-ref | Full-block vs targeted-block consequences, baseline match | Counterfactual — chọn rule scope tối thiểu |

**Kill chain match** (in-memory, tự động): match SID đến trong các kill chain stages → output trong alert context cho LLM.

---

## 5. Safety Architecture — 9-Layer Defense-in-Depth

| Layer | File | Check | Reject if |
|-------|------|-------|-----------|
| **L1 Schema** | `safety/validators.py` | Pydantic strict + forced function calling | Invalid JSON, field missing |
| **L2 Self-consistency** | `safety/consistency.py` + `safety/semantic_uncertainty.py` | N runs vote + Shannon entropy over decision shape | Action disagreement OR entropy > 1.0 OR src_ip consensus < 67% |
| **L3 Topology validators** | `safety/validators.py` | Zone exists, policy conflict (DROP on ALLOW path) | Unknown zone, conflict |
| **L4 NEVER_BLOCK** | `safety/guardrails.py` | Hardcoded CIDR whitelist (mgmt, SVI, IDS, IDS, mgt-01) | src_ip in whitelist → CRITICAL halt |
| **L4b Off-target** | `safety/validators.py` | `intent.src_ip` contains `alert.src_ip` (CIDR membership) | LLM hallucinated different IP |
| **L5 Blast radius** | `safety/rate_limiter.py` | 5 rules/min, 50 total cap, 3/IP/5min, TTL [60-3600] | Vượt rate/scope/TTL |
| **L6 Severity↔action** | `safety/validators.py` | P1/P2 → DROP, P3/P4 → log_only | P3/P4 với DROP → reject |
| **L7 Confidence gate** | `safety/confidence.py` | ≥0.85 enforce, 0.70-0.85 enforce+notify, 0.50-0.70 HOLD, <0.50 reject | Confidence < 0.70 → no enforce |
| **L8 Circuit breaker** | `safety/circuit_breaker.py` | 3-fail consecutive halt 5 min | 3 enforce errors → halt |
| **L1+ Prompt injection** | `safety/prompt_injection.py` | Pattern detector (15 regex from PINT/JailBreakBench corpus) + suspicious unicode | Sanitize signature/category before LLM sees |

**Soft tag wrapper**: alert text wrap trong `<untrusted_alert_data>...</untrusted_alert_data>` + system prompt instruct LLM treat as data. Defense-in-depth với hard pattern detector (L1+).

---

## 6. LLM Configuration

**Provider**: Cerebras (OpenAI-compatible API). Swap provider chỉ qua `.env`:

| Param | Primary (reasoning + Stage 1+2) | Fast (classify) |
|-------|--------------------------------|-----------------|
| Provider | `openai_compat` | `openai_compat` |
| Base URL | `https://api.cerebras.ai/v1` | `https://api.cerebras.ai/v1` |
| Model | `zai-glm-4.7` | `llama3.1-8b` |
| Temperature | 0.1 | 0.0 |
| Max tokens | **4096** (V3: tránh JSON truncation cho Stage 2) | 512 |
| Timeout | 10s + 3 retries | 10s |

**Robustness**:
- Per-attempt retry với exponential backoff trong consistency.py
- Fallback path: `response_format=json_object` khi `tool_choice` parser fail
- Schema split V3: Stage 1 (9 scalar) ~0% parser fail, Stage 2 (4 arrays) acceptable fail (non-blocking)

---

## 7. Storage Architecture

### 7.1 Postgres (`zerotrust` DB)

Table `decisions` — full audit trail per decision:
```
id, alert_sid, alert_src_ip, outcome, action, src_ip, dst_ip, dst_port,
confidence, rejection_reason, safety_checks (JSONB), reasoning (JSONB list),
hypotheses (JSONB list), rollback_plan (JSONB), rule_id, ttl_seconds, latency_ms,
created_at, dry_run, trace_id (Langfuse link),
primary_hypothesis, alternative_actions (JSONB), follow_up_actions (JSONB),
mitre_technique, mitre_tactic, reasoning_completed_at,
retrospective_outcome, retrospective_notes, labeled_at  -- Phase 4 background labeler
```

### 7.2 Redis (logical DB tách biệt)

| DB | Purpose | Eval-flushable? | Keys |
|----|---------|-----------------|------|
| **DB 0** | Agent state | ✅ Yes — `redis-cli -n 0 FLUSHDB` | `dedup:*`, `alert_history:*`, `agent:resp_cache:*`, `decision_cache:*` |
| **DB 1** | Events stream (NEW V3) | ❌ NO — preserved across eval | `events:violations`, `events:flows` (sorted sets, score=ts_ms) |

**EventsStore** (Redis DB 1):
- `src/storage/events_store.py` — sorted set buffer, 7-day TTL, max 100K events
- Auto-prune: inline mỗi push + hourly background coroutine
- Flow poller fallback: SSE + 5s poll `/flows` endpoint của ids-agent
- API: `GET /events?since=<iso|ms>&limit=600&kind=all|violation|flow`

### 7.3 Operational Memory + IncidentMemory

- `OperationalMemory.get_ip_summary(src_ip, 30d)` — Postgres aggregate, return outcome breakdown + retrospective accuracy + trust score
- `OperationalMemory.get_recent_alerts_for_correlation(src_ip, 10min)` — kill chain signal (single-SID / multi-stage)
- `IncidentLabeler` background coroutine (5-min interval) — label decisions ≥30min old:
  - true_positive: no recurrence within TTL
  - recurrence: alerts during active TTL → rule possibly bypassed
  - inconclusive: IDS query failed
  - Push score 1.0/0.3/0.5 vào Langfuse trace

---

## 8. Langfuse Observability

**Self-host** Langfuse v2 trong stack — port host **3001** (internal :3000), DB `langfuse` riêng trên cùng Postgres instance.

**Wired** ([src/observability/langfuse_tracer.py](../intelligence-layer/src/observability/langfuse_tracer.py)):
- Mỗi alert → 1 root trace `agent.process` với `session_id=src_ip` + tags `[severity:P1, sid:9000001]`
- 8 child spans cho 7 pipeline nodes: `load_context, classify_alert, gather_context, cache_lookup, policy_decision, validate_decision, enforce, reasoning_trace`
- 3 generations LLM events: 1 llama classify + 1 GLM Stage 1 + 1 GLM Stage 2 — full input/output + token usage + cost
- IncidentLabeler push retrospective `score=true_positive` vào trace ID

**Bootstrap auto-init** (idempotent qua env vars):
- Org: `zt-org`, Project: `zt-agent`
- Public key: `pk-lf-zt-public-2026`, Secret: `sk-lf-zt-secret-2026`
- Admin: `admin@zt.local` / `AkJ8uAipXssHBJaTQXJ4VjT3`

---

## 9. Response Cache (Redis DB 0)

`src/agent/response_cache.py` — cache PolicyIntent template để skip LLM call cho same threat shape.

**Cache key**: `sha256(sid|src_zone|dst_zone|dst_port|baseline_match|correlation_signal)` — không include raw src_ip, nên 2 attackers cùng pattern (cùng zone, cùng baseline) hit same cache.

**Rebind safety**: cache value chứa **template**, không phải target. Trên cache hit, `src_ip` được rebind từ alert thật → agent không thể block sai target due to stale cache.

**TTL**: 60s. Hit rate trong burst attack typically 30-60%, cứu 4500ms latency / hit (5000ms LLM call → 50ms cache lookup).

---

## 10. API Endpoints

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/health` | Liveness + circuit breaker + rate limiter state |
| GET | `/decisions?limit=N` | List recent decisions |
| GET | `/decisions/{id}` | Full decision incl V3 reasoning trace + `reasoning_loading` flag |
| DELETE | `/decisions/{rule_id}` | Emergency revert |
| POST | `/alerts` | Manual inject alert |
| GET | `/policy-history?limit=N` | Frontend list format |
| GET | `/stream` | SSE real-time decisions |
| **GET** | **`/events?since=&limit=&kind=`** | **EventsStore — Redis DB 1, 7-day window** |
| GET | `/events/stats` | Buffer stats (count, oldest_ms, retention) |
| GET | `/cache/stats` | Response cache hits/misses |
| POST | `/cache/reset` | Reset cache counters |
| GET | `/prompt/preview?sid=&src_ip=&dst_ip=` | Inspect alert-scoped prompt size (V3 dynamic selection) |
| **GET** | **`/kg/visualize`** | **Interactive HTML KG (pyvis, 30 nodes, 43 edges)** |
| GET | `/kg/stats` | KG node/edge counts by type |
| POST | `/admin/reset` | Reset rate limiter (eval workflow) |

---

## 11. File Structure

```
intelligence-layer/
├── knowledge/                          # Source of truth (production-language docs)
│   ├── 01-DATAPLANE.md
│   └── 02-SECURE-FRAMEWORK.md
├── pyproject.toml                      # Dependencies (no chromadb, no langgraph, no langchain)
├── Dockerfile
├── docker-compose.yml
├── .env                                # Live config
│
├── src/
│   ├── config.py                       # Pydantic Settings
│   ├── main.py                         # FastAPI lifespan + wiring
│   │
│   ├── models/                         # Pydantic types
│   │   ├── alert.py                    # SuricataAlert
│   │   ├── decision.py                 # PolicyIntent V3 + Hypothesis + RollbackPlan
│   │   ├── topology.py
│   │   └── enforcement.py
│   │
│   ├── core/                           # Knowledge layers
│   │   ├── system_model.py             # ASSETS, ZONES, LEAFS — render_for_alert()
│   │   ├── baselines.py                # LEGITIMATE_FLOWS — render_for_alert()
│   │   ├── threat_playbook.py          # SID_DETECTIONS + KILL_CHAINS — render_for_alert(sid)
│   │   ├── enforcement_plane.py        # SF contract — render_summary()
│   │   ├── invariants.py               # NEVER_BLOCK + bounds
│   │   ├── topology.py                 # NetworkX + ip_to_zone/leaf
│   │   ├── policy.py                   # POLICY_MATRIX, detect_conflict
│   │   ├── knowledge.py                # SID_KNOWLEDGE
│   │   ├── knowledge_loader.py         # 3-tier cache + alert-scoped render
│   │   └── kg_visualizer.py            # pyvis HTML export
│   │
│   ├── pipeline/
│   │   ├── consumer.py                 # SSE consumer + flow poller → EventsStore
│   │   ├── filters.py                  # Severity/dedup/whitelist/zone
│   │   └── gate.py                     # Filter chain orchestrator
│   │
│   ├── agent/
│   │   ├── state.py                    # AgentState TypedDict
│   │   ├── graph.py                    # 8-node pipeline + asyncio.gather fork
│   │   ├── nodes.py                    # node_decide_policy + node_collect_reasoning (V3)
│   │   ├── prompts.py                  # build_policy_prompt + build_reasoning_prompt
│   │   ├── tools.py                    # POLICY_DECISION_SCHEMA + REASONING_TRACE_SCHEMA + 3 investigation tools
│   │   ├── response_cache.py           # Redis-backed PolicyIntent cache
│   │   ├── llm/
│   │   │   ├── interface.py
│   │   │   ├── openai_compat.py        # chat_json + JSON-mode fallback
│   │   │   └── factory.py
│   │   └── safety/                     # 9-layer defense
│   │       ├── guardrails.py           # NEVER_BLOCK
│   │       ├── validators.py           # L1+L3+L4+L4b+L5+L6
│   │       ├── rate_limiter.py
│   │       ├── consistency.py          # Self-consistency vote
│   │       ├── semantic_uncertainty.py # Shannon entropy over decision shape (L2+)
│   │       ├── prompt_injection.py     # Pattern detector + sanitize
│   │       ├── confidence.py
│   │       └── circuit_breaker.py
│   │
│   ├── enforcement/
│   │   ├── interface.py
│   │   └── ids_agent_proxy.py          # Single backend
│   │
│   ├── storage/
│   │   ├── redis.py                    # DB 0 — agent state
│   │   ├── events_store.py             # DB 1 — traffic+violations buffer (V3)
│   │   ├── postgres.py                 # decisions audit table
│   │   ├── operational_memory.py       # 30-day aggregations
│   │   └── incident_memory.py          # Retrospective labeler
│   │
│   ├── api/
│   │   ├── routes.py                   # /health, /decisions, /events, /kg/*, /cache/*
│   │   └── schemas.py
│   │
│   └── observability/
│       ├── logging.py                  # structlog JSON
│       └── langfuse_tracer.py          # Trace + spans + generations
│
├── tests/
│   ├── unit/                           # 31 tests (filters, validators, tools, safety)
│   └── integration/
│
└── scripts/
    ├── init_db.py
    ├── load_topology.py
    └── benchmark_agent.py
```

**Total: ~50 Python source files, 31 unit tests passing.**

---

## 12. Roadmap

### Đã làm

#### v0.1.0 — MVP
- ids-agent refactor (xóa `tryAutoBlock`, thêm `POST/DELETE /rules`)
- Toàn bộ intelligence-layer Python (43 source files, 31 unit tests)
- 9-layer safety architecture (L1-L9)
- Phase A — Dataplane realism: services thật, scenario controllers
- Phase B — Frontend `/policy` page + AI Agent status bar + Agent Policy History

#### v0.2.0 — Live enforcement
- Flip `AGENT_DRY_RUN=false`
- 10/10 eval PASS validated
- Postgres decisions audit + retrospective labeling
- Idempotent rule_id (sha256 of flow tuple)
- Off-target enforcement check (L4b)
- Prompt injection detector (L1+ pattern + sanitize)

#### v0.3.0 — Knowledge + Intelligence
- 5-layer knowledge architecture (system_model, baselines, threat_playbook, enforcement_plane, invariants)
- 3 investigation tools pre-fetched parallel (asset neighbors, past incidents, block impact, kill chain match)
- Hypothesis-driven decision schema
- Operational memory (30-day Postgres aggregation)
- IncidentMemory retrospective labeler
- KG visualization (pyvis HTML, 30 nodes, 43 edges)
- Dynamic knowledge selection (alert-scoped prompt, ~49% token reduction)
- Semantic entropy L2+ (Shannon over decision-shape clusters)
- Response cache Redis (60s TTL, ~30-60% hit rate in burst)

#### v0.4.0 — V3 Schema split + Observability + EventsStore (CURRENT)
- **V3 schema split**: POLICY_DECISION_SCHEMA (Stage 1, 9 scalar) + REASONING_TRACE_SCHEMA (Stage 2, 4 arrays)
- **Parallel enforce + reasoning**: `asyncio.gather(_enforce_path, _reasoning_path)` — Stage 2 fail-tolerant
- **Cerebras 400 zero rate**: Stage 1 simple schema → 0/30 parser failures in 10-run eval
- **Langfuse v2 self-hosted**: trace per alert (8 spans + 3 generations), token cost tracking, retrospective scoring
- **EventsStore Redis DB 1**: traffic + violations buffer (7-day, max 100K), eval không touch DB 1
- **Frontend reasoning button**: 🧠 modal expand mỗi decision row, auto-poll khi Stage 2 đang load, link 📊 Trace mở Langfuse
- **Frontend theme toggle**: Dark/Light (GitHub Primer + IBM Carbon palette, severity-aware print-safe colors)
- **Eval workflow**: per-run + final cleanup, flush DB 0 only

### Backlog (v0.5.0+)
- **HITL endpoints** cho HELD decisions (confidence 0.50-0.70): `POST /decisions/{id}/approve|reject` + auto-expire
- **Per-source LLM call quota** (DoS / cost control trước AlertGate)
- **Post-enforce health check + auto-revoke** nếu connectivity probe degrade
- **Adversarial eval suite** (50+ prompt-injection corpus, hallucination IP corpus)
- **Drift canary**: golden set 50 alerts chạy daily, fail nếu output thay đổi (LLM provider model update)
- **OpenTelemetry vendor-neutral tracing** (besides Langfuse)
- **Multi-provider failover**: Z.ai trực tiếp khi Cerebras 400 (currently fully mitigated by V3, optional)

### Tech debt (out of scope MVP)
- SF REST RBAC theo cert OU
- SF webhook khi rule push/delete
- Integration tests E2E
