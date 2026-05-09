# Intelligence Layer — AI Security Agent

> Reactive Policy Decision Engine cho Zero Trust Microsegmentation
> **Version**: 0.5.0 — GraphRAG: Neo4j-backed KG + .md authoring + `query_kg` tool
> **Status**: ✅ Production — port 8767, `AGENT_DRY_RUN=false`, 10/10 eval PASS (2026-05-09)
> **Last updated**: 2026-05-09

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

## 3. Knowledge Architecture — GraphRAG hybrid (v0.5.0)

Knowledge sống ở **Neo4j** (durable, queryable graph) và được **hydrate vào RAM cache** ở startup.
Authoring layer là markdown files — humans edit, parser validate qua Pydantic schema, ETL push vào Neo4j.
Agent có 2 đường tiếp cận: **static prompt inject** (alert-scoped slice, instant) và
**`query_kg` tool** (live Cypher, on-demand cho cases prompt không cover).

### 3.1 Boot path

```
knowledge/infra/*.md (humans edit, git-tracked)
    │
    ▼
src/core/knowledge_parser.py    (.md YAML blocks → Pydantic validate)
    │
    ├──▶ Module-level dicts in core/*.py (BOOTSTRAP — used as fallback)
    │
    ▼
src/storage/neo4j_kg.py         (ETL: Pydantic → Neo4j MERGE, idempotent)
    │
    ▼
Neo4j  (70 nodes, 28 edges — single durable source of truth)
    │
    ▼
src/storage/neo4j_reader.py     (Cypher → Pydantic rehydrate)
    │
    ▼
main.py lifespan HOT-SWAP       (replace core/*.py module dicts in place)
    │
    ▼
core/system_model.ZONES, ASSETS, LEAFS               ◀─── Agent reads from RAM
core/baselines.ALL_BASELINES, APPLICATION_FLOWS, ...    here. Identical Python
core/threat_playbook.SID_DETECTIONS, KILL_CHAINS        API to v0.4.0; only the
core/policy.POLICY_MATRIX                                source has changed.
core/enforcement_plane.ENDPOINT_CONTRACTS, ...
core/invariants.NEVER_BLOCK_CIDRS, ...
```

After lifespan: Neo4j is the runtime source. The .md bootstrap is the cold-start
fallback (used if Neo4j is unreachable at startup). Agent code consumes the same
Pydantic objects regardless of which source populated them.

### 3.2 Authoring source — `intelligence-layer/knowledge/infra/`

Each `.md` file is hybrid: prose for humans + ` ```yaml ` fenced blocks parsed
deterministically. Pydantic validates every block before it reaches Neo4j —
typo / wrong enum / missing field aborts ETL fail-closed.

| File | Entities | Pydantic schema |
|------|----------|-----------------|
| `zones.md` | 4 trust zones | `Zone` |
| `assets.md` | 4 workload hosts | `Asset` (nested `Service`) |
| `leafs.md` | 2 SONiC leafs | `Leaf` |
| `baselines.md` | 8 traffic flows + anomaly patterns + steady-state constants | `TrafficPattern` |
| `policy-matrix.md` | 12 zone-pair verdicts | `(src, dst) → ALLOW/DENY` |
| `sids.md` | 8 Suricata signatures | `SidDetection` |
| `kill-chains.md` | 4 multi-stage adversary playbooks | `KillChain` (nested `KillChainStage`) |
| `enforcement-plane.md` | SF REST contracts, gotchas, failure modes, RBAC | mixed |
| `invariants.md` | NEVER_BLOCK CIDRs, allowed actions, comment prefixes | hard safety constants |

Workflow: edit `.md` → run `scripts/dump_pydantic_to_markdown.py` (only needed
to seed initially) and `scripts/verify_knowledge_roundtrip.py` (ensures parser
output equals reference) → restart container (lifespan ETL pushes to Neo4j +
hot-swaps RAM cache).

### 3.3 Neo4j schema (Layer 1 — current)

```
Nodes:
  (:Zone {name, cidr, leaf, vlan, svi_gateway, trust_level, criticality, purpose})
  (:Asset {ip, hostname, zone, tier, role, criticality, data_classification,
           owner_team, services_json, expected_inbound_sources,
           expected_outbound_destinations, if_compromised_impact, if_blocked_impact})
  (:Leaf {name, mgmt_ip, zones, role})
  (:Sid {sid, severity_p_level, signature_msg, production_description,
         mitre_tactic, mitre_technique, detection_logic, recommended_response,
         default_ttl_seconds, false_positive_likelihood, false_positive_scenarios})
  (:KillChain {name, production_description, typical_dwell,
               recommended_intervention, containment_strategy, stage_count})
  (:Baseline {name, src_zone, src_ip, dst_zone, dst_ip, dst_port, proto, cadence,
              expected_volume_per_hour, burst_anomaly_threshold,
              criticality_to_business, production_description, if_disrupted})
  (:NeverBlockEntry {cidr, rationale})
  (:ApiEndpoint), (:Gotcha), (:FailureMode), (:FieldMapping)
  (:KnowledgeMeta)  — singletons (baseline_constants, rbac_contract, agent_invariants)

Edges:
  (:Asset)-[:MEMBER_OF]->(:Zone)
  (:Leaf)-[:ENFORCES]->(:Zone)
  (:Zone)-[:ALLOW|DENY]->(:Zone)              — policy matrix
  (:Sid)-[:EXPECTED_IN {stage, tactic,
       indicators, false_positive_sources}]->(:KillChain)

All nodes/edges flagged with kg_managed=true so ETL can wipe + reload safely
without clobbering user-authored Cypher.
```

### 3.4 What's in the prompt vs. what's in Neo4j only

The static system prompt receives an **alert-scoped slice** (~3K tokens) — only
zones/assets/baselines/SID-detail relevant to the current `(src_ip, dst_ip, sid)`.
Anything not in that slice lives in Neo4j and is reachable only via `query_kg`.

| | In static prompt? | In Neo4j? | Notes |
|---|---|---|---|
| Architecture overview, principles | ✅ Always | — | Persona — "agent is expert" |
| Invariants (NEVER_BLOCK, allowed actions) | ✅ Always | ✅ | Hard safety, double-encoded |
| Anomalous patterns (red flags) | ✅ Always | ✅ | Detect contract |
| Zones/assets/leafs relevant to alert | ✅ Selective | ✅ Full | Other zones in Neo4j only |
| Baselines involving alert IPs | ✅ Selective | ✅ Full | Other baselines in Neo4j only |
| Triggered SID detail + short ref of others | ✅ | ✅ Full | Other SIDs full detail in Neo4j only |
| **Kill chains** | **❌ Removed** | ✅ Full | **Anti-leak** (see 3.5) |
| Multi-hop traversal | — | ✅ | `query_kg` only |
| Enforcement plane gotchas + RBAC | ✅ | ✅ | Always inject |

### 3.5 Anti-leak design — kill chains intentionally NOT in prompt

Pre-baking "SID 9000001 = stage 2 of presentation-tier-breach playbook → block at LEAF-1"
into the agent's prompt turns reasoning into pattern-matching against the test
scenario itself. The agent quotes the playbook and executes the recipe; it does
not actually reason about lateral movement.

After v0.5.0: kill chains are stored in Neo4j but **not injected** into the
prompt or pre-fetched. Agent must INFER multi-stage attacks from primitives
(baseline absence + zone trust mismatch + MITRE technique + asset criticality).
If the agent decides it genuinely needs kill-chain context (e.g., correlated
alert sequence suggests a campaign), it can call:

```cypher
MATCH (s:Sid {sid: 9000001})-[r:EXPECTED_IN]->(k:KillChain)
RETURN k.name, r.stage, r.tactic, k.containment_strategy
```

via the `query_kg` tool — this is a deliberate investigation step, not a
pre-loaded answer key.

### 3.6 Cold-start safety floor

`main.py` lifespan validates after Neo4j hot-swap that critical NEVER_BLOCK
CIDRs are present (mgt-01, IDS, all SVI gateways, mgmt OOB). Missing entries
abort startup — even if Neo4j is mutated post-deployment, the safety floor
is enforced at container boot. The list is hardcoded in lifespan code, not
data-driven, so removing it requires a code change + review.

---

## 4. Investigation Tools — pre-fetch + ReAct hybrid (v0.5.0)

Agent CHỈ có 1 action capability = push DROP rule. Investigation tools là **read-only data fetchers**. Two access modes:

### 4.1 Pre-fetched (node_gather_context, parallel, ~30ms)

Agent always receives these regardless of whether it asked.

| Tool | Source | Output | Vai trò |
|------|--------|--------|---------|
| `query_asset_neighbors(ip)` | system_model + baselines (Neo4j-hydrated dicts) | Asset profile, blast radius score, expected inbound/outbound flows, if_blocked impact | Trước block: biết hậu quả |
| `find_similar_past_incidents(sid, src_zone, dst_zone, lookback=90d)` | Postgres + pgvector — **3 strategies parallel** | Match count, outcome breakdown, last 3 decisions, pattern assessment | Học từ quá khứ — recurrence + novel-variant pattern |
| `simulate_block_impact(src_ip, dst_ip, dst_port)` | baselines (Neo4j-hydrated dicts) | Full-block vs targeted-block consequences, baseline match | Counterfactual — chọn rule scope tối thiểu |

**Kill chain match removed** — previously pre-fetched, now anti-leak (see §3.5).
Agent reaches kill chains via `query_kg` if it suspects multi-stage campaign.

### 4.2 LLM-callable via ReAct (`query_kg`, `get_alert_history`)

Agent decides at decision time whether to invoke. Wired through `chat_react`
multi-round loop in `node_decide_policy` (max 4 iterations, then forces final
structured output).

| Tool | Backend | Use case | Safety |
|------|---------|----------|--------|
| `query_kg(cypher)` | Neo4j async driver, read-only | Verify hypothesis ("does SID X appear in any kill chain?"), multi-hop traversal, find entities not in alert-scope slice | Read-only regex (rejects CREATE/DELETE/MERGE/SET/REMOVE/DROP/DETACH/FOREACH/LOAD CSV/CALL DBMS), 50-row cap, 5s timeout |
| `get_alert_history(src_ip, limit)` | Redis cache | Re-fetch IP history if pre-fetched value insufficient | Read-only |

**Tool teaching in system prompt**: explicit instructions to use `query_kg` ONLY
to verify hypotheses or fetch facts NOT in the prompt — not to re-look-up basic
zone/asset/SID facts already provided. This preserves the "expert who already
knows the system" persona while enabling deep exploration when needed.

In practice for Layer 1 (small KG, fits in alert-scoped slice): agent rarely
invokes `query_kg` — slice usually sufficient. For Phase B (Layer 2 docs),
agent will use it heavily because NIST/CIS content cannot fit prompt.

### 4.3 Multi-strategy past-incident retrieval

`find_similar_past_incidents` chạy **3 retrieval paths parallel**, gộp kết quả vào prompt. Production attacks hiếm khi giống past attacks 100% — semantic + MITRE paths catch novel variants:

| Path | Match logic | Index | Khi hữu dụng |
|------|-------------|-------|--------------|
| **Exact-SID** | `alert_sid = X AND created_at >= 90d` | `decisions_sid_created_at_idx` (btree) | Recurring threats — same signature fires lặp lại |
| **Semantic** | `embedding <-> query_vec` cosine ≥ 0.30 | `decisions_embedding_hnsw_idx` (HNSW) | Same pattern, different SID — kill-chain stage variants |
| **MITRE** | `mitre_technique = X AND alert_sid != Y` | `decisions_mitre_created_at_idx` (btree partial) | Adversary dùng same TTP qua nhiều vectors |

**Sentinel pre-flight** ([tools.py](../intelligence-layer/src/agent/tools.py#L281)): nếu `decisions` table không có row nào trong window (cold cache, eval_iid post-truncate), short-circuit cả 3 paths → save ~250ms wasted compute.

**Embedding cache** ([redis.py](../intelligence-layer/src/storage/redis.py)): `embed_text(query) → vec` deterministic; cache by `sha1(query_text)` với TTL 1h. Saves ~150-200ms CPU embed compute trên repeat queries.

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

**Tables:** `decisions` (workspace, eval-truncatable) + `decisions_history` (audit, never truncated). Schema giống nhau — agent reads from `decisions`, FE Policy History reads from `decisions_history`.

```
id, alert_sid, alert_src_ip, outcome, action, src_ip, dst_ip, dst_port,
confidence, rejection_reason, safety_checks (TEXT, JSON-encoded), reasoning (TEXT, JSON list),
hypotheses (TEXT, JSON list), rollback_plan (TEXT, JSON), rule_id, ttl_seconds, latency_ms,
created_at, dry_run, trace_id (Langfuse link),
primary_hypothesis, alternative_actions (TEXT, JSON), follow_up_actions (TEXT, JSON),
mitre_technique, mitre_tactic, reasoning_completed_at,
retrospective_outcome, retrospective_notes, labeled_at,  -- Phase 4 background labeler
embedding vector(384)                                    -- pgvector for semantic search
```

**Indexes** (auto-migrated qua `connect()` — [postgres.py](../intelligence-layer/src/storage/postgres.py#L160)):

| Index | Columns | Used by |
|-------|---------|---------|
| `decisions_pkey` | `id` (PK) | Per-decision lookup, Langfuse trace fetch |
| `decisions_embedding_hnsw_idx` | `embedding vector_cosine_ops` HNSW (m=16, ef_construction=64) | Semantic similarity search |
| `decisions_src_ip_created_at_idx` | `(alert_src_ip, created_at DESC)` | `get_ip_summary`, `get_recent_alerts_for_correlation`, `fetch_reputation` |
| `decisions_sid_created_at_idx` | `(alert_sid, created_at DESC)` | Exact-SID match in past-incident retrieval |
| `decisions_mitre_created_at_idx` | `(mitre_technique, created_at DESC) WHERE mitre_technique IS NOT NULL` | MITRE technique cross-SID retrieval (partial — saves space, ~20% rows have technique set) |
| `decisions_created_at_idx` | `(created_at DESC)` | Sentinel pre-flight count, FE Policy History pagination |

`decisions_history` mirrors all 4 btree + HNSW indexes (same workload from FE).

**Index choice rationale:**
- **HNSW** thay vì IVFFlat — không cần ANALYZE, immediate optimal post-CREATE, scale tốt 100k-1M vectors
- Composite `(filter_col, created_at DESC)` — phục vụ cả `WHERE filter = X AND created_at >= cutoff` và `ORDER BY created_at DESC` trong 1 index
- Partial MITRE index — chỉ lưu rows có technique set, giảm index size + ghi update rẻ hơn

### 7.2 Redis (logical DB tách biệt)

| DB | Purpose | Eval-flushable? | Keys |
|----|---------|-----------------|------|
| **DB 0** | Agent state | ✅ Yes — `redis-cli -n 0 FLUSHDB` | `dedup:*`, `alert_history:*`, `agent:resp_cache:*`, `decision_cache:*`, `emb:*` (embedding cache, TTL 1h) |
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
├── knowledge/                          # Authoring source for KG content
│   ├── 01-DATAPLANE.md                 # Human narrative reference
│   ├── 02-SECURE-FRAMEWORK.md
│   └── infra/                          # ★ Machine-parsable .md (parser → Pydantic → Neo4j)
│       ├── README.md
│       ├── zones.md                    # 4 trust zones
│       ├── assets.md                   # 4 workload hosts
│       ├── leafs.md                    # 2 SONiC leafs
│       ├── baselines.md                # 8 traffic flows + anomalous patterns
│       ├── policy-matrix.md            # 12 zone-pair verdicts
│       ├── sids.md                     # 8 Suricata signatures
│       ├── kill-chains.md              # 4 multi-stage adversary playbooks (Neo4j-only, NOT injected)
│       ├── enforcement-plane.md        # SF REST contract / gotchas / failure modes
│       └── invariants.md               # NEVER_BLOCK + allowed actions + comment prefixes
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
│   ├── core/                           # Knowledge layers (Neo4j-hydrated at lifespan)
│   │   ├── knowledge_parser.py         # ★ .md YAML blocks → Pydantic objects (with deferred imports for circular-dep safety)
│   │   ├── system_model.py             # ASSETS, ZONES, LEAFS — populated from parser at import, hot-swapped from Neo4j at lifespan
│   │   ├── baselines.py                # ALL_BASELINES, ANOMALOUS_PATTERNS, constants — same pattern
│   │   ├── threat_playbook.py          # SID_DETECTIONS + KILL_CHAINS — render_for_alert(sid) NO LONGER injects kill chains
│   │   ├── enforcement_plane.py        # ENDPOINT_CONTRACTS, GOTCHAS, FAILURE_MODES, RBAC — same pattern
│   │   ├── invariants.py               # NEVER_BLOCK_CIDRS + bounds — same pattern
│   │   ├── topology.py                 # NetworkX + ip_to_zone/leaf
│   │   ├── policy.py                   # POLICY_MATRIX — same pattern
│   │   ├── knowledge.py                # SID_KNOWLEDGE
│   │   ├── knowledge_loader.py         # 3-tier cache + alert-scoped render (kill_chain_match section removed)
│   │   └── kg_visualizer.py            # pyvis HTML export
│   │
│   ├── pipeline/
│   │   ├── consumer.py                 # SSE consumer + flow poller → EventsStore
│   │   ├── filters.py                  # Severity/dedup/whitelist/zone
│   │   └── gate.py                     # Filter chain orchestrator
│   │
│   ├── agent/
│   │   ├── state.py                    # AgentState TypedDict
│   │   ├── graph.py                    # 8-node pipeline + asyncio.gather fork (now accepts neo4j_driver)
│   │   ├── nodes.py                    # node_decide_policy uses chat_react when driver wired (v0.5.0)
│   │   ├── prompts.py                  # build_policy_prompt + build_reasoning_prompt + ★ KG ACCESS section teaching when to query_kg
│   │   ├── tools.py                    # POLICY_DECISION_SCHEMA + REASONING_TRACE_SCHEMA + investigation tools + ★ query_kg + execute_query_kg + TOOL_DEFINITIONS
│   │   ├── response_cache.py           # Redis-backed PolicyIntent cache
│   │   ├── llm/
│   │   │   ├── interface.py            # +chat_react abstract method
│   │   │   ├── openai_compat.py        # chat_json + JSON-mode fallback + ★ chat_react multi-round loop
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
│   │   ├── neo4j_kg.py                 # ★ Async Neo4j ETL: parser → Pydantic → Cypher MERGE (extended for Asset.services_json, anomaly patterns, FailureModes, NeverBlockEntries, etc.)
│   │   ├── neo4j_reader.py             # ★ Cypher → Pydantic rehydrator (inverse of ETL, used by main.py hot-swap)
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
    ├── benchmark_agent.py
    ├── dump_pydantic_to_markdown.py    # ★ One-shot: dumps Pydantic constants → knowledge/infra/*.md (used to seed)
    ├── verify_knowledge_roundtrip.py   # ★ Asserts parser output identical to original Pydantic
    └── verify_neo4j_roundtrip.py       # ★ Asserts ETL+Reader preserves data through Neo4j
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

#### v0.5.0 — GraphRAG: Neo4j durable KG + .md authoring + query_kg tool (CURRENT)
- **Knowledge moves from `.py` constants to `knowledge/infra/*.md`** — humans edit markdown, parser validates via Pydantic, ETL pushes to Neo4j. Module-level dicts in `core/*.py` populated from parser at import (bootstrap), hot-swapped from Neo4j at lifespan. Single durable source of truth.
- **Neo4j ETL extended** — pushes `Asset.services_json` (nested JSON), `Asset.expected_inbound/outbound_destinations`, `Asset.if_compromised_impact`, `STEADY_STATE_FLOWS_PER_MINUTE`/`MGT_AUDIT_ALERT_RATE_PER_MINUTE`, `ANOMALOUS_PATTERNS`, `KillChainStage` props (full), `FieldMapping`, `ApiEndpoint`, `Gotcha`, `FailureMode`, `NeverBlockEntry`, `KnowledgeMeta` singletons. 70 nodes / 28 edges (vs ~30 nodes pre-refactor).
- **`neo4j_reader.py`** — Cypher → Pydantic rehydrate, inverse of ETL. Drop-in replacement for `knowledge_parser.parse_all()` shape. Used by `main.py` lifespan hot-swap.
- **`query_kg(cypher)` tool** — read-only Cypher executor exposed to LLM via new `chat_react` multi-round tool-calling loop. Regex word-boundary safety rejects writes (CREATE/DELETE/MERGE/SET/REMOVE/DROP/DETACH/FOREACH/LOAD CSV/CALL DBMS), 50-row cap, 5s timeout. Wired through `node_decide_policy` when `neo4j_driver` is available; falls back to `chat_json` if ReAct loop exhausts max iterations or fails.
- **Kill chain anti-leak** — removed from agent's static prompt and from pre-fetched `kill_chain_match`. Test scenario "presentation-tier-breach-to-data-exfiltration" no longer leaks into reasoning (was previously the test answer key). Agent must INFER multi-stage from primitives or actively call `query_kg`. Reasoning shifted from playbook quoting to multi-source primitive synthesis.
- **Cold-start safety floor** — `main.py` validates after hot-swap that critical NEVER_BLOCK CIDRs (mgt-01, IDS, SVI gateways, mgmt OOB) are present. Missing entries abort startup, even if Neo4j was mutated post-deployment.
- **Eval (10 runs, dry_run=false)** — pass rate 10/10 unchanged, confidence 0.95 unchanged, agent latency avg `7385ms → 6627ms (−10%)`, max `16499ms → 10115ms (−39% tail cut)`, M1 stdev `3.31s → 1.32s (−60% variance)`.

#### v0.4.0 — V3 Schema split + Observability + EventsStore
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
