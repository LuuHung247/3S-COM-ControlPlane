# Ports & UIs — Map Toàn Hệ Thống

> Last verified: 2026-05-06 (V3 + Asset Reputation + pgvector multi-strategy + decisions_history dual-write)

Ghi nhanh tất cả services, ports, URLs để tra cứu khi cần. Stack chạy bằng
`docker compose` từ `/home/dis/deploy/zerotrust/`.

---

## 1. UIs có thể mở browser

| URL | Service | Mục đích | Auth |
|-----|---------|----------|------|
| **http://localhost:3000** | **fe (Next.js)** | Frontend dashboard — Live Monitor, Policy page với 🧠 Reasoning button, Topology, Rules | none |
| http://localhost:3000/monitor | fe → ids-agent SSE + Redis DB 1 | Real-time alerts + flows, server-side buffer 7 ngày, theme toggle Dark/Light | none |
| http://localhost:3000/policy | fe → SF + intel | Active rules, manual block, **Agent Policy History với Reasoning modal** | none |
| http://localhost:3000/topology | fe | Network topology view | none |
| **http://localhost:3001** | **Langfuse v2** | LLM observability — trace tree per alert, token cost, prompt+completion, retrospective scores | login |
| **http://localhost:8767/kg/visualize** | intelligence-layer | Knowledge Graph interactive HTML — 30 nodes (zones, assets, leafs, SIDs, kill chains, baselines), 43 edges | none |
| http://localhost:8767/docs | intelligence-layer | FastAPI auto-generated Swagger UI | none |
| http://localhost:8767/redoc | intelligence-layer | FastAPI ReDoc | none |
| **http://localhost:8080** | **Adminer** (standalone) | Postgres web UI — browse `decisions_history`, run SQL, debug pgvector | login (ztuser/ztpass) |
| **http://localhost:5540** | **RedisInsight** (standalone) | Redis web UI — DB 0 (workspace) + DB 1 (events buffer) | none |

**Langfuse credentials**:
- Email: `admin@zt.local`
- Password: `AkJ8uAipXssHBJaTQXJ4VjT3`
- Project: `Intelligence Layer` (zt-agent)
- API keys (in `.env`):
  - Public: `pk-lf-zt-public-2026`
  - Secret: `sk-lf-zt-secret-2026`

---

## 2. Container Map (docker compose stack)

| Container | Image | Host port | Internal port | Vai trò |
|-----------|-------|-----------|---------------|---------|
| `fe` | fe:latest | **3000** | 3000 | Next.js frontend với theme toggle Dark/Light |
| `intelligence-layer` | intelligence-layer:latest | **8767** | 8767 | AI agent FastAPI (V3 pipeline) |
| `ids-agent` | ids-agent:latest | **8766** | 8766 | Go SSE bridge + SF proxy |
| `zt-langfuse` | langfuse/langfuse:2 | **3001** | 3000 | Langfuse v2 web UI + API |
| `zt-postgres` | pgvector/pgvector:pg16 | **5432** (LAN-exposed) | 5432 | DB `zerotrust` (decisions + decisions_history with pgvector embeddings) + DB `langfuse` |
| `zt-redis` | redis:7-alpine | **6379** (LAN-exposed) | 6379 | DB 0 = agent state, DB 1 = events buffer |

Network: `ztnet` bridge. Inter-container DNS qua container name.

### Redis logical DB separation (V3)

| DB | Purpose | Eval-flushable? | Keys |
|----|---------|-----------------|------|
| **DB 0** | Agent state | ✅ Yes — `redis-cli -n 0 FLUSHDB` | `dedup:*`, `alert_history:*`, `agent:resp_cache:*`, `decision_cache:*` |
| **DB 1** | EventsStore (V3) | ❌ NO — preserved | `events:violations`, `events:flows` (sorted sets, score=ts_ms, 7-day TTL, max 100K) |

---

## 3. External services (không nằm trong docker compose)

| Endpoint | Service | Vai trò |
|----------|---------|---------|
| http://10.10.6.238:8765 | Suricata IDS REST API | Alert source (`/alerts`, `/stream`, `/health`) — chạy trong Suricata VM trên GNS3VM |
| http://10.10.6.238:9090 | Secure Framework REST | Enforcement (`POST /api/rules`) — container `nos-sf` trên gns3vm |
| 10.10.6.238:6513 | SF NETCONF/TLS | ONAP SDNC path (không dùng trong intel) |
| 10.10.6.238:9339 | gNMI mTLS (SF→LEAF) | Internal, không expose ra agent |
| 192.168.122.20 / .21 | LEAF-1 / LEAF-2 mgmt | nos-acl-bridge gNMI :9339, không trực tiếp |
| Suricata IDS console | telnet `112.137.129.232:5018` | GNS3 console (debugging) |
| Alpine console (WEB/DB/APP/MGT) | telnet `:5008/5011/5014/5016` | GNS3 console (scenario triggers) |

---

## 4. Intelligence-Layer API endpoints (port 8767)

### Health & decisions

| Method | Path | Mục đích |
|--------|------|----------|
| GET | `/health` | Liveness + circuit breaker + rate limiter state |
| GET | `/decisions?limit=N` | List recent decisions (Postgres) |
| **GET** | **`/decisions/{id}`** | **Full decision incl V3 reasoning trace + `reasoning_loading` flag — backing for frontend 🧠 modal** |
| DELETE | `/decisions/{rule_id}` | Emergency revert |
| POST | `/alerts` | Inject manual alert (testing) |
| GET | `/policy-history?limit=N` | Frontend list format |
| GET | `/stream` | SSE stream of new decisions (real-time) |

### Events buffer (V3 — Redis DB 1)

| Method | Path | Mục đích |
|--------|------|----------|
| **GET** | **`/events?since=&limit=&kind=`** | **Frontend Monitor hydration — Redis DB 1, 7-day window. Eval flush DB 0 KHÔNG ảnh hưởng.** |
| GET | `/events/stats` | Buffer stats (count, oldest_ms, retention) |

### Knowledge & cache observability

| Method | Path | Mục đích |
|--------|------|----------|
| **GET** | **`/kg/visualize`** | **Interactive HTML — KG graph (pyvis, 30 nodes, 43 edges)** |
| GET | `/kg/stats` | KG node/edge counts by type |
| GET | `/prompt/preview?sid=&src_ip=&dst_ip=` | So sánh full vs alert-scoped prompt size (V3 dynamic selection) |
| GET | `/cache/stats` | Response cache hits/misses/hit_rate |
| POST | `/cache/reset` | Reset cache counters (entries auto-expire by TTL) |

### Admin

| Method | Path | Mục đích |
|--------|------|----------|
| POST | `/admin/reset` | Reset rate limiter (eval workflow) |

---

## 5. Frontend → Backend proxy routes (Next.js API)

| Frontend route | Proxies to |
|----------------|-----------|
| `/api/ids/health` | `http://ids-agent:8766/health` |
| `/api/ids/alerts` | `http://ids-agent:8766/alerts` (Suricata transient API — fallback) |
| `/api/ids/flows` | `http://ids-agent:8766/flows` (Suricata transient API — fallback) |
| `/api/ids/stream` | `http://ids-agent:8766/events` (SSE) |
| `/api/ids/rules` | `http://ids-agent:8766/rules` (proxy SF list/POST/DELETE) |
| `/api/ids/autoblock` | `http://ids-agent:8766/autoblock` (manual block button) |
| `/api/intel/health` | `http://intelligence-layer:8767/health` |
| `/api/intel/decisions` | `http://intelligence-layer:8767/policy-history?limit=50` |
| **`/api/intel/decisions/[id]`** | **`http://intelligence-layer:8767/decisions/{id}` — Reasoning modal** |
| **`/api/intel/events`** | **`http://intelligence-layer:8767/events` — Monitor hydration** |

---

## 6. Direct DB / Cache access — Web UIs (debug & inspection)

**Web UI ngay trên server** — chỉ cần mở browser, không cài client local, không SSH tunnel. 2 service standalone (KHÔNG nằm trong `docker-compose.yml`, chạy riêng để khỏi nặng stack chính):

| URL | UI | DB nó connect tới |
|-----|----|--------------------|
| **http://10.10.6.231:8080** | Adminer (PostgreSQL) | `postgres:5432` (qua docker network) |
| **http://10.10.6.231:5540** | RedisInsight | `redis:6379` (qua docker network) |

> Public truy cập: dùng VS Code port forward 8080 + 5540, hoặc SSH tunnel cổng 2231 nếu cần.

### Adminer (Postgres) — http://10.10.6.231:8080

Form login (đã pre-fill server):

| Field | Value |
|-------|-------|
| System | PostgreSQL |
| Server | `postgres` (đã pre-fill) |
| Username | `ztuser` |
| Password | `ztpass` |
| Database | `zerotrust` (hoặc `langfuse` để xem internal Langfuse data) |

→ Click **Login**. Browse tables → click `decisions_history` → "Select data" → xem rows ngay. Có thể chạy SQL custom ở tab "SQL command".

### RedisInsight — http://10.10.6.231:5540

Lần đầu mở:
1. Click **Add Redis database**
2. Form:
   - Host: `redis`
   - Port: `6379`
   - Database alias: `Zero Trust Agent`
   - (no username/password)
3. Click **Add Redis Database**

Sau khi add → Browser tab → cây keys hiển thị trực quan. Switch DB 0 ↔ 1 ở dropdown trên cùng để chuyển workspace ↔ events buffer.

### Lifecycle — start/stop khi cần

```bash
# Start (1 lần là đủ, restart unless-stopped tự dậy theo server)
docker run -d --name zt-adminer --restart unless-stopped \
  --network zerotrust_ztnet -p 8080:8080 \
  -e ADMINER_DEFAULT_SERVER=postgres -e ADMINER_DESIGN=dracula \
  adminer:latest

docker run -d --name zt-redisinsight --restart unless-stopped \
  --network zerotrust_ztnet -p 5540:5540 \
  -v zt_redisinsight:/data \
  redis/redisinsight:latest

# Stop khi không debug nữa
docker stop zt-adminer zt-redisinsight

# Xóa hẳn (data cấu hình RedisInsight ở volume zt_redisinsight)
docker rm -f zt-adminer zt-redisinsight
```

---

### Postgres connection details (cho người không dùng web UI)

| Field | Value |
|-------|-------|
| Host (LAN) | `10.10.6.231` |
| Host (qua VS Code/SSH forward) | `127.0.0.1` |
| Port | `5432` |
| Database | `zerotrust` (chính) hoặc `langfuse` (Langfuse internal) |
| User | `ztuser` |
| Password | `ztpass` |
| Extensions | `vector` (pgvector) |

**Tables quan trọng**:
| Table | Workspace? | Vai trò |
|-------|-----------|---------|
| `decisions` | ✅ Workspace — eval truncates | Agent reads (reputation, past-incident, ops memory). Wiped per eval run. |
| `decisions_history` | ❌ Audit — never truncated | FE Policy History reads from here. Preserves full audit forever. |

**Cột chính trong `decisions`/`decisions_history`** (1:1 schema):
- `id` (UUID), `created_at`, `alert_sid`, `alert_src_ip`
- `outcome` (`enforced`/`dry_run`/`rejected`/`held`), `action`, `confidence`, `latency_ms`
- `reasoning` (JSON list), `primary_hypothesis`, `hypotheses` (JSON), `mitre_technique`
- `retrospective_outcome` (`true_positive`/`false_positive`/`recurrence`/`inconclusive`) — set bởi IncidentLabeler
- `embedding` (`vector(384)`) — pgvector, set bởi embed-on-write background task
- `trace_id` — link tới Langfuse trace

**Useful queries cho debug**:
```sql
-- Recent decisions tổng quan
SELECT id, alert_sid, alert_src_ip, outcome, confidence, latency_ms,
       reasoning_completed_at, retrospective_outcome
FROM decisions_history
ORDER BY created_at DESC LIMIT 20;

-- Workspace size vs history (xem eval truncate ảnh hưởng đúng không)
SELECT 'decisions' AS tbl, COUNT(*) AS rows, COUNT(embedding) AS with_emb
FROM decisions
UNION ALL
SELECT 'decisions_history', COUNT(*), COUNT(embedding)
FROM decisions_history;

-- Per-IP retrospective label breakdown (asset reputation source)
SELECT alert_src_ip, retrospective_outcome, COUNT(*) AS n
FROM decisions
WHERE created_at >= NOW() - INTERVAL '1 hour'
  AND retrospective_outcome IS NOT NULL
GROUP BY alert_src_ip, retrospective_outcome
ORDER BY alert_src_ip, retrospective_outcome;

-- Test pgvector cosine search (cần vector literal)
SELECT id, alert_sid, primary_hypothesis,
       1 - (embedding <=> (SELECT embedding FROM decisions WHERE id = '<some-id>')) AS similarity
FROM decisions
WHERE embedding IS NOT NULL
ORDER BY embedding <=> (SELECT embedding FROM decisions WHERE id = '<some-id>') ASC
LIMIT 5;

-- Reasoning trace cho 1 decision (FE Reasoning modal source)
SELECT primary_hypothesis, reasoning, hypotheses, mitre_technique, mitre_tactic,
       follow_up_actions, alternative_actions
FROM decisions_history
WHERE id = '<decision-id>';

-- Langfuse internal DB — link decisions với trace_id
SELECT d.id, d.alert_src_ip, d.trace_id
FROM decisions_history d
WHERE d.trace_id IS NOT NULL
ORDER BY d.created_at DESC LIMIT 10;
```

### Redis connection details (cho người không dùng web UI)

| Field | Value |
|-------|-------|
| Host (LAN) | `10.10.6.231` |
| Host (qua VS Code/SSH forward) | `127.0.0.1` |
| Port | `6379` |
| Auth | **none** (lab only — KHÔNG dùng cấu hình này cho production) |
| Databases | DB 0 (agent state, eval-flushable) · DB 1 (EventsStore, preserved 7d) |

**Useful keys cho debug**:
```bash
# DB 0 — agent state (workspace, eval flushes)
redis-cli -n 0 KEYS "alert_history:*"          # per-IP recent alert ring buffer
redis-cli -n 0 KEYS "agent:resp_cache:*"       # response cache (V3 cache hits)
redis-cli -n 0 KEYS "dedup:*"                  # de-dup keys (30s TTL)
redis-cli -n 0 GET "agent:rate:per_ip:10.1.100.10"   # rate limiter counter

# DB 1 — EventsStore (preserved 7 days, eval KHÔNG flush mặc định cho FE)
redis-cli -n 1 ZCARD events:violations         # số sự kiện violation
redis-cli -n 1 ZCARD events:flows              # số flow events
redis-cli -n 1 ZRANGE events:violations -5 -1 WITHSCORES   # 5 events mới nhất
redis-cli -n 1 ZREVRANGEBYSCORE events:violations +inf -inf LIMIT 0 10
```

### Langfuse Postgres (cùng container, DB khác)

Langfuse v2 share `zt-postgres` container nhưng dùng database `langfuse` riêng. Mở Adminer login với Database = `langfuse` thay vì `zerotrust`.

Các bảng lớn: `traces`, `observations`, `scores`. Thường ít cần query trực tiếp — dùng UI ở port 3001 thoải mái hơn.

### Khi nào dùng cái nào

| Nhu cầu | Tool |
|---------|------|
| Xem decision history, reasoning trace, retrospective label | Adminer → table `decisions_history` |
| Test pgvector semantic search / chạy SQL ad-hoc | Adminer → SQL command tab |
| Xem rate-limit counter, response cache hit rate | RedisInsight → DB 0 |
| Inspect EventsStore size, oldest event | RedisInsight → DB 1 |
| LLM trace per alert, prompts, costs | Langfuse UI (`http://localhost:3001`) |
| Decision-level audit (FE-friendly) | `/policy` page → 💡 Reasoning modal |

---

## 7. Quick health check (verify toàn stack)

```bash
# Frontend
curl -sI http://localhost:3000 | head -1

# Intelligence layer
curl -s http://localhost:8767/health

# Langfuse
curl -s http://localhost:3001/api/public/health

# IDS agent
curl -s http://localhost:8766/health

# Suricata IDS (qua GNS3VM NAT)
curl -s http://10.10.6.238:8765/health

# Secure Framework
curl -s http://10.10.6.238:9090/health

# Redis DB separation
docker exec zt-redis redis-cli -n 0 DBSIZE   # agent state
docker exec zt-redis redis-cli -n 1 DBSIZE   # events buffer

# EventsStore
curl -s http://localhost:8767/events/stats
```

---

## 8. Các UI chính cần biết khi vận hành

### Frontend (`fe`) — http://localhost:3000

**Pages**:
- `/dashboard` — system status overview
- `/monitor` — real-time alerts + flows feed (SSE), **theme toggle Dark/Light**, **auto-follow toggle**, server buffer Redis DB 1 (F5 không mất data)
- `/policy` — Active Rules table + Agent Policy History với **🧠 Reasoning button** mỗi row → modal full hypothesis + reasoning + alternatives + rollback + follow-up + MITRE
- `/topology` — network topology view
- `/rules` — ZT baseline + agent rules

**Theme toggle**: nút `☀ Light` / `🌙 Dark` ở navbar (cả desktop + mobile). Persist `localStorage.zt-theme`. Light mode dùng GitHub Primer + IBM Carbon palette — print-safe cho thesis screenshot.

### Langfuse — http://localhost:3001

**Quan trọng cho debug agent**. Mở khi:
- Muốn xem agent đã reason gì cho 1 alert cụ thể (full prompt + completion)
- Đo cost LLM (token usage, $ ước tính theo Cerebras pricing)
- Xem latency breakdown từng node trong V3 pipeline
- Filter traces theo `session_id` (= src_ip) → thấy attacker pattern theo thời gian
- Filter theo tags `severity:P1`, `sid:9000001`
- Xem retrospective score (true_positive/false_positive/recurrence) từ IncidentLabeler

**Trace tree per alert** (V3):
```
agent.process (root, session_id=src_ip, tags=[severity:P1, sid:9000001])
├── span: load_context
├── span: classify_alert
│    └── generation: llm.chat (llama3.1-8b, ~3540 in / 2 out tokens)
├── span: gather_context
├── span: cache_lookup
├── span: policy_decision         ← Stage 1
│    └── generation: llm.chat (zai-glm-4.7, ~5400 in / 600 out)
├── span: validate_decision
├── span: enforce                  ← parallel với reasoning_trace
└── span: reasoning_trace          ← Stage 2
     └── generation: llm.chat (zai-glm-4.7, ~5400 in / 1500 out)
```

### KG Visualizer — http://localhost:8767/kg/visualize

Mở khi:
- Muốn hiểu agent "đang biết những gì"
- Verify knowledge sau khi update `src/core/system_model.py` / `baselines.py` / `threat_playbook.py`
- Dạy/demo cho người mới về kiến trúc ZT

Interactive: drag-drop, click node → properties popup.

### FastAPI Swagger — http://localhost:8767/docs

Mở khi:
- Cần test endpoint manually (POST /alerts, GET /events with params, GET /decisions/{id})
- Inspect schema của API responses
- Tra cứu params

### Prompt Preview — http://localhost:8767/prompt/preview

Mở khi muốn xem **agent thực sự thấy gì** khi nhận 1 alert. Compare full vs alert-scoped để đo tokens reduction (V3 dynamic selection ~49%).

Example: `http://localhost:8767/prompt/preview?sid=9000001&src_ip=10.1.100.10&dst_ip=10.1.200.10`

---

## 9. Nếu service không reach được

| Triệu chứng | Kiểm tra |
|-------------|----------|
| `localhost:3000` 502/refused | `docker compose ps fe` — restart `docker compose up -d fe` |
| `localhost:8767` refused | `docker compose logs intelligence-layer --tail 30` |
| `localhost:3001` 502 | Langfuse boot mất 30-60s. `docker compose logs langfuse --tail 30`. Ensure DB `langfuse` exists in postgres |
| Trace không xuất hiện trong Langfuse | Check `LANGFUSE_*` env trong intelligence-layer container, restart |
| KG visualize 500 | Check pyvis dependency, rebuild image |
| `10.10.6.238:8765` timeout | Suricata VM trong GNS3 chưa start, hoặc libvirt NAT down |
| `10.10.6.238:9090` refused | SF container `nos-sf` trên gns3vm — `ssh dis@10.10.6.238 docker restart nos-sf` |
| Frontend Monitor F5 thấy "Loading" lâu | Check `/api/intel/events` — Redis DB 1 events buffer; fallback Suricata transient API |
| Reasoning modal "loading reasoning..." không kết thúc | Stage 2 LLM call timeout — check `docker logs intelligence-layer | grep reasoning_trace_failed` |
| Eval bỏ FLUSHDB tất cả Redis | Đảm bảo eval scripts truncate **chỉ** `decisions` (workspace), KHÔNG đụng `decisions_history`. Verify `grep TRUNCATE experiments/eval_*.py` |
| DBeaver `connection refused` 5432 | `docker compose ps postgres` — verify `Up`. Sau đó `docker compose down && docker compose up -d` để apply port mapping mới (nếu mới expose) |
| RedisInsight `connection refused` 6379 | Cùng cách — verify `docker compose ps redis`, restart nếu cần |
| FE Policy History trống sau eval | Kiểm tra dual-write: `psql ... "SELECT COUNT(*) FROM decisions_history"` — nếu 0 thì save_decision không ghi history. Check intel-layer logs cho exception trong `save_decision` |
| Decision có trong `decisions_history` nhưng KHÔNG có embedding | Embed-on-write fail. Check `docker logs intelligence-layer | grep embed_failed`. Verify pgvector extension: `psql ... "SELECT extname FROM pg_extension WHERE extname='vector'"` |
