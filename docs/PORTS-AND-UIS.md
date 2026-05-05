# Ports & UIs — Map Toàn Hệ Thống

> Last verified: 2026-05-05

Ghi nhanh tất cả services, ports, URLs để tra cứu khi cần. Stack chạy bằng
`docker compose` từ `/home/dis/deploy/zerotrust/`.

---

## 1. UIs có thể mở browser

| URL | Service | Mục đích | Auth |
|-----|---------|----------|------|
| http://localhost:3000 | **fe** (Next.js) | Frontend dashboard — Live Monitor, Policy page, AI Agent status, Agent Policy History | none |
| http://localhost:3000/monitor | fe → ids-agent SSE | Real-time Suricata alerts | none |
| http://localhost:3000/policy | fe → SF + intel | Active rules, manual block, Agent decisions timeline | none |
| **http://localhost:3001** | **Langfuse** | LLM observability — trace tree per alert, token cost, prompt+completion, retrospective scores | login |
| **http://localhost:8767/kg/visualize** | intelligence-layer | Knowledge Graph interactive HTML — zones, assets, SIDs, kill chains, baselines, edges | none |
| http://localhost:8767/docs | intelligence-layer | FastAPI auto-generated Swagger UI | none |
| http://localhost:8767/redoc | intelligence-layer | FastAPI ReDoc | none |

**Langfuse credentials**:
- Email: `admin@zt.local`
- Password: `AkJ8uAipXssHBJaTQXJ4VjT3`
- Project: `Intelligence Layer` (zt-agent)

---

## 2. Container Map (docker compose stack)

| Container | Image | Host port | Internal port | Vai trò |
|-----------|-------|-----------|---------------|---------|
| `fe` | fe:latest | **3000** | 3000 | Next.js frontend |
| `intelligence-layer` | intelligence-layer:latest | **8767** | 8767 | AI agent FastAPI |
| `ids-agent` | ids-agent:latest | **8766** | 8766 | Go SSE bridge + SF proxy |
| `zt-langfuse` | langfuse/langfuse:2 | **3001** | 3000 | Langfuse v2 web UI + API |
| `zt-postgres` | postgres:16-alpine | (internal only) | 5432 | DB cho intel + langfuse |
| `zt-redis` | redis:7-alpine | (internal only) | 6379 | Cache + dedup |

Network: `ztnet` bridge. Inter-container DNS qua container name.

---

## 3. External services (không nằm trong docker compose)

| Endpoint | Service | Vai trò |
|----------|---------|---------|
| http://10.10.6.238:8765 | Suricata IDS REST API | Alert source (`/alerts`, `/stream`, `/health`) — chạy trong Suricata VM trên GNS3VM |
| http://10.10.6.238:9090 | Secure Framework REST | Enforcement (POST /api/rules) — container `nos-sf` trên gns3vm |
| 10.10.6.238:6513 | SF NETCONF/TLS | ONAP SDNC path (không dùng trong intel) |
| 10.10.6.238:9339 | gNMI mTLS (SF→LEAF) | Internal, không expose ra agent |
| 192.168.122.20 / .21 | LEAF-1 / LEAF-2 mgmt | nos-acl-bridge gNMI :9339, không trực tiếp |

---

## 4. Intelligence-Layer API endpoints (port 8767)

### Health & decisions

| Method | Path | Mục đích |
|--------|------|----------|
| GET | `/health` | Liveness + circuit breaker + rate limiter state |
| GET | `/decisions` | List recent decisions (`?limit=N`) |
| GET | `/decisions/{id}` | Single decision detail |
| POST | `/alerts` | Inject manual alert (testing) |
| GET | `/stream` | SSE stream of new decisions (real-time) |
| GET | `/policy-history` | Frontend timeline format |

### Knowledge & cache observability

| Method | Path | Mục đích |
|--------|------|----------|
| **GET** | **`/kg/visualize`** | **Interactive HTML — KG graph** |
| GET | `/kg/stats` | KG node/edge counts by type |
| **GET** | **`/prompt/preview?sid=&src_ip=&dst_ip=`** | **So sánh full vs alert-scoped prompt size** |
| GET | `/cache/stats` | Response cache hits/misses/hit_rate |
| POST | `/cache/reset` | Reset cache counters (entries auto-expire by TTL) |

### Admin

| Method | Path | Mục đích |
|--------|------|----------|
| POST | `/admin/reset` | Reset rate limiter (eval workflow) |

---

## 5. Quick health check (verify toàn stack)

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
```

---

## 6. Các UI chính cần biết tới khi vận hành

### Frontend (fe) — http://localhost:3000
Dùng hằng ngày. Live monitor + policy management. Đây là cái user/ops sẽ tương tác.

### Langfuse — http://localhost:3001
**Quan trọng cho debug agent**. Mở khi:
- Muốn xem agent đã reason gì cho 1 alert cụ thể
- Đo cost LLM (token usage, $ ước tính)
- Xem latency breakdown từng node trong pipeline
- Filter traces theo session_id (= src_ip) → thấy attacker pattern theo thời gian
- Filter theo tags `severity:P1`, `sid:9000001`
- Xem retrospective score (true_positive/false_positive) để đánh giá quality agent

### KG Visualizer — http://localhost:8767/kg/visualize
Mở khi:
- Muốn hiểu agent "đang biết những gì"
- Verify knowledge sau khi update `core/system_model.py` / `baselines.py` / `threat_playbook.py`
- Dạy/demo cho người mới về kiến trúc ZT

### FastAPI Swagger — http://localhost:8767/docs
Mở khi:
- Cần test endpoint manually
- Inspect schema của API responses
- Tra cứu params

### Prompt Preview — http://localhost:8767/prompt/preview
Mở khi muốn xem **agent thực sự thấy gì** khi nhận 1 alert. So sánh full vs alert-scoped để đo tokens reduction.

---

## 7. Nếu service không reach được

| Triệu chứng | Kiểm tra |
|-------------|----------|
| `localhost:3000` 502/refused | `docker compose ps fe` — restart `docker compose up -d fe` |
| `localhost:8767` refused | `docker compose logs intelligence-layer --tail 30` |
| `localhost:3001` 502 | Langfuse boot mất 30-60s. `docker compose logs langfuse --tail 30` |
| Trace không xuất hiện trong Langfuse | Check `LANGFUSE_*` env trong intelligence-layer container, restart |
| KG visualize 500 | Check pyvis dependency, rebuild image |
| `10.10.6.238:8765` timeout | Suricata VM trong GNS3 chưa start, hoặc libvirt NAT down |
| `10.10.6.238:9090` refused | SF container `nos-sf` trên gns3vm — `ssh dis@10.10.6.238 docker restart nos-sf` |
