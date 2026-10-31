# Web Layer — Frontend (Next.js) + IDS Agent (Go)

> Reference doc cho lớp web: FE Next.js + Next.js API routes + ids-agent Go bridge.
> Mục đích: bất cứ session nào sau cũng có thể đọc tài liệu này để biết FE đang lấy data ở đâu, qua đường nào, format gì.
> Last updated: 2026-05-31 (V2 fabric — 4 LEAFs / 8 zones, post-`9bf4a78` SF multi-LEAF, AGENT_DRY_RUN=true)

---

## 0. Tóm tắt 1 câu

> **FE Next.js (port 3000) → Next.js route handlers (`/api/*`) → ids-agent Go (port 8766) → Secure Framework (10.10.6.238:9090) → gNMI mTLS (port 9339) → nos-acl-bridge trên mỗi LEAF → ConfigDB DB4 + iptables FORWARD.**

Bất kỳ data nào hiện trên web (alert, flow, rule, agent decision) đều đi qua chain này. FE **KHÔNG** gọi thẳng SF hoặc Suricata — tất cả đi qua proxy lớp.

---

## 1. Topology lớp web

```
┌─────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE host (Docker stack)                                  │
│                                                                     │
│   Browser (user)                                                    │
│       │ HTTP                                                        │
│       ▼                                                             │
│   ┌────────────────────────┐                                        │
│   │   fe (Next.js 15)      │  container `fe` · port 3000            │
│   │   pages: /, /monitor,  │                                        │
│   │          /policy        │                                        │
│   │   Next.js API routes:  │                                        │
│   │     /api/ids/*         │ ───────► ids-agent :8766               │
│   │     /api/intel/*       │ ───────► intelligence-layer :8767      │
│   └────────────────────────┘                                        │
│                                                                     │
│   ┌────────────────────────┐                                        │
│   │  ids-agent (Go)         │  container `ids-agent` · port 8766    │
│   │  SSE bridge + REST      │                                        │
│   │  proxy:                 │                                        │
│   │    /events    SSE       │ ◄────── (consumes) ────► Suricata     │
│   │    /alerts /flows /h.   │ ───────►  IDS API :8765 (NAT)         │
│   │    /rules GET/POST/DEL  │ ───────►  SF :9090                    │
│   │    /autoblock           │ ───────►  SF :9090                    │
│   └────────────────────────┘                                        │
│                                                                     │
│   ┌────────────────────────┐                                        │
│   │ intelligence-layer      │  container · port 8767                │
│   │ FastAPI · LangGraph     │                                        │
│   │ /events, /decisions,    │                                        │
│   │ /policy-history, /kg... │                                        │
│   └────────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                       ┌──────────┴──────────┐
                       ▼                     ▼
   http://10.10.6.238:8765      http://10.10.6.238:9090
        Suricata IDS API              Secure Framework REST
   (ids-vm 192.168.122.205)        (container nos-sf, gns3vm)
                                            │
                                            │  gNMI/mTLS :9339
                                            ▼
                              nos-acl-bridge trên 4 LEAFs
                              192.168.122.20/21/22/23
                              → ConfigDB DB4 → iptables FORWARD
```

Source-of-truth files:
- FE: [fe/src/app/](../fe/src/app/) (Next.js App Router)
- FE proxy: [fe/src/app/api/](../fe/src/app/api/)
- ids-agent: [ids-agent/main.go](../ids-agent/main.go) (~660 LOC, single file)
- SF: [secure-framework/sam/role_api.py](../secure-framework/sam/role_api.py) (`_handle_get_rules` line 447, `_handle_post_rule` line 486)

---

## 2. FE pages (Next.js App Router)

Navigation cố định trong [SiteHeader.tsx](../fe/src/components/SiteHeader.tsx) — chỉ 3 entry:

| Page | File | Vai trò |
|---|---|---|
| `/` Dashboard | [fe/src/app/page.tsx](../fe/src/app/page.tsx) | Landing, system status overview, click-through nhanh |
| `/monitor` Live Monitor | [fe/src/app/monitor/page.tsx](../fe/src/app/monitor/page.tsx) | Real-time alerts + flow events theo 8 zones V2, agent notification feed, filter zone/priority/traffic on-off |
| `/policy` Policy Manager | [fe/src/app/policy/page.tsx](../fe/src/app/policy/page.tsx) | Active Rules **chia per-LEAF**, push thủ công, agent decision history với reasoning modal, Raw gNMI modal |

**Đã bỏ:** `/topology`, `/rules`, `/knowledge` (nav cũ — V1) — knowledge graph giờ chỉ truy cập trực tiếp qua URL `http://localhost:8767/kg/visualize`.

### 2.1 `/policy` — chi tiết hiển thị rule

Polling chu kỳ **8000ms** ([page.tsx:176](../fe/src/app/policy/page.tsx#L176)) gọi song song 3 endpoint:

```ts
fetch("/api/ids/rules")        // rules từ LEAFs (gNMI Get)
fetch("/api/ids/autoblock")    // status manual block
fetch("/api/intel/health")     // agent health (dry_run, circuit breaker)
fetch("/api/intel/decisions")  // policy history (50 decisions gần nhất)
```

Rule render được tổ chức **per-LEAF**, không gộp:

```ts
Object.entries(leavesData).map(([leafName, leafData]) => {
  const leafRules = extractRules(leafData);   // page.tsx:87
  return <PerLeafBlock leafName leafRules />;
})
```

→ User nhìn thấy LEAF-1/2/3/4 tách biệt, biết rule nào trên LEAF nào.

**Modal "Raw gNMI"** ([page.tsx:360-372](../fe/src/app/policy/page.tsx#L360)): click button trên top hoặc click vào từng LEAF block → hiện nguyên `leavesData` JSON. Mục đích: chứng minh rule lấy từ LEAF thật qua gNMI, không phải FE bịa.

**Modal "YANG instance"** ([page.tsx:414-422](../fe/src/app/policy/page.tsx#L414)): click vào rule-id → hiện `val{}` (JSON-IETF YANG instance).

### 2.2 `/monitor` — V2 8-zone awareness

`ipZone()` ([page.tsx:54-64](../fe/src/app/monitor/page.tsx#L54)) map IP → zone:

| Prefix | Zone | LEAF |
|---|---|---|
| `10.1.100.` | WEB | LEAF-1 |
| `10.1.200.` | DB (OLTP) | LEAF-1 |
| `10.2.100.` | APP (CORE) | LEAF-2 |
| `10.2.50.` | MGT | LEAF-2 |
| `10.3.100.` | APP-GW | LEAF-3 |
| `10.3.200.` | DB-ANLT | LEAF-3 |
| `10.4.100.` | WORKER | LEAF-4 |
| `10.4.200.` | MON | LEAF-4 |

Zones constant: `["ALL", "WEB", "DB", "APP", "MGT", "APP-GW", "DB-ANLT", "WORKER", "MON"]` ([page.tsx:49](../fe/src/app/monitor/page.tsx#L49)).

Data sources:
- **Alerts** — SSE từ `/api/ids/stream` (proxy `ids-agent /events`) realtime.
- **Flows** — poll mỗi 5s `/api/intel/events?kind=flow` (Suricata flow events quá nhiều, không broadcast SSE).
- **Hydration F5** — `/api/intel/events?limit=600` từ Redis DB 1 (7-day retention).

### 2.3 `AgentNotificationFeed` — filter + dedup

File [fe/src/components/AgentNotificationFeed.tsx](../fe/src/components/AgentNotificationFeed.tsx):
- Poll `/api/intel/decisions` mỗi 3s.
- **Filter:** chỉ giữ `decision === "enforced"` và có `action === "DROP"`. Bỏ hết WARN / log_only / non-DROP (yêu cầu user: feed đỡ rối, chỉ show cái thực sự chặn).
- **Dedup:** key `(attacker_ip, action, block_dst)`, window **60s**. Nhiều SID fire cùng lúc trên cùng 1 flow → chỉ hiện 1 entry đầu tiên ([line 26-43](../fe/src/components/AgentNotificationFeed.tsx#L26)).
- **No severity badges** — đã bỏ INFO/WARN/ALERT/CRITICAL chips per user request.

---

## 3. Next.js API route handlers (FE → backend proxy)

Tất cả nằm trong [fe/src/app/api/](../fe/src/app/api/). Lý do tách lớp: browser không gọi thẳng backend → tránh CORS, tập trung env config, có thể inject middleware sau này.

Env config (từ [docker-compose.yml](../docker-compose.yml)):
- `AGENT_URL` = `http://ids-agent:8766` (internal Docker DNS)
- `INTEL_URL` = `http://intelligence-layer:8767`

### 3.1 IDS routes (`/api/ids/*`)

| FE route | Method | File | Proxies to |
|---|---|---|---|
| `/api/ids/health` | GET | [health/route.ts](../fe/src/app/api/ids/health/route.ts) | `ids-agent /health` |
| `/api/ids/alerts` | GET | [alerts/route.ts](../fe/src/app/api/ids/alerts/route.ts) | `ids-agent /alerts?last=N` |
| `/api/ids/alerts/clear` | POST | [alerts/clear/route.ts](../fe/src/app/api/ids/alerts/clear/route.ts) | `ids-agent /alerts/clear` |
| `/api/ids/flows` | GET | [flows/route.ts](../fe/src/app/api/ids/flows/route.ts) | `ids-agent /flows?last=N&since=ISO` |
| `/api/ids/stream` | GET (SSE) | [stream/route.ts](../fe/src/app/api/ids/stream/route.ts) | `ids-agent /events` (Server-Sent Events, ReadableStream pump) |
| **`/api/ids/rules`** | **GET** | [rules/route.ts](../fe/src/app/api/ids/rules/route.ts) | **`ids-agent /rules` → SF `/api/rules` → gNMI Get 4 LEAFs** |
| **`/api/ids/rules`** | **POST** | (same file) | **`ids-agent /autoblock` (manual block button)** |
| `/api/ids/rules/[id]` | DELETE | [rules/[id]/route.ts](../fe/src/app/api/ids/rules/[id]/route.ts) | `ids-agent /autoblock/unblock/{id}` → SF `DELETE /api/rules/{id}` |
| `/api/ids/autoblock` | GET/POST | [autoblock/route.ts](../fe/src/app/api/ids/autoblock/route.ts) | `ids-agent /autoblock` |

**Lưu ý quirk:** `POST /api/ids/rules` (manual rule push từ FE) **không** đi qua `ids-agent /rules` (vì handler đó force `source=agent`). Thay vào đó đi qua `/autoblock` để giữ `source=manual`. [rules/route.ts:21](../fe/src/app/api/ids/rules/route.ts#L21).

### 3.2 Intelligence Layer routes (`/api/intel/*`)

| FE route | Method | Proxies to |
|---|---|---|
| `/api/intel/health` | GET | `intelligence-layer /health` |
| `/api/intel/decisions` | GET | `intelligence-layer /policy-history?limit=50` |
| `/api/intel/decisions/[id]` | GET | `intelligence-layer /decisions/{id}` (full reasoning trace cho modal 🧠) |
| `/api/intel/events` | GET | `intelligence-layer /events?since=&limit=&kind=` (Redis DB 1, 7-day) |

---

## 4. ids-agent — Go HTTP bridge (port 8766)

Single-file Go binary tại [ids-agent/main.go](../ids-agent/main.go). Container `ids-agent`. Không stateful — chỉ proxy + SSE hub + heartbeat cache.

### 4.1 Vai trò 4 lớp

1. **SSE consumer** — kết nối Suricata IDS API `/stream`, broadcast lại cho WS/SSE client local. Có 2 watchdog: stall-30s + max-age-4-phút (chống upstream silently dies).
2. **REST proxy** — `/alerts`, `/flows`, `/health` đi qua NAT tới `idsURL` (Suricata API).
3. **Rule provenance gateway** — `POST /rules` force `source="agent"` server-side ([main.go:320](../ids-agent/main.go#L320)). Đây là điểm "đóng dấu" agent ID — bất kỳ rule nào đi qua endpoint này SF tin là do agent push.
4. **Service-health poller** — 30s/lần, gọi `/service-health` các service, broadcast snapshot cho FE.

### 4.2 Endpoints

| Method | Path | Handler | Backend |
|---|---|---|---|
| GET | `/events` | `eventsHandler` (SSE, heartbeat 15s) | hub broadcast |
| GET | `/ws` | `wsHandler` | hub broadcast |
| GET | `/health` | `healthHandler` | Suricata `/health` |
| GET | `/alerts[?last=N]` | `alertsHandler` | Suricata `/alerts` |
| GET | `/flows[?last=N&since=]` | `flowsHandler` | Suricata `/flows` |
| GET | `/rules[?source=X]` | `rulesGetHandler` | SF `GET /api/rules`, optional filter by `source` field |
| **POST** | **`/rules`** | **`rulesPostHandler`** | **Force `source=agent`, POST SF `/api/rules`** |
| DELETE | `/rules/{id}` | `rulesDeleteHandler` | SF `DELETE /api/rules/{id}` |
| GET/POST | `/autoblock` | `autoblockHandler` | (POST) `pushBlockRule(srcIP)` — force `source=manual`, SF push |
| DELETE | `/autoblock/unblock/{id}` | `unblockHandler` | SF `DELETE /api/rules/{id}` |

### 4.3 Provenance — tại sao có 2 path POST

| Endpoint | Source stamp | Use case |
|---|---|---|
| `POST /rules` | `agent` (forced server-side) | **Intelligence Layer** gọi sau khi LLM quyết định DROP |
| `POST /autoblock` | `manual` (in body) | **FE Policy form** "Push New Rule" + "Manual block by IP" |

SF khi nhận rule sẽ check `source` field để quyết định routing:
- `source=sdnc` → broadcast 4 LEAFs (baseline policy)
- `source=agent` → zone-routing theo `src_ip` (1 LEAF cụ thể)
- `source=manual` → fallback `get_any_client()` (default LEAF-1)

→ Chi tiết zone-routing trong [Secure-Framework.md §3.2](Secure-Framework.md#32-zone-routing-on-post-rule).

### 4.4 Env config

```go
idsURL     = "http://10.10.6.238:8765"   // override IDS_API_URL
sfURL      = "http://10.10.6.238:9090"   // override SF_API_URL
listenAddr = ":8766"                      // override AGENT_ADDR
```

---

## 5. Rule fetch chain — chi tiết end-to-end

Đây là chain **quan trọng nhất** cho integration với dataplane agent. Khi user/dev hỏi "FE lấy rule như nào", trả lời theo đúng chain dưới đây:

```
Browser /policy
   │ fetch("/api/ids/rules", {cache: "no-store"})  ⟵ page.tsx:153
   │
   ▼
fe/src/app/api/ids/rules/route.ts (GET handler)
   │ fetch(`${AGENT_URL}/rules`)            ⟵ AGENT_URL = http://ids-agent:8766
   │
   ▼
ids-agent/main.go rulesGetHandler (line ~281)
   │ http.Client.Get(sfURL + "/api/rules")  ⟵ sfURL = http://10.10.6.238:9090
   │
   ▼
secure-framework/sam/role_api.py _handle_get_rules (line 447)
   │ for leaf_name, leaf_ip in self.gnmi_pool.leaves.items():
   │     client = pool.get_client_by_key(SonicRole.ADMIN, leaf_ip)
   │     data   = client.gc.get(path=["/nos-iptables:acl/rule"], encoding="json_ietf")
   │     results[leaf_name] = {"connected": True, "rules": data}
   │
   ▼ gNMI Get mTLS port 9339 × 4 LEAFs (parallel-ish, sequential trong code)
   │
nos-acl-bridge trên mỗi LEAF
   │ đọc Redis ConfigDB DB4 key NOS_IPTABLES_RULE|*
   │ trả về YANG JSON-IETF
   ▼
Response chain ngược lại với shape:
```

**Response shape** (FE phụ thuộc — không được thay đổi):

```json
{
  "success": true,
  "leaves": {
    "leaf-1": {
      "connected": true,
      "rules": {
        "notification": [
          {
            "timestamp": <unix-ns>,
            "update": [
              {
                "path": "/nos-iptables:acl/rule[rule-id=Web-AppGw-allow]",
                "val": {
                  "rule-id":     "Web-AppGw-allow",
                  "action":      "ACCEPT",
                  "chain":       "FORWARD",
                  "src-prefix":  "10.1.100.0/24",
                  "dst-prefix":  "10.3.100.0/24",
                  "src-port":    "",
                  "dst-port":    "",
                  "protocol":    "all",
                  "priority":    "200",
                  "source":      "sdnc",
                  "comment":     "Web -> AppGw allowed",
                  "ttl-seconds": "0"
                }
              }
            ]
          }
        ]
      }
    },
    "leaf-2": { ... },
    "leaf-3": { ... },
    "leaf-4": { ... }
  }
}
```

**Naming convention bắt buộc**: YANG dùng **dấu gạch ngang** (`rule-id`, `src-prefix`, `ttl-seconds`). **KHÔNG** underscore. FE TypeScript `interface Rule` ([page.tsx:5-19](../fe/src/app/policy/page.tsx#L5)) match đúng schema này.

**FE parse logic** ([page.tsx:87-107](../fe/src/app/policy/page.tsx#L87)):

```ts
function extractRules(leafData: LeafData): Rule[] {
  const notif = leafData?.rules?.notification;
  if (Array.isArray(notif) && notif.length > 0) {
    const updates = notif[0]?.update;
    if (Array.isArray(updates)) {
      const rules: Rule[] = [];
      for (const u of updates) {
        const val = u?.val;
        if (val?.["rule-id"]) rules.push(val);
      }
      return rules;
    }
  }
  // fallback shapes...
}
```

---

## 6. Rule push chains (FE → enforcement)

### 6.1 Manual push (FE form)

```
User điền form /policy → click "Push Rule"
   │ POST /api/ids/rules  body={rule_id, action, src_ip, dst_ip, protocol, priority, comment, source:"manual"}
   ▼
Next.js handler (rules/route.ts POST)
   │ POST http://ids-agent:8766/autoblock  body nguyên vẹn
   ▼
ids-agent /autoblock handler
   │ pushBlockRule(srcIP) → SF /api/rules (source="manual" hoặc "agent" tùy path)
   ▼
SF _handle_post_rule → `source` field quyết định routing:
   manual → get_any_client() (LEAF-1 default)
   ▼ gNMI Set mTLS
nos-acl-bridge → ConfigDB DB4 → iptables FORWARD
```

### 6.2 Agent enforce (intelligence-layer)

```
intelligence-layer LangGraph pipeline → policy_decision → enforce node
   │ POST http://ids-agent:8766/rules  body={rule_id, action:"DROP", src_ip, dst_ip, dst_port, ttl_seconds, ...}
   ▼
ids-agent rulesPostHandler (main.go:313)
   │ body["source"] = "agent"   ⟵ FORCE server-side, provenance unforgeable
   │ POST http://10.10.6.238:9090/api/rules
   ▼
SF _handle_post_rule: source=="agent" → ip_to_leaf(src_ip) → 1 LEAF cụ thể
   ▼ gNMI Set mTLS (single LEAF)
nos-acl-bridge → ConfigDB → iptables FORWARD priority=50 (trên zt baseline 200)
```

### 6.3 SDNC baseline (ONAP push hoặc SF restart cert=sdnc)

```
sdnc cert + POST {source:"sdnc"} → SF
   ▼
_handle_post_rule: source=="sdnc" → broadcast TẤT CẢ LEAFs
   ▼ gNMI Set × 4 LEAFs
Mỗi LEAF nhận cùng rule → defense-in-depth baseline policy
```

---

## 7. Delete chain

```
FE click "Del" → window.confirm(...) → DELETE /api/ids/rules/{id}
   │
   ▼
Next.js DELETE handler → http://ids-agent:8766/autoblock/unblock/{id}
   │
   ▼
ids-agent unblockHandler → SF DELETE /api/rules/{id}
   │
   ▼
SF _handle_delete_rule: for leaf in pool.leaves: client.gc.set(delete=[path])
   ▼ gNMI Delete × 4 LEAFs (broadcast — xóa khỏi mọi LEAF)
nos-acl-bridge → ConfigDB del key → iptables -D FORWARD
```

→ Delete **luôn** broadcast cả 4 LEAFs (không zone-route). Cleanup phải kỹ.

---

## 8. SSE flow (live alert/flow stream)

```
Suricata eve.json
   │ tail
   ▼
ids-vm/ids-api.py exposes /stream (SSE)
   │
   ▼
ids-agent consumeSSE (main.go runBridge)
   │ scanner line-by-line, "data: <json>\n\n"
   │ hub.broadcast(msg)
   │
   ▼ 2 paths concurrent:
   │
   ├─ subscriber: intelligence-layer (Python aiohttp)
   │    consumes SSE → LangGraph pipeline → decision
   │
   └─ subscriber: FE /api/ids/stream
        ReadableStream pump → browser EventSource
        → /monitor renders alerts
```

**Heartbeat:** ids-agent gửi `: ping\n\n` mỗi 15s để giữ kết nối.

**Watchdogs (main.go:455-466):**
1. Stall-timeout 30s — không nhận dòng nào → reconnect (heartbeats từ upstream mỗi 15s, miss 2 → trigger).
2. Max connection age 4 phút — force reconnect định kỳ. Bắt case heartbeat đến đều nhưng broadcast list upstream silently reset (alert thật không bao giờ tới).

---

## 9. Reasoning modal (Stage 1 + Stage 2 dual-stage)

FE click 💡 icon trên Agent Policy History row:

```
GET /api/intel/decisions/{id}
   │
   ▼
intelligence-layer /decisions/{id}
   │ SELECT * FROM decisions_history WHERE id=$1
   ▼
Response body:
{
  id, alert_sid, alert_src_ip, outcome, action, src_ip, dst_ip, dst_port,
  confidence, rule_id, ttl_seconds, latency_ms, trace_id,
  ─ Stage 1 (policy_decision) ─
  primary_hypothesis, hypotheses[], reasoning[],
  alternative_actions[], rollback_plan{}, follow_up_actions[],
  mitre_technique, mitre_tactic,
  ─ Stage 2 (reasoning_trace, async) ─
  reasoning_completed_at, reasoning_loading
}
```

`reasoning_loading: true` → FE hiển thị skeleton, poll lại sau 2s. Stage 2 fail-tolerant — decision vẫn enforce dù reasoning chưa xong.

---

## 10. Health / status indicators FE hiển thị

| FE element | Source endpoint | Field |
|---|---|---|
| Top-right `N LEAF` chip | `/api/ids/rules` → `leaves[*].connected` count | `Object.values(leavesData).filter(l => l.connected).length` |
| "AI Agent LIVE / DRY-RUN / CIRCUIT OPEN" | `/api/intel/health` | `dry_run`, `circuit_breaker.is_open` |
| Stats card "Total Rules / DROP / ACCEPT" | `/api/ids/rules` (aggregated dedup by rule-id) | `allRules.length`, filter action |
| Agent Policy History timeline | `/api/intel/decisions` | last 50 decisions |
| Monitor alert feed | `/api/ids/stream` (SSE) + `/api/intel/events` (hydrate) | EventStore Redis DB 1 |

---

## 11. Env variables (web layer)

```yaml
# docker-compose.yml services:
fe:
  environment:
    AGENT_URL: http://ids-agent:8766    # FE → ids-agent (internal Docker DNS)
    INTEL_URL: http://intelligence-layer:8767
    NODE_ENV: production

ids-agent:
  environment:
    IDS_API_URL: http://10.10.6.238:8765    # → Suricata API (qua NAT)
    SF_API_URL:  http://10.10.6.238:9090    # → SF Role API (qua NAT)
    AGENT_ADDR:  :8766                       # listen port
```

Override khi develop local (chạy `pnpm dev` ngoài Docker):
```bash
AGENT_URL=http://localhost:8766 INTEL_URL=http://localhost:8767 pnpm --filter ./fe dev
```

---

## 12. Lifecycle / restart

```bash
# Sau khi sửa FE code
docker compose build fe && docker compose up -d fe

# Sau khi sửa ids-agent (Go) code
docker compose build ids-agent && docker compose up -d ids-agent

# Sau khi sửa SF — bundle phải sync lên dataplane host
# (SF chạy container nos-sf TRÊN gns3vm @ 10.10.6.238, KHÔNG trên control plane)
rsync -av /home/dis/deploy/zerotrust/secure-framework/ \
      dis@10.10.6.238:/home/dis/deploy/zerotrust/secure-framework/
ssh dis@10.10.6.238 'cd /home/dis/deploy/zerotrust && docker compose restart nos-sf'
```

---

## 13. Troubleshooting

| Triệu chứng | Endpoint check | Fix |
|---|---|---|
| FE `/policy` "No LEAF connections" | `curl http://10.10.6.238:9090/api/rules` từ control plane | SF down hoặc gNMI pool chưa connect 4 LEAFs |
| FE `/policy` "SF offline" badge | `docker logs ids-agent` xem SF_API_URL timeout | Check NAT 10.10.6.238 reachable, SF container alive |
| Rules trên FE lệch giữa các LEAF | Đúng theo design (per-LEAF render) | Click "Raw gNMI" modal để confirm response từng LEAF |
| Manual block từ FE không xuất hiện rule | `docker logs ids-agent | grep autoblock` | Check `source` field — phải là `manual` (không bị stamp `agent`) |
| Live alert feed `/monitor` trống | `curl http://localhost:8766/events` từ host | ids-agent SSE upstream down, kiểm watchdog log |
| Agent Policy History trống | `curl http://localhost:8767/policy-history?limit=5` | Intelligence-layer chưa nhận alert hoặc AGENT_DRY_RUN bị tắt sai |
| Reasoning modal "loading reasoning..." hoài | `docker logs intelligence-layer | grep reasoning_trace_failed` | Stage 2 LLM timeout — fail-tolerant nên decision vẫn enforce, modal sẽ trống |
| FE poll loop spam SF logs | Polling chu kỳ 8s là intended | Để giữ live feel — không thay vì SSE vì rule list cập nhật chậm |

---

## 14. Cấu trúc thư mục liên quan

```
fe/
├── src/app/
│   ├── layout.tsx               # Root layout, SiteHeader + SiteFooter
│   ├── page.tsx                 # / Dashboard landing
│   ├── monitor/page.tsx         # /monitor V2 8-zone live feed (586 LOC)
│   ├── policy/page.tsx          # /policy per-LEAF rules + agent history (837 LOC)
│   └── api/
│       ├── ids/
│       │   ├── health/route.ts
│       │   ├── alerts/{route.ts, clear/route.ts}
│       │   ├── flows/route.ts
│       │   ├── stream/route.ts        # SSE proxy
│       │   ├── rules/{route.ts, [id]/route.ts}
│       │   └── autoblock/route.ts
│       └── intel/
│           ├── health/route.ts
│           ├── decisions/{route.ts, [id]/route.ts}
│           └── events/route.ts
├── src/components/
│   ├── SiteHeader.tsx           # Top nav (3 entries: Dashboard / Monitor / Policy)
│   ├── SiteFooter.tsx
│   ├── ThemeToggle.tsx          # ☀ Light / 🌙 Dark, persist localStorage zt-theme
│   ├── AgentNotificationFeed.tsx  # Bottom-right toast, enforced-DROP only, 60s dedup
│   └── ScrollReveal.tsx
└── package.json (Next.js 15, pnpm workspace)

ids-agent/
├── main.go                      # Single file (~660 LOC) — SSE bridge + REST proxy
├── go.mod
└── Dockerfile
```

---

## 15. Liên quan / xem thêm

- [Secure-Framework.md](Secure-Framework.md) — backend SF (port 9090, gNMI pool, RBAC, zone-routing)
- [INTELLIGENCE-LAYER.md](INTELLIGENCE-LAYER.md) — LangGraph agent pipeline V3 (8 nodes, Langfuse trace)
- [DATAPLANE_V2.md](DATAPLANE_V2.md) — V2 topology, 4 LEAFs, 8 zones, baseline policy matrix
- [PORTS-AND-UIS.md](PORTS-AND-UIS.md) — port map toàn stack + debug Web UI (Adminer, RedisInsight)
- [demo_system_walkthrough.md](demo_system_walkthrough.md) — full E2E demo script
