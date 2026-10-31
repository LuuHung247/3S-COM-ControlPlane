# Secure Framework — Pipeline Architecture

> Mô tả chi tiết kiến trúc và luồng đẩy policy từ Control Plane → Dataplane
> Last updated: 2026-05-31 (**V2 fabric — 4 LEAFs / 8 zones**, source-based routing: sdnc=broadcast, agent=zone-route, CamelCase rule IDs)
> Previous: 2026-05-05 (V3 schema split, Langfuse, EventsStore)

---

## 1. Tổng quan hệ thống

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE  (Docker @ host máy tính cá nhân)                             │
│                                                                              │
│   ┌────────────────────┐       ┌──────────────────────┐                     │
│   │   Frontend (fe)    │ HTTP  │     IDS Agent (Go)   │                     │
│   │   Next.js :3000    │──────▶│     :8766            │                     │
│   │   /policy page     │       │   /rules (POST/DEL)  │                     │
│   │   /monitor page    │       │   /autoblock         │                     │
│   └────────────────────┘       │   /events (SSE/WS)   │                     │
│                                └──────┬───────▲───────┘                     │
│   ┌────────────────────┐    SSE│      │ POST  │rules                        │
│   │ Intelligence Layer │───────┘      │                                     │
│   │ FastAPI :8767      │──────────────┘                                     │
│   │ LangGraph pipeline │                                                    │
│   └────────────────────┘                                                    │
│                                           │ HTTP REST                       │
└──────────────────────────────────────────┼──────────────────────────────────┘
                                           │
                             ╔═════════════▼═════════════╗
                             ║   PUBLIC INTERNET / LAN   ║
                             ╚═════════════╦═════════════╝
                                           │
┌──────────────────────────────────────────┼──────────────────────────────────┐
│  DATAPLANE  (GNS3VM @ 10.10.6.238)      │                                  │
│                                          ▼                                  │
│   ┌─────────────────────────────────────────────────────────────┐           │
│   │  Secure Framework  (container: nos-sf, Python 3.11)         │           │
│   │  Role API  :9090     NETCONF server  :6513                   │           │
│   │                                                             │           │
│   │  ┌────────────────────┐   ┌──────────────────────────────┐ │           │
│   │  │  REST /api/rules   │   │  NETCONF adapter (ONAP SDNC) │ │           │
│   │  │  (role_api.py)     │   │  (netconf_gnmi_adapter.py)   │ │           │
│   │  └────────┬───────────┘   └─────────────┬────────────────┘ │           │
│   │           │                             │                   │           │
│   │           └──────────┬──────────────────┘                   │           │
│   │                      │  gNMI Set (mTLS :9339)               │           │
│   │           ┌──────────▼──────────────────┐                   │           │
│   │           │  nos_gnmi_pool.py            │                   │           │
│   │           │  Source-based routing:       │                   │           │
│   │           │    sdnc  → broadcast 4 LEAFs │                   │           │
│   │           │    agent → ip_to_leaf(src)   │                   │           │
│   │           │    manual→ get_any_client()  │                   │           │
│   │           └──────┬──────────────┬────────┘                   │           │
│   └──────────────────┼──────────────┼────────────────────────────┘           │
│                      │              │                                        │
│      gNMI/mTLS :9339 │              │ gNMI/mTLS :9339                       │
│                      ▼              ▼                                        │
│   ┌────────────────────┐  ┌────────────────────┐                            │
│   │  nos-acl-bridge    │  │  nos-acl-bridge    │  (systemd service)         │
│   │  SONIC-LEAF-1      │  │  SONIC-LEAF-2      │                            │
│   │  192.168.122.20    │  │  192.168.122.21    │                            │
│   │  bridge/           │  │  bridge/           │                            │
│   │   validators.py    │  │   validators.py    │                            │
│   │   iptables.py      │  │   iptables.py      │                            │
│   └────────┬───────────┘  └────────┬───────────┘                            │
│            │                       │                                        │
│            ▼                       ▼                                        │
│   ┌────────────────┐     ┌────────────────┐                                 │
│   │  ConfigDB DB4  │     │  ConfigDB DB4  │  (Redis — survives restart)     │
│   │  iptables      │     │  iptables      │  (FORWARD chain)                │
│   │  FORWARD chain │     │  FORWARD chain │                                 │
│   └────────────────┘     └────────────────┘                                 │
│                                                                              │
│   ⚠ V2 (2026-05-31): pool nay co 4 LEAFs (.20/.21/.22/.23) chu khong phai 2.│
│   LEAF-3/4 deploy them voi nos-acl-bridge tuong tu, mTLS gNMI:9339, server  │
│   cert SAN=IP do ONAP-SONiC-CA ky. So do truc giac giu nguyen — chi mo rong │
│   fan-out. See §7 cho zone map day du va §3 cho source-based routing.       │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 1.b V2 fabric — 4 LEAFs / 8 zones (2026-05-31)

Cập nhật từ V1 (2 LEAFs / 4 zones) → V2 (4 LEAFs / 8 zones). Mọi pipeline + RBAC + YANG schema giữ nguyên; chỉ scale-out gNMI pool và mở rộng zone map.

| LEAF | mgmt IP | TLS hostname (cert SAN) | Zones |
|---|---|---|---|
| LEAF-1 | 192.168.122.20 | `sonic-leaf-1` | WEB (10.1.100.0/24), DB-OLTP (10.1.200.0/24) |
| LEAF-2 | 192.168.122.21 | `sonic-leaf-2` | APP-CORE (10.2.100.0/24), MGT (10.2.50.0/24) |
| LEAF-3 ✦ | 192.168.122.22 | `sonic-leaf-3` | APP-GW (10.3.100.0/24), DB-ANLT (10.3.200.0/24) |
| LEAF-4 ✦ | 192.168.122.23 | `sonic-leaf-4` | WORKER (10.4.100.0/24), MON (10.4.200.0/24) |

✦ = V2 new.

CLI args để thêm/skip LEAF khi start SF ([app.py:58-65](../secure-framework/app.py#L58)):

```bash
python3 app.py \
  --leaf1-host 192.168.122.20 \
  --leaf2-host 192.168.122.21 \
  --leaf3-host 192.168.122.22 \
  --leaf4-host 192.168.122.23 \
  --client-cert ./certificate/generate/output_3snos/agent-ids/client.crt \
  --client-key  ./certificate/generate/output_3snos/agent-ids/client.key \
  --client-ca   ./certificate/generate/output_3snos/agent-ids/trustedCertificates.crt
```

Truyền `--leaf3-host ''` để skip LEAF chưa deploy bridge.

---

## 2. Components

### 2.1 IDS Agent (`ids-agent/`)

Go binary, container `ids-agent` trên control plane.

**Vai trò (sau refactor — pure proxy/bridge):**
- Bridge SSE/WebSocket từ Suricata IDS → Frontend + Intelligence Layer
- Proxy REST `/rules` ↔ SF `/api/rules` (GET: list, POST: push với `source=agent` forced, DELETE: revoke)
- REST `/autoblock` để Frontend push rule thủ công (manual block button)

> ⚠️ `tryAutoBlock()`, `autoBlockEnabled`, `blockedIPs map`, `/autoblock/enable`, `/autoblock/disable` **đã bị xóa hoàn toàn** khỏi `main.go`. Auto-decision thuộc về Intelligence Layer, không phải ids-agent.

**Key endpoints:**

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/events` | SSE stream alerts từ Suricata (+ heartbeat 15s) |
| GET | `/ws` | WebSocket — cùng payload |
| GET | `/health` | Proxy → Suricata `/health` |
| GET | `/alerts` | Proxy → Suricata `/alerts` |
| GET | `/stats` | Alert counters |
| GET | `/rules` | Proxy → SF `/api/rules` (gNMI format) |
| **POST** | **`/rules`** | **Push rule, force `source=agent` server-side — Intelligence Layer dùng** |
| **DELETE** | **`/rules/{rule_id}`** | **Revoke rule khỏi SF + LEAF — Intelligence Layer dùng** |
| POST | `/autoblock` | Frontend manual block by IP |
| DELETE | `/autoblock/unblock/{id}` | Frontend manual unblock |

### 2.1b Intelligence Layer (`intelligence-layer/`)

Python FastAPI, container `intelligence-layer` port 8767, cùng Docker network `ztnet`.

**Vai trò:** LLM AI agent — single source of truth cho automated enforcement.
- Subscribe SSE từ `ids-agent:8766/events`
- LLM pipeline: classify → reason → validate → enforce
- Push DROP rule qua `POST ids-agent:8766/rules`
- Revoke rule qua `DELETE ids-agent:8766/rules/{id}`

→ Chi tiết: [INTELLIGENCE-LAYER.md](INTELLIGENCE-LAYER.md)

### 2.2 Frontend (`fe/`)

Next.js 15 app, container `fe` port 3000 trên control plane.

**Policy page** (`/policy`):
- Active Rules: poll SF qua `/api/ids/rules` mỗi 8s, agent rules highlight orange
- Push rule thủ công: form → POST `/api/ids/rules` → IDS Agent → SF (`source=manual`)
- Xóa rule: DELETE `/api/ids/rules/{id}`
- Manual block: POST `/api/ids/autoblock`
- **AI Agent status bar**: live health từ `/api/intel/health` (model, dry_run, circuit breaker)
- **Agent Policy History timeline**: decisions từ `/api/intel/decisions` (⚡ ENFORCED / ◎ DRY-RUN, confidence bar, latency)

**Next.js API routes:**

| Route | Proxies to |
|-------|-----------|
| `/api/ids/rules` GET/POST | IDS Agent `/rules` |
| `/api/ids/rules/[id]` DELETE | IDS Agent `/rules/{id}` DELETE |
| `/api/ids/autoblock` GET/POST | IDS Agent `/autoblock` |
| `/api/ids/autoblock/unblock/[id]` DELETE | IDS Agent `/autoblock/unblock/{id}` |
| `/api/intel/health` GET | Intelligence Layer `/health` |
| `/api/intel/decisions` GET | Intelligence Layer `/policy-history?limit=50` |

### 2.3 Secure Framework (`secure-framework/`)

Python 3.11, container `nos-sf` trên dataplane (10.10.6.238).

**Hai entry point:**
- **NETCONF server** `:6513` — nhận `edit-config` từ ONAP SDNC
- **Role API** `:9090` — nhận REST từ IDS Agent

**Core modules:**

| File | Vai trò |
|------|---------|
| `sam/role_api.py` | HTTP server (ThreadingHTTPServer), REST `/api/rules` CRUD |
| `netconf_gnmi_adapter.py` | Nhận NETCONF XML, translate → gNMI Set |
| `nos_gnmi_pool.py` | Pool kết nối gNMI tới các LEAF, zone routing |
| `sam/session_context.py` | Per-thread session (ONAP role, cert OU) |
| `tamper_logger.py` | Audit log mọi thao tác CRUD |
| `yang/nos-iptables.yang` | YANG model — dùng cho cả NETCONF schema và bridge validation |

### 2.4 nos-acl-bridge (trên mỗi LEAF)

Python systemd service tại `/opt/nos-acl-bridge/`, chạy trên 4 LEAFs (V2): LEAF-1..4 tại 192.168.122.20/21/22/23.

**Vai trò:** gNMI server nhận Set/Get từ SF → validate → ghi vào ConfigDB DB4 → apply iptables FORWARD.

| File | Vai trò |
|------|---------|
| `bridge/nos_acl_bridge.py` | gNMI server gRPC, dispatch Set/Get |
| `bridge/validators.py` | Validate rule dict theo YANG constraints + RBAC |
| `bridge/iptables.py` | Apply/delete iptables rule từ ConfigDB |
| `bridge/recovery.py` | Replay ConfigDB rules vào iptables sau restart |

---

## 3. Pipeline chi tiết — Push rule từ UI

```
User điền form /policy → nhấn "Push Rule"
        │
        │  POST /api/ids/rules  {rule_id, action, src_ip, priority, comment}
        ▼
  Next.js API route  (source="manual" tự inject)
        │
        │  POST http://ids-agent:8766/autoblock  (body nguyên vẹn)
        ▼
  IDS Agent  (Go)
        │
        │  POST http://10.10.6.238:9090/api/rules
        │  body: {rule_id, action, src_ip, priority, source="manual", comment}
        ▼
  Secure Framework  role_api.py → _handle_post_rule()  (line 486)
        │
        ├─ Validate action ∈ {ACCEPT, DROP, RETURN}
        ├─ Source-based routing (V2 — role_api.py:522-534):
        │
        │   if body.source == "sdnc":
        │       clients = ALL LEAFs in pool   ← broadcast (defense-in-depth baseline)
        │   elif body.source == "agent":
        │       leaf_ip = ip_to_leaf(src_ip)
        │       clients = [single LEAF that owns src zone]
        │   else:  # source=="manual" or missing
        │       clients = [get_any_client()]  ← fallback LEAF-1 mặc định
        │
        │  V2 zone map (8 zones → 4 LEAFs):
        │   10.1.100.0/24 WEB     → LEAF-1 (192.168.122.20)
        │   10.1.200.0/24 DB-OLTP → LEAF-1
        │   10.2.100.0/24 APP-CORE→ LEAF-2 (192.168.122.21)
        │   10.2.50.0/24  MGT     → LEAF-2
        │   10.3.100.0/24 APP-GW  → LEAF-3 (192.168.122.22) ✦
        │   10.3.200.0/24 DB-ANLT → LEAF-3                  ✦
        │   10.4.100.0/24 WORKER  → LEAF-4 (192.168.122.23) ✦
        │   10.4.200.0/24 MON     → LEAF-4                  ✦
        │
        │  gNMI Set (mTLS, cert OU=auto → AGENT role mặc định khi chạy với agent-ids cert)
        │  path: /nos-iptables:acl/rule[rule-id={id}]
        │  encoding: json_ietf
        ▼
  nos-acl-bridge  (trên LEAF tương ứng)
        │
        ├─ validate_rule(rule)       ← validators.py
        │     rule-id pattern OK?
        │     action ∈ {ACCEPT,DROP,REJECT}?
        │     src-prefix valid IPv4 CIDR?
        │     priority 1–9999?
        │     source ∈ {manual, sdnc, agent}?
        │     if source=="agent": action phải là DROP
        │
        ├─ enforce_rbac(rule, role)  ← cert OU → role mapping
        │     ADMIN (OU=internal/sdnc): unrestricted
        │     OPERATOR (OU=aws): source phải là sdnc
        │     AGENT (OU=auto): source phải là agent + action=DROP
        │
        ├─ Ghi vào ConfigDB DB4  (Redis)
        │     key: NOS_IPTABLES_RULE|{rule-id}
        │     value: {rule fields}
        │
        └─ Apply iptables FORWARD
              iptables -I FORWARD <priority> -s <src-ip> [-d <dst-ip>]
                       [-p <proto>] [--sport/--dport] -m comment
                       --comment "{rule-id}:{source}" -j {action}
```

**Response ngược lại:**
```
nos-acl-bridge → gNMI OK
SF → {success: true, rule_id, pushed_to: ["10.1.100.x"]}
IDS Agent → forward response
Next.js → {success: true, pushed_to: [...]}
UI → hiển thị "✓ pushed to 10.1.100.x"
UI → reload rules sau 1s
```

---

## 4. Pipeline — Intelligence Layer automated enforcement

> ⚠️ `tryAutoBlock()` đã bị **xóa hoàn toàn** khỏi ids-agent. Mọi auto-decision đều do Intelligence Layer xử lý.

```
Suricata phát hiện violation (e.g., WEB→DB lateral move)
        │
        │  SSE event  data: {src_ip, alert.severity=1, alert.signature_id}
        ▼
  IDS Agent  consumeSSE() / runPoller()
        │
        ├─ hub.broadcast(msg)  → Frontend /monitor real-time
        │
        └─ SSE stream → Intelligence Layer  :8767  (subscriber)

  Intelligence Layer V3  (FastAPI + 8-node async pipeline)
        │
        ├─ [pipeline/gate.py]  Filter chain:
        │     SeverityFilter   → skip P3/P4 (severity > 2)
        │     DedupFilter      → skip nếu đã xử lý trong 30s
        │     RateLimiter      → tối đa 30 alerts/phút
        │     WhitelistFilter  → skip nếu src_ip trong NEVER_BLOCK list
        │
        ├─ [pipeline/consumer.py]  Mirror sang EventsStore (Redis DB 1)
        │     events:violations / events:flows (sorted set, 7-day TTL)
        │
        ├─ [agent/graph.py]  V3 pipeline (8 spans, Langfuse-traced):
        │     load_context      → alert-scoped KG render (~3000 tokens)
        │     classify_alert    → llama3.1-8b (benign/suspicious/threat)
        │     gather_context    → 4 parallel: history + summary + correlation +
        │                         investigation tools (asset_neighbors, past_incidents,
        │                         block_impact, kill_chain_match)
        │     cache_lookup      → Redis response cache (60s TTL)
        │     ★ policy_decision → Stage 1 BLOCKING — GLM-4.7
        │                         POLICY_DECISION_SCHEMA (9 scalar fields, 0% parser fail)
        │     validate_decision → 9 safety layers + L1+ prompt injection + L4b off-target
        │     ★ asyncio.gather:
        │         enforce_path:        POST ids-agent → SF → gNMI → LEAF
        │         reasoning_trace:     Stage 2 GLM-4.7 (REASONING_TRACE_SCHEMA, 4 arrays)
        │                              fail-tolerant — decision still enforces
        │     record_decision   → Postgres + Redis cache + SSE /stream + Langfuse spans
        │
        │  POST http://ids-agent:8766/rules
        │  {rule_id: "agent-{sha256[:10]}",   ← deterministic, idempotent
        │   action: "DROP", src_ip: "10.1.100.10/32", dst_ip: "10.1.200.10/32",
        │   dst_port: 5432, protocol: "tcp",
        │   priority: 50, ttl_seconds: 3600,
        │   comment: "agent:..."}
        ▼
  IDS Agent  /rules  POST handler
        │  force source="agent" server-side
        │  POST http://10.10.6.238:9090/api/rules
        ▼
  (pipeline tiếp theo giống mục 3)
  Bridge enforce: source="agent" → action phải DROP ✓
```

**Safety guardrails (9 layers + L1+ + L2+ + L4b) trước khi enforce:**

| Layer | Check | Reject nếu |
|-------|-------|-----------|
| L1 Schema | Pydantic strict + forced function calling | Output tự do, field sai |
| L1+ Prompt injection | Pattern detector (PINT/JailBreakBench corpus) + sanitize | Suspicious patterns in alert.signature/category |
| L2 Consistency | Self-consistency vote (N=1 stable với V3) | Action disagreement (N>=2) |
| L2+ Semantic entropy | Shannon over decision shape clusters | Entropy > 1.0 OR src_ip consensus < 67% |
| L3 Validators | Schema, topology, policy conflict, idempotency | Bất kỳ violation |
| L4 Whitelist | NEVER_BLOCK hardcoded (management IPs, SVIs, mgt-01, IDS) | Block IP trong whitelist |
| L4b Off-target | `intent.src_ip` contains `alert.src_ip` (CIDR membership) | LLM hallucinated wrong IP |
| L5 Blast radius | 5 rules/min, 50 total, 3/IP/5min, TTL 60–3600s | Vượt giới hạn |
| L6 Severity↔action | P1/P2→DROP, P3/P4→log_only | P3/P4 với DROP |
| L7 Confidence gate | ≥0.85 enforce, 0.70–0.85 enforce+notify, <0.70 hold | Confidence < 0.70 |
| L8 Reversibility | TTL mandatory, `AGENT_DRY_RUN` kill switch, circuit breaker | 3 fail liên tiếp → halt |
| L9 Tests | adversarial unit tests + pattern injection corpus | Fail = block deploy |

**V3 verified results (10/10 PASS, 2026-05-05)**:
- M1 Alert→Decision avg 8.5s (V2 was 4.75s but had Cerebras 400 outliers 17-26s)
- Cerebras 400 rate: **0%** in 30 LLM calls (vs ~5-10% in V2)
- Confidence: **0.92** consistent across all 10 runs
- M3 Enforcement Correctness: **100%** (correct IP blocked every time)

**Priority ordering trên LEAF:**

| Priority | Loại rule | Source | Ví dụ |
|----------|-----------|--------|-------|
| 50 | Intelligence Layer auto-block | `agent` | `agent-10-1-100-55` |
| 200 | ZT baseline (microseg) | `sdnc` | `zt-web-app-allow` |
| 9999 | Default deny-all | `sdnc` | `zt-default-drop` |

---

## 5. Pipeline — ONAP SDNC push (NETCONF)

```
ONAP ODL gửi NETCONF edit-config
        │
        │  TCP :6513  →  TLS handshake
        │  XML payload (namespace urn:3snos:iptables):
        │    <acl><rule><rule-id>...</rule-id><action>...</action>...</rule></acl>
        ▼
  Secure Framework  netconf_gnmi_adapter.py
        │
        ├─ Parse XML → dict
        ├─ Detect YANG namespace:
        │     urn:3snos:iptables → native format, dùng trực tiếp
        │     openconfig-acl    → translate sang nos-iptables format
        │
        ├─ AGENT auto-stamp:
        │     session OU=auto? → force action=DROP, source="agent"
        │
        ├─ ip_to_leaf(src_ip) → route tới LEAF đích
        │
        │  gNMI Set (cert OU=sdnc → ADMIN)
        ▼
  (pipeline bridge giống mục 3)
```

---

## 6. RBAC — phân quyền theo cert OU

SF → LEAF dùng **mTLS (mutual TLS)**: cả SF và bridge đều present certificate.  
Bridge đọc OU từ client cert để xác định role, enforce hoàn toàn ở tầng bridge — SF không thể bypass.

| Client cert OU | Role | Được phép |
|----------------|------|-----------|
| `internal` hoặc `sdnc` | ADMIN | Mọi action, mọi source |
| `aws` | OPERATOR | ACCEPT/DROP, chỉ `source=sdnc` |
| `auto` | AGENT | Chỉ DROP, chỉ `source=agent` |

**Cert paths trên SF:**
```
/app/certificate/generate/output_3snos/
  sdnc/
    client.crt    (OU=sdnc)  ← dùng cho push ZT baseline, manual
    client.key
    trustedCertificates.crt
  agent-ids/
    client.crt    (OU=auto)  ← dùng cho auto-block từ IDS Agent
    client.key
    trustedCertificates.crt
```

Hiện tại SF dùng cert SDNC (ADMIN) cho tất cả push từ REST API và NETCONF.  
IDS Agent push qua SF REST → SF relay dùng cert SDNC.  
Nếu IDS Agent push thẳng gNMI (bỏ qua SF) mới cần cert AGENT.

---

## 7. gNMI Connection Pool

[`nos_gnmi_pool.py`](../secure-framework/nos_gnmi_pool.py) quản lý pool kết nối tới các LEAF. V2 mở rộng từ 2 → 4 LEAFs.

```python
# Zone routing — src prefix → LEAF (nos_gnmi_pool.py:29)
ZONE_TO_LEAF = {
    # LEAF-1 (V1)
    "10.1.100.0/24": "192.168.122.20",   # WEB
    "10.1.200.0/24": "192.168.122.20",   # DB-OLTP
    # LEAF-2 (V1)
    "10.2.100.0/24": "192.168.122.21",   # APP-CORE
    "10.2.50.0/24":  "192.168.122.21",   # MGT
    # LEAF-3 (V2) ✦
    "10.3.100.0/24": "192.168.122.22",   # APP-GW
    "10.3.200.0/24": "192.168.122.22",   # DB-ANLT
    # LEAF-4 (V2) ✦
    "10.4.100.0/24": "192.168.122.23",   # WORKER
    "10.4.200.0/24": "192.168.122.23",   # MON
}

# TLS hostname override per LEAF — phải match SAN DNS trong bridge server cert
LEAF_TLS_HOSTNAME = {
    "192.168.122.20": "sonic-leaf-1",
    "192.168.122.21": "sonic-leaf-2",
    "192.168.122.22": "sonic-leaf-3",    # V2 ✦
    "192.168.122.23": "sonic-leaf-4",    # V2 ✦
}

def ip_to_leaf(src: str) -> Optional[str]:
    """Map src IP/prefix → LEAF owning its zone. CIDR subnet_of check."""
    net = ipaddress.ip_network(src, strict=False)
    for zone_net, leaf_ip in _ZONE_NETWORKS.items():
        if net.subnet_of(zone_net):
            return leaf_ip
    return None
```

Nếu `src_ip` không match zone nào (hoặc rỗng) → `get_any_client()` → push tới LEAF đang available (mặc định LEAF-1).

**pygnmi params quan trọng (per-LEAF):**

```python
SonicGnmiClient(
    host=(leaf_ip, 9339),
    path_cert=client_cert_path,    # OU=auto (AGENT) hoặc OU=sdnc (ADMIN)
    path_key=client_key_path,
    path_root=ca_cert_path,        # ONAP-SONiC-CA verify bridge server cert
    override=LEAF_TLS_HOSTNAME[leaf_ip],     # sonic-leaf-1..4
    grpc_options=[("grpc.ssl_target_name_override", LEAF_TLS_HOSTNAME[leaf_ip])]
)
```

**Cert signing cho LEAF mới (PKI workflow):**
- CA hiện hành: `CN=ONAP-SONiC-CA, O=ONAP, OU=Network` (notBefore Apr 4 2026)
- ca.key path: `/home/dis/deploy/acl_policy/certificate/generate/output/ca.key` (KHÔNG phải `/3s-com/...` default)
- Sign cert cho LEAF-N: SAN phải bao gồm `IP:192.168.122.{20+N-1}` để gNMI mTLS verify pass

---

## 7.b Cert role mapping (ai chạy SF với cert gì)

Bridge enforce RBAC bằng cert OU — SF không thể bypass.

| Cert subject OU | Role | Use case |
|---|---|---|
| `OU=internal` hoặc `OU=sdnc` | ADMIN | Push ZT baseline (source=sdnc, broadcast 4 LEAFs); manual delete; SDNC NETCONF path |
| `OU=aws` | OPERATOR | Read + Set, no delete; chỉ source=sdnc |
| `OU=auto` | AGENT | DROP-only, chỉ source=agent; zone-routed |

**Quirk hiện tại (2026-05-31):**
- SF đang chạy với cert `agent-ids/client.crt` (OU=auto, AGENT). Phù hợp cho agent zone-routed enforce.
- Để push **baseline policy** (source=sdnc, broadcast), cần restart SF **tạm thời** với cert `sdnc/client.crt`, push xong → restart back với agent-ids.
- Workflow: `--client-cert sdnc/client.crt --client-key sdnc/client.key --client-ca sdnc/trustedCertificates.crt` → push 21 baseline rules → restart back default.

---

## 8. ConfigDB — persistence

nos-acl-bridge ghi rule vào **Redis DB4** dưới key `NOS_IPTABLES_RULE|{rule-id}`.  
Khi bridge restart (hoặc LEAF reboot), `recovery.py` replay toàn bộ DB4 → `iptables -I FORWARD`.

```
ConfigDB DB4 (Redis)
  NOS_IPTABLES_RULE|zt-web-app-allow   → {action:ACCEPT, src-prefix:10.1.100.0/24, ...}
  NOS_IPTABLES_RULE|zt-default-drop    → {action:DROP, priority:9999, ...}
  NOS_IPTABLES_RULE|agent-10-1-100-55  → {action:DROP, src-prefix:10.1.100.55/32, priority:50}
```

Khác biệt với `07-apply-policy.py` cũ: script đó write thẳng iptables → mất sau reboot.  
gNMI Set qua bridge → ConfigDB → iptables → **survive restart**.

---

## 9. YANG Model (`yang/nos-iptables.yang`)

```
module nos-iptables (namespace: urn:3snos:iptables)
  container acl
    list rule  [key: rule-id]
      leaf rule-id      string  1..64  pattern [a-zA-Z0-9_\-]+
      leaf action       enum    ACCEPT | DROP | RETURN        (mandatory)
      leaf src-ip       string  IPv4 CIDR  e.g. 10.1.100.0/24
      leaf dst-ip       string  IPv4 CIDR
      leaf protocol     enum    tcp | udp | icmp | all        (default: all)
      leaf src-port     uint16  1..65535  (only when tcp/udp)
      leaf dst-port     uint16  1..65535  (only when tcp/udp)
      leaf priority     uint16  1..9999                       (default: 1000)
      leaf source       enum    manual | sdnc | agent         (default: sdnc)
      leaf comment      string  0..256
      leaf ttl-seconds  uint32  0..86400                      (default: 0 = permanent)
```

Bridge nhận field tên `src-prefix` / `dst-prefix` thay vì `src-ip` / `dst-ip`  
(YANG model dùng `src-ip`, bridge normalize về `src-prefix` khi lưu ConfigDB).  
UI hiển thị `rule["src-prefix"] ?? rule["src-ip"]` để handle cả hai.

---

## 10. Docker Compose — Control Plane

```yaml
# /home/dis/deploy/zerotrust/docker-compose.yml
services:
  ids-agent:
    build: ./ids-agent
    ports: ["8766:8766"]
    environment:
      IDS_API_URL: http://10.10.6.238:8765   # Suricata REST
      SF_API_URL:  http://10.10.6.238:9090   # Secure Framework Role API
      AGENT_ADDR:  :8766
    networks: [ztnet]

  intelligence-layer:
    build: ./intelligence-layer
    ports: ["8767:8767"]
    env_file: ./intelligence-layer/.env
    environment:
      IDS_AGENT_URL: http://ids-agent:8766
      REDIS_URL: redis://redis:6379/0          # DB 0 — agent state
      REDIS_EVENTS_URL: redis://redis:6379/1   # DB 1 — events buffer
      POSTGRES_URL: postgresql+asyncpg://ztuser:ztpass@postgres:5432/zerotrust
      LANGFUSE_HOST: http://langfuse:3000
      LANGFUSE_PUBLIC_KEY: pk-lf-zt-public-2026
      LANGFUSE_SECRET_KEY: sk-lf-zt-secret-2026
    depends_on: [ids-agent, redis, postgres, langfuse]
    networks: [ztnet]

  fe:
    build: ./fe
    ports: ["3000:3000"]
    environment:
      AGENT_URL: http://ids-agent:8766
      INTEL_URL: http://intelligence-layer:8767
      NODE_ENV: production
    depends_on: [ids-agent, intelligence-layer]
    networks: [ztnet]

  langfuse:
    image: langfuse/langfuse:2
    ports: ["3001:3000"]                       # UI port 3001, internal 3000
    environment:
      DATABASE_URL: postgresql://ztuser:ztpass@postgres:5432/langfuse
      NEXTAUTH_URL: http://localhost:3001
      NEXTAUTH_SECRET: <secret>
      SALT: <salt>
      ENCRYPTION_KEY: <hex>
      # Bootstrap auto-create org/project/keys at first start
      LANGFUSE_INIT_ORG_ID: zt-org
      LANGFUSE_INIT_PROJECT_ID: zt-agent
      LANGFUSE_INIT_PROJECT_PUBLIC_KEY: pk-lf-zt-public-2026
      LANGFUSE_INIT_PROJECT_SECRET_KEY: sk-lf-zt-secret-2026
      LANGFUSE_INIT_USER_EMAIL: admin@zt.local
      LANGFUSE_INIT_USER_PASSWORD: <password>
    depends_on: [postgres]
    networks: [ztnet]

  redis:
    image: redis:7-alpine
    # 16 logical DBs available (0-15)
    # DB 0 used by intelligence-layer agent state — eval-flushable
    # DB 1 used by EventsStore — preserved across eval (7-day TTL, max 100K)
    networks: [ztnet]

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: zerotrust
      POSTGRES_USER: ztuser
      POSTGRES_PASSWORD: ztpass
    volumes:
      # Init script tạo `langfuse` database trên cùng instance
      - ./postgres-init:/docker-entrypoint-initdb.d:ro
    networks: [ztnet]

networks:
  ztnet:
    driver: bridge
```

---

## 11. Dataplane deploy workflow (V2 — 4 LEAFs)

Sau khi thay đổi code SF hoặc bridge:

```bash
# 1. Sync SF code lên dataplane (V2 path)
rsync -av /home/dis/deploy/zerotrust/secure-framework/ \
      dis@10.10.6.238:/home/dis/deploy/zerotrust/secure-framework/

# 2. Restart SF container (đang chạy bằng docker compose trên gns3vm)
ssh dis@10.10.6.238 "cd /home/dis/deploy/zerotrust && docker compose restart nos-sf"

# 3. Sync bridge code — V2 cần update 4 LEAFs
for leaf in 192.168.122.20 192.168.122.21 192.168.122.22 192.168.122.23; do
  scp /home/dis/deploy/zerotrust/nos-acl-bridge/bridge/validators.py \
      admin@$leaf:/tmp/validators.py
  ssh admin@$leaf "sudo cp /tmp/validators.py /opt/nos-acl-bridge/bridge/ \
                   && sudo systemctl restart nos-acl-bridge"
done

# 4. Rebuild control plane (nếu thay đổi ids-agent/, fe/, intelligence-layer/)
cd /home/dis/deploy/zerotrust
docker compose build <service>
docker compose up -d <service>
```

**Credentials:**
- Dataplane host: `dis@10.10.6.238` / `httt@25`
- LEAF-1..4: `admin@192.168.122.{20,21,22,23}` / `YourPaSsWoRd`
- Kết nối LEAF qua jump host: từ 10.10.6.238, `ssh admin@192.168.122.x`

---

## 12. End-to-end data flow summary

**A. Manual block (Frontend)**
```
[Frontend /policy]
        │ POST /api/ids/autoblock  {src_ip="x.x.x.x"}      ← form hoặc "Manual block" button
        │
[Next.js API rules/route.ts POST]
        │ POST http://ids-agent:8766/autoblock
        │
[IDS Agent autoblockHandler]  pushBlockRule() → body.source="manual"
        │ POST http://10.10.6.238:9090/api/rules
        │
[SF role_api.py _handle_post_rule]
  validate action
  V2 routing: source=="manual" → get_any_client() → default LEAF-1 (192.168.122.20)
        │ gNMI Set /nos-iptables:acl/rule[rule-id=x]  (mTLS OU=auto current default)
        │
[nos-acl-bridge LEAF-1]
  validate_rule() → OK  |  enforce_rbac(role=AGENT, source=manual) → OK (cho action=DROP)
  Redis DB4: NOS_IPTABLES_RULE|x = {...}
  iptables -I FORWARD ... -j DROP
        │
        ✓  Rule active trên LEAF-1 iptables FORWARD
        ✗  Lưu ý V2: manual chỉ vào LEAF-1, không broadcast. Để baseline-style broadcast → source=sdnc.
```

**B. Automated enforcement (Intelligence Layer V3 — schema split)**
```
[Suricata IDS]
        │ EVE JSON alert → Suricata REST :8765
        │
[IDS Agent]  SSE broadcast (also flow events)
        │
[Intelligence Layer]  subscribe SSE :8766/events
        │ Mirror to EventsStore (Redis DB 1, sorted set, 7-day TTL)
        │ V3 Pipeline:
        │   classify_alert (llama3.1-8b)
        │   gather_context (parallel: history + summary + correlation + investigation tools)
        │   cache_lookup (Redis DB 0, 60s TTL)
        │   policy_decision (Stage 1, GLM-4.7, 9 scalar fields, 0% Cerebras 400)
        │   validate_decision (9 safety layers + L1+ injection + L4b off-target)
        │   ★ asyncio.gather:
        │     enforce_path: POST → SF → gNMI → LEAF
        │     reasoning_trace: Stage 2 GLM-4.7 (4 arrays, fail-tolerant)
        │   record (Postgres + Redis + SSE + Langfuse trace)
        │
        │ POST http://ids-agent:8766/rules
        │   {rule_id:"agent-{sha256[:10]}",   ← deterministic, idempotent
        │    action:"DROP", src_ip:"10.1.100.10/32",
        │    dst_ip:"10.1.200.10/32", dst_port:5432, ttl_seconds:3600}
        │
[IDS Agent]  force source="agent" server-side
        │ POST http://10.10.6.238:9090/api/rules
        │
[SF role_api.py]
  V2 routing: source=="agent" → ip_to_leaf("10.1.100.10") → 192.168.122.20 (LEAF-1 owns WEB)
  (Nếu src_ip=10.3.100.x → LEAF-3 v.v. — zone-awareness)
        │ gNMI Set (mTLS OU=auto → AGENT role, action=DROP enforced)
        │
[nos-acl-bridge LEAF-1]
  validate_rule() → OK  |  enforce_rbac(source=agent, action=DROP) → OK
  Redis DB4: NOS_IPTABLES_RULE|agent-... = {...}
  iptables -I FORWARD 1 -s 10.1.100.10/32 -d 10.1.200.10/32 --dport 5432 -j DROP
        │
        ✓  Rule active priority=50 (top of chain — before Default-drop)
        ✓  TTL countdown 3600s → caller (agent) auto-revoke via DELETE
        ✓  Decision logged: Postgres audit + Redis cache + SSE /stream + Langfuse trace
        ✓  V2 efficient: chỉ push 1 LEAF (so với V1 cũng 1 LEAF do zone routing đã có sẵn)
```

**C. SDNC baseline broadcast (V2 mới — defense-in-depth)**
```
[SF restart với --client-cert sdnc/client.crt]  (tạm thời chuyển role ADMIN)
        │
[ZT baseline 21 rules, source="sdnc"]
        │ POST /api/rules × 21 (mỗi rule là 1 cell trong policy matrix V2)
        │
[SF role_api.py]
  V2 routing: source=="sdnc" → broadcast TẤT CẢ 4 LEAFs
        │ gNMI Set × 4 LEAFs (mTLS OU=sdnc → ADMIN role)
        │
[Tất cả LEAFs đồng đều có baseline]
  iptables FORWARD priority=200 (Web-AppGw-allow, Mgt-DbAnlt-allow, Default-drop, ...)
        │
        ✓  Defense-in-depth: nếu agent rule miss, baseline ALLOW/DROP vẫn enforce
        ✓  Rule IDs: CamelCase với dấu gạch ngang (Web-AppGw-allow, Default-drop)
```

**Latency kết quả thực nghiệm (10 runs, 2026-05-05, V3 schema split):**
- **M1 Alert→Decision: avg 8.5s** (range 6.5-12.0s, V2 was 4.75s but had Cerebras 400 outliers 17-26s)
- **Cerebras 400 rate: 0%** (V3 split eliminates parser fail on critical path)
- **M3 Enforcement Correctness: 10/10 (100%)**
- **Confidence: 0.92** consistent across all 10 runs
- **Reasoning quality**: 3 hypotheses + 6.7 reasoning steps + 2.9 alternatives + 3.8 follow-up actions per decision (Stage 2 audit metadata)
