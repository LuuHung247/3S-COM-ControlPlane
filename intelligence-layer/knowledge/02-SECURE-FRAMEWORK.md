# Cơ Sở Tri Thức — Secure Framework Enforcement Plane

**Mục đích**: Tài liệu này được inject vào system prompt của LLM AI security agent. Agent
đọc và hiểu Secure Framework như một enforcement plane production — không phải REST API
rời rạc — bao gồm contract, lifecycle, failure mode, và observability cần thiết để ra
quyết định policy có provenance đầy đủ.

**Nguyên tắc cốt lõi**: SF là single source of truth để áp policy lên SONiC fabric. Agent
KHÔNG SSH vào bất kỳ LEAF/SPINE nào, KHÔNG chạm Redis/iptables trực tiếp. Mọi verify và
mutate đi qua SF REST API.

---

## 1. Architecture & Deployment Topology

### 1.1 Vị trí và vai trò

Secure Framework (SF) là control plane của microsegmentation enforcement. SF không trực
tiếp cầm iptables; nó là cầu nối có policy giữa **2 loại caller hợp lệ** và các leaf
switch nơi nos-acl-bridge đảm nhận việc dịch sang iptables FORWARD.

```
                ┌──────────────────────────────────┐
                │ Caller plane (CHỈ 2 LOẠI)         │
                │   - Operator manual  (OU=sdnc)    │
                │   - AI Agent         (OU=auto)    │
                └──────────────┬───────────────────┘
                               │
              HTTP :9090       │      NETCONF/TLS :6513
              (Role API)       │      (multi-client)
                               ▼
   ┌─────────────────────────────────────────────────────────┐
   │ container nos-sf  (host: gns3vm)                          │
   │   role_api.py → netconf_gnmi_adapter.py → nos_gnmi_pool  │
   │   audit: tamper_logger.py                                 │
   └───────────────────────┬─────────────────────────────────┘
                           │  gNMI/TLS :9339, mTLS, OU-keyed
              ┌────────────┴────────────┐
              ▼                         ▼
      ┌────────────────┐        ┌────────────────┐
      │ LEAF-1 mgmt    │        │ LEAF-2 mgmt    │
      │ 192.168.122.20 │        │ 192.168.122.21 │
      │ nos-acl-bridge │        │ nos-acl-bridge │
      │   - validators │        │   - validators │
      │   - RBAC       │        │   - RBAC       │
      │   - ConfigDB   │        │   - ConfigDB   │
      │   - iptables   │        │   - iptables   │
      └────────────────┘        └────────────────┘
```

Agent KHÔNG truy cập trực tiếp tới hai LEAF box — không SSH, không gNMI client riêng,
không Redis. **Đường vào duy nhất là SF.**

### 1.2 Stack giao thức từ request → entry trong FORWARD chain

1. Caller → SF: HTTP/JSON (port 9090) hoặc NETCONF/TLS (port 6513).
2. SF → bridge: gNMI Set/Get (port 9339) trên kênh mTLS, JSON_IETF encoding.
3. Bridge → ConfigDB: Redis ConfigDB instance #4, key prefix `NOS_IPTABLES_RULE|*`.
4. Bridge → kernel: subprocess `iptables -I/-A/-D FORWARD ...` với comment `nos:<rule-id>`.

Mọi entry trên FORWARD chain do SF tạo ra đều có comment match được regex
`nos:([a-zA-Z0-9_\-]+)` — đây là provenance anchor mà agent phải giữ.

### 1.3 mTLS chain và RBAC điểm

| Hop | Chiều | mTLS | Identity carrier | Ai enforce RBAC |
|---|---|---|---|---|
| Caller → SF NETCONF :6513 | inbound | optional (tắt hôm nay) | Client cert OU | SF NETCONF session |
| Caller → SF Role API :9090 | inbound | server cert only (HTTP) | None | KHÔNG có RBAC ở REST hôm nay |
| SF → LEAF gNMI :9339 | outbound | mandatory | OU trong client cert SF dùng | nos-acl-bridge |

**Quan trọng**: vì SF hiện chạy với cờ `--no-require-client-cert`, mọi REST/NETCONF call
đều rớt vào default role. **Defense-in-depth thực sự nằm ở bridge** — bridge nhận gNMI
mTLS từ SF với cert có OU cụ thể, và bridge mới quyết RBAC.

Trong deployment hôm nay, SF bound outbound gNMI với cert `agent-ids` (OU=auto). Vì thế
mọi rule SF push xuống đều bị bridge stamp role AGENT — bất kể caller là ai.

**⇒ Agent KHÔNG dựa vào "tôi gửi gì thì SF dùng cái đó". Provenance được quyết bởi cert
mà SF bound vào outbound gNMI.**

## 2. REST API Contract

### 2.1 Endpoint surface

| # | Method + Path | Mục đích |
|---|---|---|
| 1 | GET /health | Liveness probe |
| 2 | GET /role, /role/status | SF→LEAF role hiện tại |
| 3 | POST /role/switch/{role} | Đổi outbound role |
| 4 | GET /policy, /policy/{onap_role} | Inspect role policy |
| 5 | POST /policy/{onap_role} | Mutate role policy |
| 6 | GET /sessions, /pool | Quan sát connections |
| 7 | GET /interfaces | Liệt kê Ethernet ports trên LEAF |
| 8 | **GET /api/rules** | List active rules từ tất cả LEAF |
| 9 | **GET /api/rules/{rule_id}** | Get single rule |
| 10 | **POST /api/rules** | Push rule |
| 11 | **DELETE /api/rules/{rule_id}** | Revoke rule |
| 12 | GET /api/logs | Audit log query |

Agent chủ yếu dùng 8, 9, 10, 11 + 1, 12 để verify.

### 2.2 POST /api/rules — Push rule (control contract chính)

**Request body schema**:

| Field (REST) | Type | Required | Default | Server semantics |
|---|---|---|---|---|
| rule_id | string `[a-zA-Z0-9_\-]{1,64}` | YES | — | Khoá định danh duy nhất. Same rule_id = REPLACE. |
| action | enum `DROP\|ACCEPT\|RETURN` | YES | — | Với role AGENT, **buộc phải DROP**, không thì 400. |
| src_ip / src-ip | IPv4 prefix (CIDR) | optional | "" | Bridge normalize sang `src-prefix` ở ConfigDB. |
| dst_ip / dst-ip | IPv4 prefix (CIDR) | optional | "" | Bridge normalize sang `dst-prefix`. |
| protocol | enum `tcp\|udp\|icmp\|all` | optional | "all" | YANG default. |
| src_port | uint16 1–65535 | optional | "" | Chỉ hợp lệ khi protocol ∈ {tcp,udp}. |
| dst_port | uint16 1–65535 | optional | "" | Chỉ hợp lệ khi protocol ∈ {tcp,udp}. |
| priority | uint16 1–9999 | optional | 1000 | **GOTCHA — xem §5.5** |
| source | enum `manual\|sdnc\|agent` | optional | "sdnc" | **SERVER OVERWRITE** nếu role=AGENT → ép "agent" |
| comment | string ≤256 | optional | "" | Append vào comment iptables sau prefix `nos:<rule-id>` |
| ttl_seconds | uint32 0–86400 | optional | 0 | Server LƯU field nhưng **KHÔNG enforce hết hạn**. Caller chịu trách nhiệm DELETE. |

**Server-side overrides**:
- `source` bị overwrite về `"agent"` khi outbound cert OU = auto (cấu hình hôm nay).
- Nếu role là AGENT mà `comment` rỗng, adapter set `comment = "agent:<rule_id>"`.
- Nếu role AGENT push action ≠ DROP → adapter từ chối ngay với error 400 `"AGENT role
  may only push DROP rules"`.

**Success response (HTTP 201)**:
```json
{
  "success": true,
  "rule_id": "agent-block-10-1-100-10",
  "pushed_to": ["192.168.122.20"],
  "rule": { /* normalized rule echo */ },
  "errors": []
}
```

⚠️ `pushed_to` có thể là subset của các LEAF target nếu xảy ra partial failure.
`errors[]` chứa các LEAF fail kèm message. **Agent phải kiểm tra `errors` ngay cả khi
`success=true`.**

**Error responses**:

| Status | Khi nào | Body |
|---|---|---|
| 400 | Body sai schema, role AGENT push non-DROP, validator bridge reject | `{success:false, error:"<message>"}` |
| 500 | Tất cả LEAF fail (gNMI timeout / bridge crash) | `{success:false, error:"<message>"}` |
| 201 với errors non-empty | Partial success | Xem trên |

### 2.3 GET /api/rules

Trả lời từ gNMI Get tới TẤT CẢ LEAF song song (không cache). Format:

```json
{
  "success": true,
  "leaves": {
    "leaf-1": {
      "connected": true,
      "rules": [
        {
          "rule-id": "...",
          "action": "DROP",
          "src-ip": "10.1.100.10/32",
          "dst-ip": "10.1.200.10/32",
          "protocol": "tcp",
          "dst-port": 5432,
          "priority": 50,
          "source": "agent",
          "comment": "agent:...",
          "ttl-seconds": 3600
        }
      ]
    },
    "leaf-2": { ... }
  }
}
```

⚠️ Field name dùng **dấu gạch ngang** (`src-ip`, `dst-ip`, `rule-id`) trong response vì
đến từ gNMI/YANG, trong khi POST request chấp nhận cả underscore và hyphen.

### 2.4 GET /api/rules/{rule_id}

```json
{
  "success": true,
  "rule_id": "agent-block-...",
  "leaves": {
    "leaf-1": { /* rule object hoặc null nếu không có */ },
    "leaf-2": { /* rule object hoặc null */ }
  }
}
```

Dùng để check per-LEAF presence — quan trọng để phát hiện partial state.

### 2.5 DELETE /api/rules/{rule_id}

Broadcast DELETE tới tất cả LEAF. **Idempotent**: rule không tồn tại → vẫn trả 200,
`deleted_from` chỉ chứa LEAF có thực sự xóa.

```json
{
  "success": true,
  "rule_id": "...",
  "deleted_from": ["192.168.122.20", "192.168.122.21"],
  "errors": []
}
```

### 2.6 Idempotency contract

| Action | Behavior |
|---|---|
| POST cùng rule_id 2 lần | **REPLACE** — bridge xóa entry iptables cũ, ghi đè ConfigDB, re-apply. Không trả 409. |
| DELETE rule không tồn tại | 200 OK, `deleted_from=[]`. Không 404. |
| GET rule không tồn tại | 404 với `{success:false, error:"rule not found"}` |

**⇒ Agent có thể an toàn retry POST/DELETE mà không lo conflict.**

## 3. Field Name Mapping — REST ↔ gNMI/YANG ↔ ConfigDB

| REST request body | YANG leaf / gNMI path | ConfigDB hash field | Notes |
|---|---|---|---|
| `rule_id` hoặc `rule-id` | `rule-id` (KEY) | KEY của `NOS_IPTABLES_RULE\|<rule-id>` | Pattern `[a-zA-Z0-9_\-]{1,64}` |
| `action` | `action` | `action` | enum DROP/ACCEPT/RETURN |
| `src_ip` hoặc `src-ip` | `src-ip` | **`src-prefix`** ⚠️ | Bridge normalize trước khi ghi |
| `dst_ip` hoặc `dst-ip` | `dst-ip` | **`dst-prefix`** ⚠️ | Bridge normalize trước khi ghi |
| `protocol` | `protocol` | `protocol` | default "all" |
| `src_port` | `src-port` | `src-port` | only tcp/udp |
| `dst_port` | `dst-port` | `dst-port` | only tcp/udp |
| `priority` | `priority` | `priority` | default 1000 |
| `source` | `source` | `source` | enum (xem §3.1) |
| `comment` | `comment` | `comment` | iptables comment |
| `ttl_seconds` hoặc `ttl-seconds` | `ttl-seconds` | `ttl-seconds` | server không enforce |

### 3.1 Source enum drift (gotcha)

- YANG schema khai source enum = `manual | sdnc | ids-auto`.
- Bridge validator có `VALID_SOURCES = {"sdnc", "agent", "manual"}`.
- **Code wins**: bridge accept `"agent"`, không accept `"ids-auto"` (mismatch nhưng
  runtime theo code).

**⇒ Agent gửi `source="agent"`, không bao giờ `"ids-auto"`.** (Adapter dù sao cũng
overwrite nếu OU=auto.)

### 3.2 Path gNMI

```
origin = "nos-iptables"
path   = /acl/rule[rule-id=<id>]
```

Encoding: JSON_IETF (RFC 7951).

## 4. RBAC Matrix — Cert OU → Role → Permissions

### 4.1 Mapping (CHỈ 2 cert nằm trong scope agent)

| Cert OU | Khi nào dùng | Role | Allowed source | Allowed actions |
|---|---|---|---|---|
| **sdnc** | Manual push — operator đẩy rule thủ công | ADMIN | manual, sdnc, agent | ACCEPT, DROP, RETURN |
| **auto** | Agent push — AI agent tự đẩy rule phản ứng | AGENT | agent only (overwrite) | **DROP only** |

**⇒ Agent là OU=auto, role AGENT, chỉ DROP. Khi cần ALLOW (ví dụ unblock một flow), agent
phải escalate cho operator manual (OU=sdnc) — không tự làm được.**

### 4.2 RBAC enforce ở đâu?

| Layer | Enforce gì hôm nay? |
|---|---|
| SF NETCONF :6513 | Trên giấy có. Hôm nay tắt do `--no-require-client-cert` |
| SF Role API :9090 | KHÔNG — không check cert |
| SF Adapter | **Áp dụng AGENT filter (action=DROP, source=agent)** dựa trên outbound gNMI cert |
| **Bridge (`enforce_rbac`)** | **Layer authoritative** — lấy cert OU của SF từ peer cert, map ra role, áp dụng |

### 4.3 Hệ quả nếu agent gửi action=ACCEPT

→ Adapter reject ngay với HTTP 400 + message `"AGENT role may only push DROP rules"`.

Trong cấu hình hôm nay, AGENT filter là đặc tính bất biến của SF outbound cert, không
phụ thuộc cách caller xác thực với SF.

## 5. Rule Lifecycle & TTL Semantics

### 5.1 Push pipeline (synchronous, end-to-end)

```
T=0   Agent POST /api/rules
T+1   Role API parse body, ip_to_leaf(src_ip) → chọn LEAF target
T+2   Adapter inject AGENT filter (action=DROP, source=agent, comment)
T+3   nos_gnmi_pool.get(SonicRole.ADMIN, leaf_ip) → reuse hoặc tạo gNMI client
T+4   gNMI Set update [(path, JSON_IETF body)]   ← over mTLS
T+5   Bridge nhận → validate_rule() → enforce_rbac() → _write_configdb()
T+6   Bridge apply_rule() → subprocess iptables -I/-A FORWARD
T+7   Bridge _snapshot_db() ghi DB50 với TTL 86400s
T+8   gRPC response → SF
T+9   SF tamper_logger.log() ghi audit
T+10  HTTP 201 trả lại agent
```

**Sync hay async?** Hoàn toàn sync. Khi agent nhận 201, rule đã có trên iptables (hoặc
là failure rồi).

### 5.2 TTL — caller responsibility

⚠️ `ttl_seconds` được lưu trong ConfigDB nhưng **KHÔNG có background thread expire**.
Bridge không có cron, SF không có scheduler. Nếu agent push `ttl_seconds=3600`:

1. Server nhận, lưu, áp.
2. Sau 3600s, rule **vẫn còn**.
3. **Agent phải tự gọi DELETE.**

**Khuyến nghị**: agent maintain in-memory map `{rule_id → expire_at}` và background
coroutine kiểm tra mỗi 30s; gọi DELETE khi past `expire_at`. Idempotent nên retry an
toàn.

### 5.3 Persistence và recovery

| Sự kiện | Hành vi |
|---|---|
| Bridge restart | `recovery.py` chạy: đọc ConfigDB DB4 → so sánh với iptables → áp rule thiếu, xóa orphan, fix chain drift. Rule sống qua restart. |
| LEAF reboot | ConfigDB là Redis trên LEAF — nếu Redis bền, rule còn. SONiC mặc định ConfigDB persistent. |
| SF restart | SF không có in-memory rule registry. Mọi state ở ConfigDB. Restart không làm mất rule. |
| gNMI pool gián đoạn | Pool tự reconnect ở lần Set/Get tiếp theo. Không có pending queue. |
| TTL field | **Không enforce. Persists indefinitely.** |

### 5.4 Iptables rule comment format (provenance anchor)

Bridge build comment theo công thức:
```
nos:<rule-id>[ <user comment>]
```
Ví dụ: `nos:agent-block-10-1-100-10 agent:agent-block-10-1-100-10`.

Regex extract: `_NOS_RE = re.compile(r"nos:([a-zA-Z0-9_\-]+)")`.

### 5.5 Priority & insertion position (GOTCHA LỚN NHẤT)

Bridge translate priority thành position khi build iptables command:

| priority value | iptables command | Vị trí trong chain |
|---|---|---|
| `< 100` | `iptables -I FORWARD 1` | **Top — trước mọi rule khác** |
| `100–999` | `iptables -I FORWARD 2` | Sau rule top, trước phần ACCEPT |
| `≥ 1000` (default 1000) | `iptables -A FORWARD` | **Append — sau cùng** |

⚠️ **Trap với chain default-DROP**: vì chain hiện tại có rule cuối là
`nos:zt-default-drop`, nếu agent push rule `priority=1000` (mặc định) thì rule append
**SAU** default-drop → **im lặng vô hiệu**.

**Khuyến nghị**: AGENT block rule luôn dùng `priority=50`.

### 5.6 Replace semantics

POST cùng rule_id lần 2:
1. Bridge tìm comment cũ `nos:<rule-id>` → `iptables -D` xóa.
2. ConfigDB ghi đè field mới.
3. Bridge `iptables -I/-A` áp lại với position mới.

**⇒ An toàn để retry. Không sinh duplicate.**

## 6. Failure Modes & Recovery Semantics

### 6.1 SF không reach được LEAF (gNMI timeout)

| Field | Giá trị |
|---|---|
| Trigger | LEAF mgmt down, network partition, mTLS handshake fail |
| REST status | 500 (nếu tất cả LEAF fail) hoặc 201 với `errors` non-empty (partial) |
| Body | `{success:false, error:"<host>: <gRPC exception>"}` hoặc `{success:true, errors:[...], pushed_to:[...]}` |
| State | Rule không vào ConfigDB hoặc iptables của LEAF fail |
| Pending queue | **KHÔNG có. SF không retry.** |
| Agent action | (a) treat enforce fail nếu cross-leaf rule cần cả hai; (b) retry sau backoff; (c) verify bằng `GET /api/rules/{rule_id}`. **Tuyệt đối không SSH vào LEAF.** |

### 6.2 Bridge validator reject

| Field | Giá trị |
|---|---|
| Trigger | Sai schema, AGENT push non-DROP, source/role mismatch |
| REST status | 400 |
| Body | `{success:false, error:"<validator message>"}` |
| State | Rule không vào ConfigDB, không vào iptables. **Atomic.** |
| Agent action | **Không retry.** Đây là deterministic reject. Cần fix rule rồi resubmit, hoặc escalate. |

### 6.3 SF crash sau khi LEAF apply rule

| Field | Giá trị |
|---|---|
| State | Rule đã trên LEAF (ConfigDB + iptables) |
| SF restart | Không có in-memory rule registry → SF khởi động sạch |
| GET /api/rules | Vẫn thấy rule vì SF query trực tiếp gNMI Get từ bridge — không cache |
| TTL | Không tick ở đâu cả (xem §5.2) |
| Agent action | Không cần phục hồi state ở SF. Cần re-attach TTL timer của agent nếu agent restart cùng SF |

### 6.4 Partial failure (LEAF-1 ok, LEAF-2 fail)

| Field | Giá trị |
|---|---|
| Trigger | LEAF-2 mgmt link gián đoạn khi đang push cross-leaf rule |
| REST status | **201** (do REST API allow partial) |
| Body | `{success:true, pushed_to:["192.168.122.20"], errors:["192.168.122.21: <reason>"]}` |
| State | Rule có ở LEAF-1, không ở LEAF-2. Defense-in-depth bị xuyên một nửa |
| Agent action | **Phải kiểm `errors` ngay cả khi `success=true`.** Hai lựa chọn: (a) accept partial nếu rule đặt ở source-leaf đủ chặn; (b) **rollback bằng DELETE** rồi retry sau khi LEAF-2 hồi phục. **Khuyến nghị mặc định: rollback.** |

### 6.5 Duplicate rule_id

Đã nêu ở §5.6. Replace semantics, không reject. Agent có thể an toàn retry.

### 6.6 Cert OU không trusted

| Field | Giá trị |
|---|---|
| Trigger | SF outbound dùng cert có OU lạ → bridge từ chối handshake hoặc trả PERMISSION_DENIED |
| REST status | 500 với error message từ gRPC |
| Agent action | **Cấu hình lỗi, không phải data error. Escalate** — agent không có quyền fix cert |

### 6.7 Phân biệt 3 câu hỏi mà agent phải tự trả lời sau mỗi failure

**Q1: Rule có thật sự active trên LEAF không?**
- Cách check: `GET /api/rules/{rule_id}` (đi gNMI Get trực tiếp đến mỗi LEAF).
- Không SSH. Nếu SF không trả lời được → **trạng thái không xác định → escalate.**

**Q2: Nếu fail, fail ở layer nào?**
- HTTP 400 với message khớp validator → bridge layer.
- HTTP 400 với "AGENT role may only..." → adapter layer (chưa tới gNMI).
- HTTP 500 với "deadline exceeded" / "connection refused" → gNMI/network layer.
- HTTP 201 với `errors[]` → partial network failure.

**Q3: Tự recovery hay escalate?**
- 400 deterministic (validator) → fix rule, resubmit.
- 500 gNMI timeout → retry với backoff (60s, 300s). Sau N retry vẫn fail → escalate.
- Partial 201 → rollback DELETE + retry sau backoff.
- SF connection refused → **escalate ngay**. Agent KHÔNG fallback đường khác.

## 7. Observability — Verify Enforcement

**Nguyên tắc**: Agent verify rule bằng SF API. **Không SSH, không redis-cli, không
iptables -L trên LEAF.** Nếu SF không xác nhận được, escalate — không tự verify đường
khác.

### 7.1 Health probe
```
GET http://<sf-host>:9090/health
→ {status:"ok", service:"role-api", mode:"single-client"|"multi-client"}
```
Agent dùng để verify SF process liveness trước khi gửi action có cost cao.

### 7.2 Pool status
```
GET /pool
→ {port:9339, leaves:{leaf-1:{ip:"...", connections:{admin:true, operator:false}}, ...}}
```
Trước khi push cross-leaf rule, agent nên check `connections.admin == true` cho cả hai
LEAF.

### 7.3 Active rule listing
```
GET /api/rules        → toàn bộ rule trên cả hai LEAF (gNMI Get live)
GET /api/rules/{id}   → single rule, per-LEAF status
```
**Đặc điểm**:
- **Live, không cache.** Mỗi GET đi gNMI Get mới.
- Field name dùng dấu gạch ngang (YANG-style).
- Phân biệt `leaves[X].connected=false` để biết LEAF nào unreachable lúc query.
- Không có status field "pending"/"expired" — rule có nghĩa là active. Không có thì là
  không có.

### 7.4 Audit log
```
GET /api/logs?limit=50&event_type=gnmi&severity=info
GET /api/logs/tampering
GET /api/logs/stats
```
Mỗi entry có `transaction_id` (UUID), `user_identity{cn,ou,ip,role}`, `request_hash`,
`data_before_hash`, `data_after_hash`, `integrity_signature` (HMAC-SHA256).

⚠️ In-memory log có cap 1000 entries. Cho audit dài hơn, dùng `GET /api/logs/tampering`
(đọc từ file `audit_logs/tamper_logs.json`).

## 8. Invariants — Bất biến mà agent KHÔNG được vi phạm

### 8.1 Hành động cấm

| Invariant | Ai enforce | Hậu quả nếu vi phạm |
|---|---|---|
| KHÔNG SSH vào LEAF/SPINE | Convention | Phá single-source-of-truth contract |
| KHÔNG truy cập Redis/ConfigDB trực tiếp | Convention | Như trên |
| KHÔNG chạy iptables trên switch | Convention | Như trên |
| KHÔNG push qua gNMI client riêng (bypass SF) | Bridge cert check | gRPC PERMISSION_DENIED |
| **KHÔNG gửi action=ACCEPT hoặc RETURN** | SF adapter + bridge enforce_rbac | HTTP 400 |
| KHÔNG gửi source ≠ "agent" | SF adapter overwrite | Silent overwrite |
| **KHÔNG sửa/xóa rule có comment `nos:zt-*`** | Convention, không enforce code | Phá baseline ZT |
| KHÔNG sửa rule không có comment | Convention | Phá rule operator manual |
| **KHÔNG dùng `priority ≥ 1000` cho block rule** | Không enforce | Rule append SAU `nos:zt-default-drop`, **im lặng vô hiệu** |
| KHÔNG dùng `priority < 1` hoặc `> 9999` | YANG range | Validator reject 400 |
| KHÔNG đặt `src_ip` thuộc NEVER_BLOCK list | Không enforce ở SF | **Tự tay mất control plane / SF / IDS / SVI gateway** |

### 8.2 NEVER_BLOCK list (agent tự enforce)

Agent **bắt buộc** kiểm `src_ip` không thuộc các CIDR sau trước khi xây rule DROP:

- `127.0.0.0/8` — loopback
- `192.168.122.0/24` — mgmt OOB (block sẽ self-DoS)
- `10.10.6.0/24` — out-of-band reach
- `10.1.100.1/32`, `10.1.200.1/32`, `10.2.100.1/32`, `10.2.50.1/32` — SVI gateways
- `10.2.50.10/32` — mgt-01 (block sẽ giết audit/scenario controller)
- `192.168.122.205/32` — IDS Suricata (block sẽ cắt perception của agent)

### 8.3 Provenance invariant

Mọi rule agent push phải có comment chứa prefix `agent:` hoặc `nos:agent-` để dễ phân
biệt với baseline.

### 8.4 Idempotency invariant

Agent giữ map `{rule_id → (expire_at, leaves_pushed_to)}`. Mỗi rule_id duy nhất per
logical block. Pattern khuyến nghị:

```
rule_id = f"agent-{src_ip_safe}-to-{dst_ip_safe}-port-{dst_port}"
# ví dụ: "agent-10-1-100-10-to-10-1-200-10-port-5432"
```

Cùng tuple sinh cùng rule_id → POST refresh = TTL extend mặc định.

### 8.5 TTL invariant

Mọi rule agent push có `ttl_seconds > 0` và **agent tự DELETE khi hết hạn**. Không có
rule "permanent" do agent — đó là quyền của ADMIN human (OU=sdnc).

### 8.6 Single-source-of-truth invariant

SF là đường vào duy nhất để verify và mutate state. **Nếu SF không trả lời → trạng thái
không xác định → escalate, không bypass.** Agent không có "đường khác" — đây là kỷ luật
cốt lõi của enforcement plane.
