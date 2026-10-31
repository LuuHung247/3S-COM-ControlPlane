# Cơ Sở Tri Thức Mạng — Trung Tâm Dữ Liệu Zero Trust (V2)

**Mục đích**: Mô tả chính thức về data center network V2 mà AI security agent đang quản trị.
Mọi sự kiện đều ở thì hiện tại. Tài liệu này là nguồn tri thức để agent suy luận khi
correlate alert từ IDS với policy decisions và quyết định push enforcement action.

**V2 expansion (2026-05-31)**: nâng cấp từ 1-spine/2-leaf/4-zone/4-host (V1) lên
**2-spine / 4-leaf / 8-zone / 16-host Clos DCN**. Đầy đủ ECMP underlay, microsegmentation
matrix 8×8, 29 SID Suricata, passive SPAN từ 4 LEAF về 1 IDS.

---

## 1. Tư Thế Bảo Mật Mạng

Đây là trung tâm dữ liệu áp dụng vi-phân đoạn Zero-Trust, vận hành trên kiến trúc fabric
Spine-Leaf full Clos hai tầng L3 (mỗi LEAF nối CẢ HAI SPINE, ECMP qua cả 2 đường). Mọi
luồng east-west đều bị đánh giá theo policy ngay tại leaf switch. Tư thế mặc định là
deny; chỉ những application flow được mô hình hóa tường minh mới được phép. Fabric
mang workload sản xuất qua **tám vùng tin cậy** (trust zones), mỗi vùng có một ranh
giới bảo mật riêng biệt.

Fabric chạy NOS phần mềm (SONiC-VS, không có ASIC), vì vậy việc thực thi chính sách diễn ra
ở tầng kernel netfilter của mỗi leaf. Phát hiện chạy out-of-band trên IDS được tap-mirror
(Suricata 8.0). Enforcement và detection được tách rời: một packet có thể bị IDS phát
hiện ngay cả khi đã bị drop tại leaf — đây là chủ ý thiết kế, để agent vẫn nhìn thấy vi
phạm chính sách kể cả khi chính sách đã chặn rồi.

## 2. Các Vùng Tin Cậy (8 zones)

| Vùng | CIDR | LEAF | VLAN | SVI | Mục đích | Mức tin cậy |
|---|---|---|---|---|---|---|
| WEB | 10.1.100.0/24 | LEAF-1 | 100 | 10.1.100.1 | Tầng web public-facing (north-south ingress) | Không tin cậy |
| DB-OLTP | 10.1.200.0/24 | LEAF-1 | 200 | 10.1.200.1 | Database giao dịch (OLTP) | Crown-jewel |
| APP-CORE | 10.2.100.0/24 | LEAF-2 | 100 | 10.2.100.1 | Business-logic core | Tin cậy nội bộ |
| MGT | 10.2.50.0/24 | LEAF-2 | 300 | 10.2.50.1 | Management plane | Đặc quyền |
| APP-GW | 10.3.100.0/24 | LEAF-3 | 100 | 10.3.100.1 | Application gateway / reverse proxy | Tin cậy nội bộ |
| DB-ANALYTICS | 10.3.200.0/24 | LEAF-3 | 200 | 10.3.200.1 | Database analytics — sink-only | Crown-jewel |
| WORKER | 10.4.100.0/24 | LEAF-4 | 100 | 10.4.100.1 | Async job worker | Tin cậy nội bộ |
| MONITORING | 10.4.200.0/24 | LEAF-4 | 200 | 10.4.200.1 | Quan sát / metrics scrape | Đặc quyền read-only |

Mô hình tương tác giữa các vùng (intended legitimate chain):

```
External ─→ WEB ─→ APP-GW ─→ APP-CORE ─┬─→ WORKER ─→ DB-OLTP ─→ DB-ANALYTICS
                                       └─→ DB-OLTP
                                       └─→ DB-ANALYTICS
                MONITORING (scrape mọi tier trừ MGT)
                MGT (audit, cấu hình mọi nơi trừ chính nó)
```

Bất biến quan trọng:
- WEB phải đi qua APP-GW; KHÔNG được skip vào APP-CORE hay DB.
- APP-GW phải đi qua APP-CORE; KHÔNG được skip vào DB.
- WORKER chỉ được nói với DB-OLTP (không phải DB-ANALYTICS).
- DB-OLTP gần như là sink — chỉ outbound đến DB-ANALYTICS (replication).
- DB-ANALYTICS là pure sink — KHÔNG initiate outbound bao giờ.
- MONITORING quan sát mọi tier nhưng KHÔNG được chạm MGT (control plane segregation).
- MGT có full access mọi nơi (compliance design).

## 3. Topology Vật Lý & Logic

### 3.1 Underlay (L3 P2P /30, full Clos)

8 link điểm-điểm: mỗi LEAF có 2 uplink (sang SPINE-1 và SPINE-2).

| Link | Subnet | SPINE side | LEAF side | LEAF NIC |
|---|---|---|---|---|
| SPINE-1 ↔ LEAF-1 | 10.0.1.0/30 | 10.0.1.1 | 10.0.1.2 | eth0 |
| SPINE-1 ↔ LEAF-2 | 10.0.2.0/30 | 10.0.2.1 | 10.0.2.2 | eth0 |
| SPINE-1 ↔ LEAF-3 | 10.0.3.0/30 | 10.0.3.1 | 10.0.3.2 | eth0 |
| SPINE-1 ↔ LEAF-4 | 10.0.4.0/30 | 10.0.4.1 | 10.0.4.2 | eth0 |
| SPINE-2 ↔ LEAF-1 | 10.0.5.0/30 | 10.0.5.1 | 10.0.5.2 | eth5 |
| SPINE-2 ↔ LEAF-2 | 10.0.6.0/30 | 10.0.6.1 | 10.0.6.2 | eth5 |
| SPINE-2 ↔ LEAF-3 | 10.0.7.0/30 | 10.0.7.1 | 10.0.7.2 | eth5 |
| SPINE-2 ↔ LEAF-4 | 10.0.8.0/30 | 10.0.8.1 | 10.0.8.2 | eth5 |

ECMP: mỗi LEAF cài route `ip route replace 10.X.0.0/16 nexthop via SPINE1-nh dev eth0 nexthop via SPINE2-nh dev eth5`.

### 3.2 Switches (mgmt / OOB)

| Switch | Mgmt IP | Vai trò |
|---|---|---|
| SONIC-SPINE | (mgmt qua NAT1) | Pure transit — không thực thi policy |
| SONIC-SPINE-2 | console-only (V2) | Pure transit (path thứ 2) |
| SONIC-LEAF-1 | 192.168.122.20 | Enforcement WEB + DB-OLTP. gNMI :9339 |
| SONIC-LEAF-2 | 192.168.122.21 | Enforcement APP-CORE + MGT. gNMI :9339 |
| SONIC-LEAF-3 | 192.168.122.22 | Enforcement APP-GW + DB-ANALYTICS. gNMI :9339 (V2) |
| SONIC-LEAF-4 | 192.168.122.23 | Enforcement WORKER + MONITORING. gNMI :9339 (V2) |

## 4. Danh Mục Tài Sản (16 hosts)

Mỗi vùng có **2 host redundant** (`*-01` ở `.10`, `*-02` ở `.11`). Cron-driven east-west
chỉ phát ra từ `*-01` để giữ pattern đơn giản; `*-02` standby listener.

| Host pattern | IP primary | IP secondary | Vùng | Service |
|---|---|---|---|---|
| web-* | 10.1.100.10 | .11 | WEB | TCP/80 banner, TCP/22 |
| db-oltp-* | 10.1.200.10 | .11 | DB-OLTP | TCP/5432 pg-mock, TCP/22 |
| app-core-* | 10.2.100.10 | .11 | APP-CORE | TCP/8090 banner, TCP/22 |
| mgt-* | 10.2.50.10 | .11 | MGT | TCP/22 |
| app-gw-* | 10.3.100.10 | .11 | APP-GW | TCP/8080 banner, TCP/22 |
| db-analytics-* | 10.3.200.10 | .11 | DB-ANALYTICS | TCP/5432 pg-mock, TCP/22 |
| worker-* | 10.4.100.10 | .11 | WORKER | TCP/8082 banner, TCP/22 |
| monitoring-* | 10.4.200.10 | .11 | MONITORING | TCP/9090 banner, TCP/22 |

**Lưu ý implementation service**: TCP listener đều là responder banner-style hoặc
pg-mock SQL-responder (socat exec script — trả `PG_OK row_count=42` cho query thông thường,
hoặc ~80 rows giả khi thấy `JOIN`/`SELECT *`). Agent KHÔNG được giả định HTTP keep-alive,
postgres auth handshake, hoặc các hành vi protocol-stateful khác. Mô hình phát hiện là
flow-level, không phải protocol-aware.

## 5. Lưu Lượng East-West Đường Cơ Sở (Behavioral Fingerprint)

Cron-driven generators trên 16 host phát ra ~10 chuỗi luồng/phút. Xem `infra/baselines.md`
cho định lượng đầy đủ. Tóm tắt:

| Cron source → đích | Tần suất | Mục đích |
|---|---|---|
| WEB → APP-GW:8080 | 30s | Tầng web proxy sang gateway |
| APP-GW → APP-CORE:8090 | 30s | Gateway forward sang core |
| APP-CORE → DB-OLTP:5432 (SELECT users) | 30s | OLTP transaction |
| APP-CORE → WORKER:8082 | 45s | Job dispatch |
| WORKER → DB-OLTP:5432 (INSERT log) | 45s | Job persistence |
| APP-CORE → DB-ANALYTICS:5432 (SELECT report) | 60s | Report query |
| DB-OLTP → DB-ANALYTICS:5432 (JOIN replicate) | 2 phút | ETL replication |
| MONITORING → 6 đích (scrape) | 60s | Metrics scrape WEB/GW/CORE/WORKER/DB-OLTP/DB-ANLT |
| MGT → 4 đích :22 (audit rotating) | 2 phút | SSH audit |

**Ước lượng khối lượng**: ~250-500 east-west flow/phút ở steady-state. MGT initiate sinh
ra ~1-2 P4 audit alert/phút (SID 9000080) — đây KHÔNG phải sự cố, là bằng chứng
visibility bắt buộc. MONITORING tương tự (SID 9000081, rate-limited 1/300s).

### 5.1 Những thứ KHÔNG nằm trong baseline (cần điều tra)

- Bất kỳ luồng từ DB-OLTP → !DB-ANALYTICS (DB-OLTP gần như sink)
- Bất kỳ luồng từ DB-ANALYTICS (pure sink, không bao giờ initiate)
- WEB initiate đến DB-OLTP / DB-ANALYTICS / APP-CORE / WORKER / MGT / MON
- APP-GW initiate đến WEB (đảo chiều), WORKER, MGT, MON, DB direct
- APP-CORE initiate đến WEB / APP-GW (đảo chiều) hoặc MGT / MON
- WORKER initiate đến !DB-OLTP (lateral)
- MONITORING → MGT (control-plane segregation breach)

## 6. Mặt Phẳng Thực Thi (Policy Layer)

### 6.1 Ma trận chính sách 8×8 (xem `infra/policy-matrix.md` cho machine-readable form)

| Nguồn ↓ \ Đích → | WEB | APP-GW | APP-CORE | WORKER | DB-OLTP | DB-ANLT | MON | MGT |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **WEB** | — | A | D | D | D | D | D | D |
| **APP-GW** | D | — | A | D | D | D | D | D |
| **APP-CORE** | D | D | — | A | A | A | D | D |
| **WORKER** | D | D | D | — | A | D | D | D |
| **DB-OLTP** | D | D | D | D | — | A | D | D |
| **DB-ANALYTICS** | D | D | D | D | D | — | D | D |
| **MONITORING** | A | A | A | A | A | A | — | D |
| **MGT** | A | A | A | A | A | A | A | — |

A=ALLOW, D=DENY. 20 ALLOW cell, 36 DENY cell, 8 diagonal n/a. Reply traffic của bất kỳ
ALLOW flow nào được phép qua stateful conntrack.

### 6.2 Cài đặt enforcement

Hiện thực bằng Linux netfilter `iptables FORWARD` chain trên **mỗi LEAF (4 cái)**.
Secure Framework (SF) đẩy đầy đủ 20 ALLOW + 1 Default-drop tới tất cả 4 LEAF (defense-in-depth
full broadcast). Chain mỗi LEAF có:

```
1. ACCEPT  ctstate ESTABLISHED,RELATED      # conntrack reply
2. ACCEPT  10.1.100.0/24 → 10.3.100.0/24    # nos:Web-AppGw-allow
3. ACCEPT  10.3.100.0/24 → 10.2.100.0/24    # nos:AppGw-AppCore-allow
   ... (18 ALLOW khác từ matrix) ...
21. DROP                                     # nos:Default-drop (priority 9999 → cuối chain)
```

**Bất biến thứ tự**: Default-drop PHẢI ở cuối; ALLOW PHẢI nằm trên Default-drop. Khi
bridge bị bug placement Default-drop ở đầu chain → toàn bộ east-west bị DROP (đã observe
và workaround thủ công 2026-05-31).

### 6.3 Quy ước gắn nhãn rule

Mọi rule iptables đều mang annotation comment:
- `nos:Web-AppGw-allow`, `nos:AppCore-DbOltp-allow`, `nos:Default-drop`, etc — chính sách V2 8×8 SF push (OU=sdnc). Agent KHÔNG được sửa.
- `nos:zt-*` — legacy V1 prefix (deprecated; còn giữ cho backward compat).
- `nos:agent-<hash>` — AI agent chèn động khi phản ứng alert. Agent sở hữu, có TTL, có thể DELETE.
- (không gắn nhãn) — rule thủ công của operator. Agent KHÔNG được đụng vào nếu chưa escalate.

### 6.4 Mapping vùng → leaf (helper quyết định)

```python
LEAF_OF_PREFIX = {
    "10.1.": "SONIC-LEAF-1",   # WEB + DB-OLTP
    "10.2.": "SONIC-LEAF-2",   # APP-CORE + MGT
    "10.3.": "SONIC-LEAF-3",   # APP-GW + DB-ANALYTICS
    "10.4.": "SONIC-LEAF-4",   # WORKER + MONITORING
}
ZONE_PREFIX = {
    "10.1.100.": "WEB",        "10.1.200.": "DB-OLTP",
    "10.2.100.": "APP-CORE",   "10.2.50.":  "MGT",
    "10.3.100.": "APP-GW",     "10.3.200.": "DB-ANALYTICS",
    "10.4.100.": "WORKER",     "10.4.200.": "MONITORING",
}
```

## 7. Mặt Phẳng Phát Hiện (IDS)

### 7.1 Capture (4 NIC mirror)

Suricata IDS nhận traffic được mirror từ **cả 4 LEAF** qua `tc clsact` + `mirred`. Mỗi
LEAF có một cable eth4 → một NIC của IDS:

| LEAF | LEAF mirror NIC | ↔ | IDS NIC | af-packet cluster |
|---|---|---|---|---|
| LEAF-1 | eth4 | ↔ | IDS:eth0 | cluster-id 98 |
| LEAF-2 | eth4 | ↔ | IDS:eth1 | cluster-id 99 |
| LEAF-3 | eth4 | ↔ | IDS:eth3 | cluster-id 100 |
| LEAF-4 | eth4 | ↔ | IDS:eth4 | cluster-id 101 |

Capture là **bất đối xứng** (chỉ thấy chiều SYN khởi tạo trên LEAF nguồn; reply thấy
trên LEAF đích → khác cluster). Hệ quả: `flow:to_server` không tin cậy. Tất cả policy
rule đều **chỉ-SYN** (`flags:S`).

### 7.2 Tập rule đang hoạt động (29 SIDs V2)

Xem `infra/sids.md` cho danh sách đầy đủ + MITRE mapping. Tóm tắt theo category:

| Cat | SID range | Số rule | Mô tả | Priority |
|---|---|---|---|---|
| 1. V2 policy violations (8×8 DENY cells) | 9000001–9000013 | 13 | Mỗi rule encode 1 cell DENY của matrix §6.1 | P1 (12), P2 (1) |
| 2. Recon — Yatesbury | 9000040–9000044 | 5 | ICMP sweep, port scan vertical/key/UDP, multi-stage chain | P3 |
| 3. Flooding — Yatesbury | 9000050–9000052 | 3 | SYN flood single, SYN DDoS contribution, UDP flood | P2 |
| 4. C2 / tunneling / exfil | 9000060–9000062 | 3 | Beacon, DNS amp, DB-exfil to external | P1/P2 |
| 5. DB content — Yatesbury L7 | 9000070–9000072 | 3 | UNION SELECT, OR 1=1, destructive SQL | P1 |
| 6. Audit (low-rate) | 9000080–9000081 | 2 | MGT-initiated session, MON aggregation | P4 |

Defense-in-depth: hầu hết violation fire 2 SID — 1 zone-specific + 1 generic (9000011 MGT-inbound, 9000012 DB-conn). Agent correlate: cùng flow + 2 SID = high confidence; 1 SID = lower.

### 7.3 Mapping mức độ → phản ứng

| Mức | Hành động mặc định | TTL block |
|---|---|---|
| P1 | Auto-block source IP trên LEAF nguồn + LEAF đích (defense-in-depth) | 3600s |
| P2 | Auto-block source IP trên LEAF nguồn | 1800s |
| P3 | Log + correlate window 5 phút | — |
| P4 | Log only (audit baseline) | — |

### 7.4 API Alert (REST + SSE từ IDS)

Xem `02-SECURE-FRAMEWORK.md` cho contract đầy đủ.

```
GET  http://10.10.6.238:8765/health
GET  http://10.10.6.238:8765/alerts?last=N&since=ISO
GET  http://10.10.6.238:8765/alerts/clear
GET  http://10.10.6.238:8765/flows?last=N
GET  http://10.10.6.238:8765/stream                  # SSE
GET  http://10.10.6.238:8766/events                  # SSE bridge
```

## 8. Mô Hình Mối Đe Dọa Mà Agent Phòng Ngự

Agent giả định vành đai đã bị xuyên thủng và phải ngăn chặn blast radius east-west. Các
kịch bản đe dọa V2 (xem `infra/kill-chains.md` cho stage-by-stage):

1. **WEB tier bị compromise (compromise-web-dbbypass)** — pivot trực tiếp sang DB hoặc skip APP-GW. SIDs: 9000001, 9000002, 9000003, 9000012.
2. **APP-GW bị compromise (compromise-appgw-dbbypass)** — skip APP-CORE, gọi DB direct. SIDs: 9000004, 9000005, 9000012.
3. **APP-CORE bị compromise (lateral hoặc exfil)** — đảo chiều WEB/GW, hoặc bulk SELECT + outbound. SIDs: 9000006, 9000007, 9000062, 9000070-72.
4. **WORKER lateral move** — gọi !DB-OLTP. SID: 9000008, 9000013.
5. **DB-OLTP exfil / C2** — initiate outbound non-DB-ANLT. SID: 9000009, 9000060, 9000062.
6. **DB-ANALYTICS sink violation** — bất kỳ outbound nào. SID: 9000010, 9000062.
7. **MONITORING tier compromise (control-plane breach attempt)** — MON → MGT. SID: 9000011.

Agent **KHÔNG** coi traffic xuất phát từ MGT (SID 9000080) hoặc MON scrape (SID 9000081)
là khả nghi — đây là audit baseline.

## 9. Bất Biến Mạng Mà Agent Phải Bảo Toàn

Xem `infra/invariants.md` cho danh sách đầy đủ + rationale. Tóm tắt:

**Không bao giờ block** (NEVER_BLOCK CIDRs):
- 127.0.0.0/8 (loopback), 192.168.122.0/24 (mgmt OOB), 10.10.6.0/24 (control plane reach)
- 8 SVI gateway: 10.1.100.1, 10.1.200.1, 10.2.100.1, 10.2.50.1, 10.3.100.1, 10.3.200.1, 10.4.100.1, 10.4.200.1
- 4 LEAF mgmt: 192.168.122.20-23
- IDS: 192.168.122.205
- MGT hosts: 10.2.50.10, 10.2.50.11
- MON hosts: 10.4.200.10, 10.4.200.11 (kill block sẽ giết observability)

**Không bao giờ sửa**:
- Rule có comment `nos:*` baseline (SF-pushed: Web-, AppGw-, AppCore-, Worker-, DbOltp-, DbAnlt-, Mon-, Mgt-, Default-, hoặc legacy zt-)
- Rule operator không gắn nhãn

**Luôn có thể đảo ngược**:
- Mọi rule do agent đẩy đều gắn `nos:agent-<hash>`, có TTL, recover bằng `DELETE /api/rules/{id}`.

## 10. Bề Mặt Vận Hành Cho Agent

| Năng lực | Cơ chế |
|---|---|
| Đọc alert | HTTP GET đến API IDS (:8765/8766) |
| Đọc trạng thái fabric | SF API `GET /api/rules` (live gNMI Get từ 4 LEAF; KHÔNG SSH) |
| Đẩy enforcement | SF API `POST /api/rules` (qua proxy ids-agent) |
| Gỡ enforcement | SF API `DELETE /api/rules/{id}` |
| Sự thật về inventory | Tài liệu này + `infra/*.md` (knowledge base) |
| Sự thật về live state | `GET /api/rules` trên SF |

Agent suy luận trên: **(alert stream) × (knowledge này) × (live SF state) → quyết định
policy có gắn nhãn provenance**. Single source of truth invariant — agent KHÔNG có
fallback path nào khác ngoài SF cho enforcement.
