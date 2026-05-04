# Cơ Sở Tri Thức Mạng — Trung Tâm Dữ Liệu Zero Trust

**Mục đích**: Mô tả chính thức về data center network mà AI security agent đang quản trị.
Mọi sự kiện đều ở thì hiện tại. Tài liệu này là nguồn tri thức để agent suy luận khi
correlate alert từ IDS với policy decisions và quyết định push enforcement action.

---

## 1. Tư Thế Bảo Mật Mạng

Đây là trung tâm dữ liệu áp dụng vi-phân đoạn Zero-Trust, vận hành trên kiến trúc fabric
Spine-Leaf hai tầng L3. Mọi luồng east-west đều bị đánh giá theo policy ngay tại leaf
switch. Tư thế mặc định là deny; chỉ những application flow được mô hình hóa tường minh
mới được phép. Fabric mang workload sản xuất qua bốn vùng tin cậy (trust zones), mỗi
vùng có một ranh giới bảo mật riêng biệt.

Fabric chạy NOS phần mềm (SONiC, không có ASIC), vì vậy việc thực thi chính sách diễn ra
ở tầng kernel netfilter của mỗi leaf. Phát hiện chạy out-of-band trên IDS được tap-mirror
(Suricata 8.0). Enforcement và detection được tách rời: một packet có thể bị IDS phát
hiện ngay cả khi đã bị drop tại leaf — đây là chủ ý thiết kế, để agent vẫn nhìn thấy vi
phạm chính sách kể cả khi chính sách đã chặn rồi.

## 2. Các Vùng Tin Cậy

| Vùng | CIDR | Mục đích | Mức tin cậy |
|---|---|---|---|
| WEB | 10.1.100.0/24 | Tầng web public-facing — phục vụ HTTP cho người dùng (north-south ingress) | Không tin cậy theo thiết kế (lộ ra Internet) |
| DB | 10.1.200.0/24 | Tầng database — lưu trạng thái persistent, dữ liệu nhạy cảm | Crown-jewel; không outbound |
| APP | 10.2.100.0/24 | Tầng business-logic / ứng dụng — bridge request từ WEB sang DB | Tin cậy nội bộ |
| MGT | 10.2.50.0/24 | Mặt phẳng vận hành — monitoring, audit, configuration | Đặc quyền; full access theo thiết kế |

Mô hình tương tác giữa các vùng (intended):

```
External ─→ WEB ─→ APP ─→ DB
                    ↑
                   MGT (audit, scrape, cấu hình)
```

WEB không bao giờ chạm DB trực tiếp. DB không bao giờ initiate outbound. APP làm trung
gian cho mọi truy cập DB. MGT có toàn quyền đọc/SSH mọi nơi (yêu cầu compliance về
visibility).

## 3. Topology Vật Lý & Logic

**Underlay (L3 P2P /30)**:
- SPINE ↔ LEAF-1: 10.0.1.0/30 (SPINE side .1, LEAF-1 side .2)
- SPINE ↔ LEAF-2: 10.0.2.0/30 (SPINE side .1, LEAF-2 side .2)

**Overlay (VLAN-routed tại leaf)**:
- LEAF-1 chứa WEB+DB (Vlan100=WEB SVI 10.1.100.1, Vlan200=DB SVI 10.1.200.1)
- LEAF-2 chứa APP+MGT (Vlan100=APP SVI 10.2.100.1, Vlan300=MGT SVI 10.2.50.1)

**Switches (mgmt / OOB)**:

| Switch | Mgmt IP (eth0) | Vai trò |
|---|---|---|
| SONIC-SPINE | 192.168.122.10 | Pure transit — không thực thi policy |
| SONIC-LEAF-1 | 192.168.122.20 | Điểm enforcement cho vùng WEB+DB |
| SONIC-LEAF-2 | 192.168.122.21 | Điểm enforcement cho vùng APP+MGT |

## 4. Danh Mục Tài Sản (Workload Hosts)

Mỗi vùng có đúng một workload server. Đây là chủ ý — single-host-per-zone đơn giản hóa
mô hình tin cậy: CIDR của zone map 1:1 với một danh tính tenant.

| Host | IP | Vùng | Vai trò | Service đang lắng nghe |
|---|---|---|---|---|
| web-01 | 10.1.100.10 | WEB | HTTP frontend | TCP/80 (HTTP banner), TCP/22 (sshd) |
| db-01 | 10.1.200.10 | DB | SQL backend (tương thích wire Postgres) | TCP/5432 (SQL handler), TCP/22 (sshd) |
| app-01 | 10.2.100.10 | APP | Business logic | TCP/8080 (HTTP API), TCP/22 (sshd) |
| mgt-01 | 10.2.50.10 | MGT | Host vận hành | TCP/22 (sshd) duy nhất |

**Lưu ý implementation service**: Tất cả TCP listener đều là responder banner-style tối
giản — chúng xác nhận connection được thiết lập nhưng KHÔNG implement đầy đủ ngữ nghĩa
protocol. Agent KHÔNG được giả định HTTP keep-alive, postgres auth handshake, hoặc các
hành vi protocol-stateful khác. Mô hình phát hiện là flow-level, không phải
protocol-aware.

## 5. Lưu Lượng East-West Đường Cơ Sở (Behavioral Fingerprint)

Đây là traffic ứng dụng ở trạng thái ổn định. Bất cứ thứ gì khớp các pattern này là vận
hành bình thường. Bất cứ thứ gì nằm ngoài tập này (mà vẫn trên allowed flow) thì hoặc
là: (a) hành vi ứng dụng mới, hoặc (b) xâm nhập. Agent dùng tập này để baseline.

### 5.1 Lưu lượng ứng dụng

| Luồng | Nguồn | Đích | Tần suất | Mục đích |
|---|---|---|---|---|
| WEB→APP API call | web-01 | app-01:8080 | mỗi 30s | Tầng web proxy request người dùng sang tầng app (đường "shopper") |
| APP→DB query | app-01 | db-01:5432 | mỗi 30s | Tầng app phát 4 dạng query: SELECT users / SELECT orders / INSERT log / UPDATE session |
| APP→DB readiness | app-01 | db-01:5432 | mỗi 60s | Health-check connectivity DB từ phía app |

### 5.2 Lưu lượng quản trị/quan sát (xuất phát từ MGT)

| Luồng | Đích | Tần suất | Mục đích |
|---|---|---|---|
| mgt-scrape | web-01:80, app-01:8080, db-01:5432 | mỗi 60s | Probe TCP service-health |
| mgt-audit | web-01:22, app-01:22, db-01:22 (xoay vòng) | mỗi 2 phút | Compliance — SSH login + capture uptime |
| mgt-logpull | app-01:22 | mỗi 5 phút | Lấy log qua SSH từ tầng app |

**Ước lượng khối lượng**: ~120 east-west flow/phút ở steady-state. Việc MGT initiate
sinh ra ~1 audit alert/phút theo thiết kế (xem §7, SID 9000020) — đây KHÔNG phải sự cố,
đây là bằng chứng visibility bắt buộc.

### 5.3 Những thứ KHÔNG nằm trong baseline

Nếu agent quan sát thấy bất kỳ điều nào sau đây, đó là bất thường:
- Bất kỳ luồng nào xuất phát từ DB đi đến đâu cũng vậy
- WEB initiate đến DB trên bất kỳ port nào
- APP initiate đến WEB trên bất kỳ port nào (đảo chiều — dấu hiệu app bị compromise)
- WEB hoặc APP initiate đến MGT trên bất kỳ port nào

## 6. Mặt Phẳng Thực Thi (Policy Layer)

### 6.1 Ma trận chính sách (zone → zone)

| Nguồn ↓ \ Đích → | WEB | DB | APP | MGT |
|---|---|---|---|---|
| **WEB** | — | DENY | ALLOW | DENY |
| **DB** | DENY | — | DENY | DENY |
| **APP** | DENY | ALLOW | — | DENY |
| **MGT** | ALLOW | ALLOW | ALLOW | — |

Đường được phép: 4. Bị từ chối: 8. Reply traffic của bất kỳ allowed flow nào được phép
qua stateful conntrack.

### 6.2 Cài đặt enforcement

Hiện thực bằng Linux netfilter `iptables FORWARD` chain trên mỗi leaf. Chain hoạt động
như default-allow chain với một DROP cuối tường minh (chain policy ACCEPT, rule cuối là
DROP all). Điều này có nghĩa thứ tự chèn rule rất quan trọng: rule PHẢI là `-I FORWARD
<pos>` trước default-drop cuối. Một lệnh `-A FORWARD` (append) ngây thơ sẽ đặt rule SAU
default-drop và rule đó im lặng vô hiệu.

Chain LEAF-1 đang chạy:
```
1. <khối block do agent đẩy>            # nếu có, gắn nhãn nos:agent-*
2. ACCEPT  10.2.50.0/24   → any         # nos:zt-mgt-all-allow
3. ACCEPT  10.2.100.0/24  → 10.1.200.0/24 # nos:zt-app-db-allow
4. ACCEPT  10.1.100.0/24  → 10.2.100.0/24 # nos:zt-web-app-allow
5. ACCEPT  ESTABLISHED,RELATED          # reply conntrack
6. DROP    any            → any         # nos:zt-default-drop
```

Chain LEAF-2 đang chạy: cấu trúc giống hệt, hiện chưa có rule nào của agent.

### 6.3 Quy ước gắn nhãn rule

Mọi rule iptables đều mang annotation comment:
- `nos:zt-*` — chính sách ZT đường cơ sở. Bất biến. Agent không được sửa.
- `nos:agent-<hash>` — được AI agent chèn động khi phản ứng với alert. Agent sở hữu và
  bảo trì các rule này.
- (không gắn nhãn) — rule thủ công của operator. Agent không được đụng vào nếu chưa
  escalate.

**Bất biến của agent**: trước khi đẩy một rule block mới, quét chain để tìm rule
`nos:agent-*` đang tồn tại có cùng tuple (src_ip, dst_ip, dst_port). Nếu thấy, chỉ
refresh TTL — KHÔNG chèn trùng.

### 6.4 Defense in depth

Cùng một policy được thực thi trên cả hai leaf đối với luồng cross-leaf. Nghĩa là
attacker bypass được rule ở leaf nguồn (ví dụ: source-routing) thì vẫn dính rule ở leaf
đích. Agent nên đẩy block tới cả hai leaf đối với vi phạm cross-zone, và tới leaf nguồn
đối với vi phạm intra-leaf.

### 6.5 Mapping vùng → leaf (helper quyết định)

```
WEB (10.1.100.0/24) → LEAF-1
DB  (10.1.200.0/24) → LEAF-1
APP (10.2.100.0/24) → LEAF-2
MGT (10.2.50.0/24)  → LEAF-2
```

## 7. Mặt Phẳng Phát Hiện (IDS)

### 7.1 Capture

Suricata IDS nhận traffic ingress được mirror từ cả hai leaf qua tc-mirred (Vlan100/Vlan200
trên LEAF-1 → IDS eth0, Vlan100/Vlan300 trên LEAF-2 → IDS eth1). Capture là **bất đối
xứng** — IDS chỉ thấy chiều request (ingress vào leaf), không thấy reply.

**Hệ quả cho logic detection**: Suricata không thể tái dựng đầy đủ TCP session, nên các
keyword `flow:to_server` và session-state không tin cậy. Tất cả policy rule đều **chỉ-SYN**
(`flags:S`) — chúng fire khi có khởi tạo connection. Như vậy là đủ cho ngữ nghĩa ZT: ZT
quan tâm AI initiate, không phải transfer cái gì.

### 7.2 Tập rule đang hoạt động

| SID | Mức | Phát hiện | Ngữ nghĩa |
|---|---|---|---|
| 9000001 | P1 | WEB → DB:[5432,3306,1433,27017] SYN | Tầng web liên hệ trực tiếp database — bypass tầng app (lateral movement / chuẩn bị SQL exfil) |
| 9000002 | P1 | DB → !{WEB,DB,APP,MGT} SYN | Database initiate outbound ra ngoài zone — exfiltration / C2 callback |
| 9000003 | P2 | APP → WEB:[80,443,22] SYN | Reverse call — app không nên initiate đến web (dấu hiệu app bị compromise) |
| 9000004 | P2 | WEB → MGT:[22,3389] SYN | Web tier chạm mgmt plane — toan escalation |
| 9000005 | P2 | APP → MGT:[22,3389] SYN | App tier chạm mgmt plane — toan escalation |
| 9000010 | P3 | ICMP echo, ≥3 trong 10s/src | Ping sweep / network reconnaissance |
| 9000011 | P3 | TCP SYN, ≥10 trong 5s/src | Port scan |
| 9000020 | P4 | MGT → any (rate-limit 1/phút/src) | Audit log: management plane access (KHÔNG phải sự cố — visibility bắt buộc) |

### 7.3 Mapping mức độ nghiêm trọng → phản ứng (gợi ý)

| Mức | Hành động mặc định | TTL block |
|---|---|---|
| P1 | Auto-block source IP tại LEAF liên quan | 3600s |
| P2 | Auto-block source IP tại LEAF liên quan | 1800s |
| P3 | Log + escalate | — |
| P4 | Log only (audit baseline) | — |

### 7.4 API Alert

```
GET  http://10.10.6.238:8765/health      → tình trạng IDS
GET  http://10.10.6.238:8765/alerts      → ?since=ISO  hoặc ?last=N
GET  http://10.10.6.238:8765/alerts/clear → trả về {cleared_at: ISO} (anchor cho ?since)
GET  http://10.10.6.238:8765/flows       → flow event (passive)
GET  http://10.10.6.238:8765/stream      → SSE alert+flow
GET  http://10.10.6.238:8766/events      → SSE bridge (alert + heartbeat 15s)
GET  http://10.10.6.238:8766/ws          → WebSocket tương đương
```

## 8. Mô Hình Mối Đe Dọa Mà Agent Phòng Ngự

Agent giả định vành đai đã bị xuyên thủng và phải ngăn chặn blast radius east-west. Các
kịch bản đe dọa agent chủ động nhận diện:

1. **WEB tier bị compromise** — attacker có shell trên web-01 và pivot sang DB hoặc MGT.
   Phát hiện: SID 9000001 (web→DB trực tiếp), SID 9000004 (web→MGT).
2. **APP tier bị compromise** — attacker pivot từ app sang web (đảo chiều) hoặc escalate
   lên MGT. Phát hiện: SID 9000003, SID 9000005.
3. **DB exfiltration / C2** — db-01 initiate outbound (rò rỉ dữ liệu ra IP của attacker,
   hoặc beaconing). Phát hiện: SID 9000002.
4. **Trinh sát** — hành vi quét. Phát hiện: SID 9000010, 9000011.

Agent **KHÔNG** coi traffic xuất phát từ MGT là khả nghi (SID 9000020 là audit, không
phải sự cố).

## 9. Bất Biến Mạng Mà Agent Phải Bảo Toàn

**Không bao giờ block**:
- 127.0.0.0/8 (loopback)
- 192.168.122.0/24 (mgmt OOB — block sẽ tự khóa chính agent ra ngoài)
- 10.10.6.0/24 (đường out-of-band đến control plane)
- 10.1.100.1/32, 10.1.200.1/32, 10.2.100.1/32, 10.2.50.1/32 (SVI gateway — block sẽ
  chia cắt vùng)
- 10.2.50.10/32 (mgt-01 — host vận hành; block sẽ giết audit/compliance)
- 192.168.122.205/32 (IDS — block sẽ cắt đứt khả năng nhận thức của agent)

**Không bao giờ sửa**:
- Rule gắn nhãn `nos:zt-*` (chính sách ZT đường cơ sở)
- Rule operator không gắn nhãn

**Luôn có thể đảo ngược**:
- Mọi rule do agent đẩy đều gắn nhãn `nos:agent-<hash>`, có TTL, và có thể recover bằng
  `iptables -D FORWARD` match theo comment.

## 10. Bề Mặt Vận Hành Cho Agent

| Năng lực | Cơ chế |
|---|---|
| Đọc alert | HTTP GET đến API IDS (:8765/8766) |
| Đọc trạng thái fabric | SF API `GET /api/rules` (KHÔNG SSH trực tiếp) |
| Đẩy enforcement | SF API `POST /api/rules` (qua proxy ids-agent) |
| Gỡ enforcement | SF API `DELETE /api/rules/{id}` |
| Sự thật về inventory | Tài liệu này (knowledge base) |
| Sự thật về live state | `GET /api/rules` trên SF (live gNMI Get) |

Agent suy luận trên: (alert stream) × (knowledge này) × (live SF state) → ra quyết định
policy có gắn nhãn provenance.
