# 3S-NOS Data Plane Specification

> Document for ONAP SDNC Control Plane AI Agent
> Mục đích: cung cấp đầy đủ thông tin data plane để control plane (ONAP SDNC) implement connector tới các SONiC switch và đẩy/quản lý microsegmentation rules.

**Server**: `112.137.129.232:3080` (GNS3 server)
**Project**: `micro-segmentation-lab` — ID `b6bf1cd6-8d58-41d4-941c-893020abd2a3`
**SDNC reach data plane qua**: GNS3VM host `10.10.6.238` (LAN) hoặc `112.137.129.232` (public NAT)

---

## 1. Topology — Spine-Leaf Fabric

```
               ┌──────────────┐    ┌──────────────┐
               │     NAT1     │    │     NAT2     │
               │ (Cloud/Mgmt) │    │   (GNS3VM)   │
               └──────┬───────┘    └───────┬──────┘
                      │                    │
                ┌─────┴────────────────────┴─────┐
                │         SONIC-SPINE             │
                │   eth0: 192.168.122.x (mgmt)   │
                │   eth1: 10.0.1.1/30 → LEAF-1   │
                │   eth2: 10.0.2.1/30 → LEAF-2   │
                └────────┬───────────────┬────────┘
                         │               │
              ┌──────────┘               └──────────┐
     ┌────────┴─────────┐               ┌───────────┴──────┐
     │   SONIC-LEAF-1   │               │   SONIC-LEAF-2   │
     │ uplink eth0:     │               │ uplink eth0:     │
     │   10.0.1.2/30    │               │   10.0.2.2/30    │
     │ Vlan100 SVI:     │               │ Vlan100 SVI:     │
     │   10.1.100.1/24  │               │   10.2.100.1/24  │
     │ Vlan200 SVI:     │               │ Vlan300 SVI:     │
     │   10.1.200.1/24  │               │   10.2.50.1/24   │
     │ tc mirred → eth4 │               │ tc mirred → eth4 │
     └──┬───┬───────┬───┘               └──┬───┬───────┬───┘
        │   │       │ mirror               │   │       │ mirror
        │   │       └────────────┐  ┌──────┘   │       │
       ┌┴┐ ┌┴┐                   ↓  ↓         ┌┴┐ ┌┴┐
       │W│ │D│                ┌─────────┐    │A│ │M│
       │E│ │B│                │   IDS   │    │P│ │G│
       │B│ └─┘                │ Suricata│    │P│ │T│
       └─┘                    └─────────┘    └─┘ └─┘
```

---

## 2. Node Inventory

| Node | Type | GNS3 Console | Mgmt IP | Role |
|------|------|--------------|---------|------|
| SONIC-SPINE | SONiC-VS | `telnet 112.137.129.232:5006` | 192.168.122.x (DHCP) | L3 core router, inter-LEAF transit |
| SONIC-LEAF-1 | SONiC-VS | `telnet 112.137.129.232:5010` | 192.168.122.x (DHCP) | Gateway WEB+DB, ZT enforcement |
| SONIC-LEAF-2 | SONiC-VS | `telnet 112.137.129.232:5015` | 192.168.122.x (DHCP) | Gateway APP+MGT, ZT enforcement |
| Alpine-Linux-1 | Alpine 3.23 | `telnet 112.137.129.232:5008` | 10.1.100.10/24 | WEB zone host |
| Alpine-Linux-2 | Alpine 3.23 | `telnet 112.137.129.232:5011` | 10.1.200.10/24 | DB zone host |
| Alpine-Linux-3 | Alpine 3.23 | `telnet 112.137.129.232:5014` | 10.2.100.10/24 | APP zone host |
| Alpine-Linux-5 | Alpine 3.23 | `telnet 112.137.129.232:5016` | 10.2.50.10/24 | MGT zone host |
| IDS-Suricata | Alpine 3.23 + Suricata 8.0 | `telnet 112.137.129.232:5018` | 192.168.122.205 (eth2) | IDS, REST API :8765 |

**Login credentials:**
- SONiC: `admin` / `YourPaSsWoRd`
- Alpine: `root` (no password)

---

## 3. Layer 3 — IP Address Plan

### 3.1 Underlay (point-to-point /30)

| Link | SPINE side | LEAF side |
|------|-----------|-----------|
| SPINE ↔ LEAF-1 | `10.0.1.1/30` (eth1) | `10.0.1.2/30` (eth0) |
| SPINE ↔ LEAF-2 | `10.0.2.1/30` (eth2) | `10.0.2.2/30` (eth0) |

### 3.2 Overlay — VLAN/SVI per zone

| Zone | LEAF | VLAN | SVI Gateway | CIDR | Host |
|------|------|------|-------------|------|------|
| **WEB** | LEAF-1 | Vlan100 | 10.1.100.1 | 10.1.100.0/24 | Alpine-1: 10.1.100.10 |
| **DB**  | LEAF-1 | Vlan200 | 10.1.200.1 | 10.1.200.0/24 | Alpine-2: 10.1.200.10 |
| **APP** | LEAF-2 | Vlan100 | 10.2.100.1 | 10.2.100.0/24 | Alpine-3: 10.2.100.10 |
| **MGT** | LEAF-2 | Vlan300 | 10.2.50.1  | 10.2.50.0/24  | Alpine-5: 10.2.50.10 |

### 3.3 Out-of-band — Management

| Interface | IP | Mục đích |
|-----------|-----|----------|
| GNS3VM host eth0 | 10.10.6.238 (LAN) / 112.137.129.232 (public NAT) | SDNC NETCONF/SSH entrypoint |
| virbr0 (libvirt bridge) | 192.168.122.1/24 | Mgmt network — SONiC mgmt + IDS eth2 |
| IDS-Suricata eth2 | 192.168.122.205 | Alert REST API exposure |

---

## 4. Routing — Forwarding Plane

**Mechanism:** Static routes + kernel `ip forwarding=1` trên tất cả interfaces (SONiC-VS không có ASIC, dùng Linux kernel forwarding).

### 4.1 SONIC-SPINE routing table

```
10.0.1.0/30 dev eth1            # to LEAF-1 underlay
10.0.2.0/30 dev eth2            # to LEAF-2 underlay
10.1.100.0/24 via 10.0.1.2      # WEB zone via LEAF-1
10.1.200.0/24 via 10.0.1.2      # DB zone via LEAF-1
10.2.100.0/24 via 10.0.2.2      # APP zone via LEAF-2
10.2.50.0/24  via 10.0.2.2      # MGT zone via LEAF-2
```

### 4.2 SONIC-LEAF-1 routing table

```
10.0.1.0/30 dev eth0            # underlay to SPINE
10.1.100.0/24 dev Vlan100       # WEB direct
10.1.200.0/24 dev Vlan200       # DB direct
10.2.100.0/24 via 10.0.1.1      # APP via SPINE
10.2.50.0/24  via 10.0.1.1      # MGT via SPINE
default via 10.0.1.1            # all else via SPINE
```

### 4.3 SONIC-LEAF-2 routing table

```
10.0.2.0/30 dev eth0            # underlay to SPINE
10.2.100.0/24 dev Vlan100       # APP direct
10.2.50.0/24  dev Vlan300       # MGT direct
10.1.100.0/24 via 10.0.2.1      # WEB via SPINE
10.1.200.0/24 via 10.0.2.1      # DB via SPINE
default via 10.0.2.1
```

### 4.4 Critical fix — SONiC-VS host route

SONiC-VS install route `10.0.X.0/30 dev EthernetX metric 0` (NIC ảo, ARP fail) đè lên `dev eth0`. Cần inject `/32` host route:

```bash
sudo ip route add 10.0.2.1/32 dev eth0 src 10.0.2.2  # trên LEAF-2
sudo ip route add 10.0.1.1/32 dev eth0 src 10.0.1.2  # trên LEAF-1
```

---

## 5. Microsegmentation — Zero Trust Policy

### 5.1 Policy Matrix (nguồn → đích)

| Source ↓ \ Dest → | WEB | DB | APP | MGT |
|---|:---:|:---:|:---:|:---:|
| **WEB** | — | **DENY** | ALLOW | **DENY** |
| **DB**  | **DENY** | — | **DENY** | **DENY** |
| **APP** | **DENY** | ALLOW | — | **DENY** |
| **MGT** | ALLOW | ALLOW | ALLOW | — |

**Verified:** 12/12 flows enforce correct.

### 5.2 Enforcement Point

- **Where:** `iptables FORWARD chain` trên LEAF-1 và LEAF-2 (defense-in-depth — cả 2 LEAF apply rule giống nhau cho flows liên quan).
- **Why iptables, không phải SONiC ACL:** SONiC-VS chạy mode software, không có ASIC để enforce ACL → fallback Linux kernel netfilter.
- **State tracking:** `conntrack` module enabled; rule `ESTABLISHED,RELATED ACCEPT` trước các DROP rule để cho phép reply traffic.

### 5.3 iptables Rules — LEAF-1 (WEB + DB zones)

```bash
# Default policy
iptables -P FORWARD DROP

# Conntrack — cho phép reply
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: WEB zone (10.1.100.0/24) ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.1.200.0/24 -j DROP   # WEB→DB BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.50.0/24  -j DROP   # WEB→MGT BLOCK
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT # WEB→APP ALLOW

# === ZT POLICY: DB zone (10.1.200.0/24) — outbound DENY-ALL ===
iptables -A FORWARD -s 10.1.200.0/24 -d 10.1.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.100.0/24 -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -d 10.2.50.0/24  -j DROP
iptables -A FORWARD -s 10.1.200.0/24 -j DROP

# === Inbound to DB — only from APP ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT  # APP→DB ALLOW
iptables -A FORWARD -s 10.2.50.0/24  -d 10.1.200.0/24 -j ACCEPT  # MGT→DB ALLOW

# Drop everything else
iptables -A FORWARD -j DROP
```

### 5.4 iptables Rules — LEAF-2 (APP + MGT zones)

```bash
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# === ZT POLICY: APP zone (10.2.100.0/24) ===
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.100.0/24 -j DROP   # APP→WEB BLOCK (reverse call)
iptables -A FORWARD -s 10.2.100.0/24 -d 10.2.50.0/24  -j DROP   # APP→MGT BLOCK
iptables -A FORWARD -s 10.2.100.0/24 -d 10.1.200.0/24 -j ACCEPT # APP→DB ALLOW

# === ZT POLICY: MGT zone (10.2.50.0/24) — full access ===
iptables -A FORWARD -s 10.2.50.0/24 -j ACCEPT

# === Inbound to APP — from WEB only ===
iptables -A FORWARD -s 10.1.100.0/24 -d 10.2.100.0/24 -j ACCEPT  # WEB→APP ALLOW

iptables -A FORWARD -j DROP
```

### 5.5 Apply / Rollback / Status

Hiện tại quản lý qua Python helper:

```bash
cd /3s-com/zma/dc-fabric-setup
python3 07-apply-policy.py apply      # push iptables qua console
python3 07-apply-policy.py rollback   # iptables -F FORWARD && -P ACCEPT
python3 07-apply-policy.py status     # iptables -L -n -v
python3 08-verify-policy.py           # 12-flow verification
```

**SDNC AI Agent integration target:** thay thế `07-apply-policy.py` bằng REST/NETCONF call từ ONAP SDNC.

---

## 6. Traffic Mirroring — IDS Tap

### 6.1 tc mirred config (LEAF-1)

```bash
# Mirror Vlan100 ingress (WEB) → eth4 (đến IDS eth0)
tc qdisc add dev Vlan100 handle ffff: ingress
tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4

# Mirror Vlan200 ingress (DB) → eth4
tc qdisc add dev Vlan200 handle ffff: ingress
tc filter add dev Vlan200 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4
```

### 6.2 tc mirred config (LEAF-2)

```bash
# Mirror Vlan100 ingress (APP) → eth4 (đến IDS eth1)
tc qdisc add dev Vlan100 handle ffff: ingress
tc filter add dev Vlan100 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4

# Mirror Vlan300 ingress (MGT) → eth4
tc qdisc add dev Vlan300 handle ffff: ingress
tc filter add dev Vlan300 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress mirror dev eth4
```

**Quan trọng:** tc mirred chạy ở `ingress` qdisc, **trước** netfilter. IDS thấy được packet kể cả khi iptables DROP.

> **Cảnh báo asymmetric capture:** mirred chỉ tap ingress của VLAN — chỉ thấy **một chiều** flow (zone→gateway), miss return path. Suricata flow tracking + `flow:to_server` không hoạt động chuẩn. Detection rules phải dùng `flags:S` workaround (xem Section 7.1).

---

## 6A. DCN Service Simulation — Realistic East-West Workload

Để IDS có gì observe (không chỉ test với hping3), 4 Alpine hosts được provision với services + cron-driven traffic generator mô phỏng workload thực tế của một DCN.

### 6A.1 Service inventory per zone

| Zone | Host | Service | Port | Implementation | Listener pattern |
|------|------|---------|------|----------------|------------------|
| WEB | Alpine-1 (10.1.100.10) | banner HTTP | 80 | busybox `nc -l -p 80 < /tmp/banner.html` loop | request-then-reply (file redirect, không pipe) |
| WEB | Alpine-1 | sshd | 22 | OpenSSH (`PermitRootLogin yes`, `PermitEmptyPasswords yes`) | persistent |
| DB | Alpine-2 (10.1.200.10) | pg-mock SQL-aware | 5432 | busybox `nc -lk -e /usr/local/bin/pg-mock.sh` | connection-per-message, returns SQL-shape based on payload prefix |
| DB | Alpine-2 | sshd | 22 | OpenSSH | persistent |
| APP | Alpine-3 (10.2.100.10) | banner HTTP | 8080 | busybox `nc -l -p 8080 < banner` | request-then-reply |
| APP | Alpine-3 | sshd | 22 | OpenSSH | persistent |
| MGT | Alpine-5 (10.2.50.10) | sshd | 22 | OpenSSH | persistent (no app — control-only zone) |

> **busybox 1.37 nc gotcha:** `nc -lk -e` works **chỉ khi handler emits 1 line then exits**; multi-line responses cần pattern `pre-render to file → nc -l -p PORT < file`. Discovery cost: nửa ngày debug, lessons-learned đã track trong memory.

### 6A.2 Cron-driven traffic generators

Tất cả crons trong `/etc/crontabs/root`, started bằng `crond -f -L /var/log/dcn/crond.log`:

| Cron | Source | Direction | Cadence | Purpose |
|------|--------|-----------|---------|---------|
| `shopper` | WEB → APP:8080 | east-west, allowed | 30s | Mô phỏng web tier proxy → app tier |
| `noise` | APP → DB:5432 | east-west, allowed | 30s | 4 SQL shapes (SELECT users, SELECT orders, INSERT log, UPDATE session) |
| `mgt-scrape` | MGT → WEB:80 / APP:8080 / DB:5432 | inbound to all zones (audit-by-design) | 60s | banner + service-health probe |
| `mgt-audit` | MGT → WEB:22 / APP:22 / DB:22 (rotating) | SSH | 2 min | Compliance SSH login + `uptime` capture |
| `mgt-logpull` | MGT → APP:22 | SSH | 5 min | `tail -100 /var/log/dcn/*.log` over SSH |
| `attacker-web` | WEB → DB:5432 | violation (P1) | dormant — armed by scenario | Injected only during demo |
| `attacker-db` | DB → 8.8.8.8 / external | violation (P1) | dormant | Simulated C2 callback |

**Kết quả continuous:** ~120 flows/min baseline, ~11 P4 audit alerts/min từ SID 9000020 (by design — MGT outbound = always alerted), 0 P1/P2 alerts trừ khi scenario chạy.

### 6A.3 Bootstrap pipeline — provision 4 hosts

| File | Target | LOC | Notes |
|------|--------|-----|-------|
| `/3s-com/dataplane/bootstrap/web-host.sh` | Alpine-1 | 135 | banner :80 + sshd + shopper cron + dormant attacker |
| `/3s-com/dataplane/bootstrap/db-host.sh`  | Alpine-2 | 119 | pg-mock SQL-aware + sshd + dormant attacker |
| `/3s-com/dataplane/bootstrap/app-host.sh` | Alpine-3 | 123 | banner :8080 + sshd + noise→DB cron |
| `/3s-com/dataplane/bootstrap/mgt-host.sh` | Alpine-5 | 133 | sshd + audit/scrape/logpull crons + scenario controllers |

**Push mechanism:** `/tmp/paste_bootstrap.py` — base64-encode script, paste qua GNS3 console proxy port (5008/5011/5014/5016), `base64 -d > /root/bootstrap.sh && sh /root/bootstrap.sh`. Idempotent: re-run sẽ overwrite cleanly.

### 6A.4 Compromise / restore scenarios (MGT-driven demo)

Scenario controllers ở `/root/scenario/` trên Alpine-5 (MGT). Mỗi scenario có 3 scripts (compromise/restore/status), trigger từ console hoặc qua AI agent's run.sh.

| Script | Effect | Detection |
|--------|--------|-----------|
| `compromise-web.sh` | SSH→WEB, write `/usr/local/bin/attacker-web-loop.sh`, nohup loop `nc -z -w2 10.1.200.10 5432; sleep 15` | SID 9000001 P1 (~10s/alert) |
| `compromise-db.sh`  | SSH→DB, write `/usr/local/bin/attacker-db-loop.sh`, nohup loop `nc -z -w2 8.8.8.8 443; sleep 15` | SID 9000002 P1 (~10s/alert) |
| `restore-web.sh` / `restore-db.sh` | SSH, kill PID từ `/tmp/attacker-{web,db}.pid`, rm loop script | alert stream goes quiet |
| `status-web.sh` / `status-db.sh`   | check `/tmp/scenario-{web,db}.state` → `armed (since TS)` hoặc `disarmed` | — |

**State files:** `/tmp/scenario-{web,db}.state` trên MGT (chứa ISO timestamp khi arm). Idempotent: gọi compromise khi đã armed → no-op + thông báo. Gọi restore khi đã restored → no-op.

> **Pitfall — `pkill -f` self-kill:** SSH command line containing substring `attacker-{web,db}-loop` sẽ bị `pkill -f attacker-{web,db}-loop` matched ngay chính cmdline của SSH session, gây SIGTERM lên parent shell → SSH exit 255. **Fix:** kill bằng PID file (`kill -9 $(cat /tmp/attacker-web.pid)`), không dùng pattern match.

**Demo flow:** start clean → (P4 audit baseline only) → `compromise-web.sh` → SID 9000001 visible < 30s → `restore-web.sh` → quiet.

### 6A.4.1 Validation 2026-05-04 (rewritten scripts)

| Step | Result |
|------|--------|
| 6 scripts pushed via console 5016 (base64 paste) | ✅ |
| `compromise-web` armed → 50s sau, SID 9000001 delta = +8 | ✅ ~10s/alert |
| `restore-web` → status returns `disarmed`, alerts dừng | ✅ |
| `compromise-db` armed → 50s sau, SID 9000002 delta = +8 | ✅ ~10s/alert |
| `restore-db` → cleanup OK | ✅ |
| `/alerts/clear` returns `{cleared_at: ISO}` (since-based) | ✅ working |
| `/alerts?since=<cleared_at>` returns count=0 ngay sau clear | ✅ |

### 6A.5 Validation checkpoint (2026-05-03)

| Test | Result |
|------|--------|
| 4 zones up, services healthy | ✅ |
| Continuous east-west traffic (cron-driven) | ✅ 120 flow/min |
| SC compromise-web → SID 9000001 fires | ✅ < 30s |
| SC compromise-db → SID 9000002 fires | ✅ < 30s |
| Baseline FPR (P1+P2 false positives over 1h) | **0%** |
| MGT audit baseline (SID 9000020) | ✅ ~11/min by design |

---

## 7. Detection Rules — Suricata 8.0

**Source:** `/3s-com/zma/suricata/rules/zt-lab.rules` (host) — mount-bind vào `/etc/suricata/rules/zt-lab.rules` trong IDS VM
**Config:** `/3s-com/zma/suricata/suricata-zt.yaml` → mount vào `/etc/suricata/suricata-zt.yaml`
**Capture:** `af-packet` cluster_flow trên `eth0` (mirror từ LEAF-1) + `eth1` (mirror từ LEAF-2)
**eve.json types:** `alert`, `flow` (flow logging bật để dashboard show normal traffic)
**Reload:** `kill -USR2 $(cat /var/run/suricata.pid)` — không cần restart

### 7.1 Asymmetric capture workaround

`tc mirred` ingress qdisc chỉ mirror **một chiều** (request hoặc reply, không phải cả hai) → Suricata không reassemble được full TCP session → `flow:to_server` keyword **không tin cậy**. Workaround: dùng `flags:S` (chỉ match SYN packet — connection initiation) + ràng buộc `dst_port` = service port. Chỉ fire trên init, suppress được FP từ return-traffic của shopper/scrape cron.

### 7.2 Active rule set (8 rules)

| SID | Priority | Class | Match | Msg |
|-----|----------|-------|-------|-----|
| 9000001 | P1 | policy-violation | `WEB → DB:[5432,3306,1433,27017] flags:S` | WEB direct to DB - microsegmentation bypass |
| 9000002 | P1 | policy-violation | `DB → !lab-zones any flags:S` | DB initiating outbound connection |
| 9000003 | P2 | policy-violation | `APP → WEB:[80,443,22] flags:S` | APP reverse call to WEB - lateral movement |
| 9000004 | P2 | policy-violation | `WEB → MGT:[22,3389] flags:S` | WEB to MGT - unauthorized access |
| 9000005 | P2 | policy-violation | `APP → MGT:[22,3389] flags:S` | APP to MGT - unauthorized access |
| 9000010 | P3 | network-scan | ICMP echo, threshold 3/10s/src | ICMP ping sweep detected |
| 9000011 | P3 | network-scan | TCP SYN, threshold 10/5s/src | Possible port scan |
| 9000020 | P4 | policy-violation | `MGT → ANY` (1/min/src) | Management zone access (audit) |

> Note: SID 9000006 (APP→DB direct) đã removed vì APP→DB là **allowed path** trong policy matrix (5.1). Đã thay bằng audit-by-design pattern qua SID 9000020 cho MGT.

---

## 8. North-bound API — for ONAP SDNC Integration

### 8.1 IDS Alert API (Suricata side)

Base URL: `http://10.10.6.238:8765` (LAN) / `http://112.137.129.232:8765` (public NAT)
**Source:** `/usr/local/bin/ids-api.py` **inside** IDS-Suricata VM (Python stdlib `BaseHTTPRequestHandler` + `ThreadingHTTPServer`, ~147 LOC). Process autostart, restart bằng `pkill -f ids-api.py; nohup python3 /usr/local/bin/ids-api.py >/tmp/api.log 2>&1 &`.
**Exposure:** libvirt `virbr0` NAT bridge → DNAT từ host `:8765` → VM `192.168.122.205:8765`.

| Method | Path | Response |
|--------|------|----------|
| GET | `/health` | `{status, suricata: bool, ts}` |
| GET | `/alerts?last=N&since=ts` | `{count, summary{sid:n}, alerts[]}` |
| GET | `/alerts/clear` | `{cleared_at: ts}` — client dùng làm anchor cho `?since=` để skip pre-F5 alerts |
| GET | `/flows?last=N&since=ts` | `[flow event objects]` — đọc reverse từ eve.json, max 500 |
| GET | `/stream` | SSE — gồm cả alert events + flow events (rate-limit 10 flow/cycle/s) |
| GET | `/service-health` | Passive flow-inference: `{services:[{name,ip,port,zone,status:up\|unknown}], method:"flow-inference"}` — quét eve.json 180s gần nhất |

### 8.2 Go IDS Agent (real-time bridge + enforcement proxy)

Base URL: `http://10.10.6.238:8766`

> After refactor (2026-04-xx): pure proxy/bridge. `tryAutoBlock()` removed. Auto-enforcement is now handled by Intelligence Layer.

| Method | Path | Use |
|--------|------|-----|
| GET | `/health` | Proxy → Suricata `/health` |
| GET | `/alerts` | Proxy → Suricata `/alerts` |
| GET | `/events` | SSE — alerts + heartbeat (15s) + `{type:"connected"}` event |
| GET | `/ws` | WebSocket — same payload as `/events` |
| GET | `/stats` | Alert counters |
| GET | `/rules` | Proxy → SF `GET /api/rules` (gNMI format: `{leaves:{leaf-N:{rules:{notification:[{update:[{path,val}]}]}}}}`) |
| **POST** | **`/rules`** | **Push rule to SF; force `source=agent` server-side — Intelligence Layer primary path** |
| **DELETE** | **`/rules/{rule_id}`** | **Revoke rule from SF + LEAF — Intelligence Layer TTL cleanup** |
| POST | `/autoblock` | Frontend manual block by IP |
| DELETE | `/autoblock/unblock/{id}` | Frontend manual unblock |

**Note on gNMI response format:** `GET /rules` returns the raw gNMI notification structure. Rule fields use YANG names: `src-prefix` (not `src_ip`), `rule-id` (not `rule_id`), `src-port`/`dst-port`. Clients must parse accordingly.

### 8.3 Alert JSON Schema

```json
{
  "timestamp": "2026-04-19T18:13:01Z",
  "event_type": "alert",
  "src_ip": "10.1.100.10",
  "dest_ip": "10.1.200.10",
  "proto": "TCP",
  "alert": {
    "signature": "[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass",
    "signature_id": 9000001,
    "severity": 1,
    "category": "policy-violation"
  }
}
```

---

## 9. Control Plane Integration — What SDNC Needs to Do

### 9.1 Connector Targets

ONAP SDNC AI Agent cần build connector tới:

| Target | Protocol | Endpoint | Action |
|--------|----------|----------|--------|
| SONIC-SPINE | SSH telnet console | `telnet 112.137.129.232:5006` | Routing policy push |
| **SONIC-LEAF-1** | **SSH telnet console** | `telnet 112.137.129.232:5010` | **Apply iptables** (ZT enforcement) |
| **SONIC-LEAF-2** | **SSH telnet console** | `telnet 112.137.129.232:5015` | **Apply iptables** (ZT enforcement) |
| IDS Suricata | REST + SSE | `:8765` / `:8766` | Subscribe alerts |

**Ghi chú:** SONiC-VS không support proper NETCONF/gNMI — cần dùng Linux shell qua telnet console hoặc SSH (nếu enable). Production SONiC sẽ có gNMI/NETCONF chuẩn.

### 9.2 Enforcement Targets — chỉ LEAF cần apply rule

| Switch | Cần apply microsegmentation? | Lý do |
|--------|:-:|------|
| SONIC-SPINE | ❌ | Pure transit, không terminate VLAN, không có host trực tiếp |
| **SONIC-LEAF-1** | ✅ | Terminate WEB+DB SVI, phải enforce intra-leaf (WEB→DB) + inter-leaf rules |
| **SONIC-LEAF-2** | ✅ | Terminate APP+MGT SVI, phải enforce intra-leaf (APP→MGT) + inter-leaf rules |

### 9.3 Suggested SDNC Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ ONAP SDNC AI Agent                                          │
│                                                             │
│  1. Subscribe SSE: GET http://10.10.6.238:8766/events       │
│  2. On P1 alert received:                                   │
│     a. Identify src_ip → determine LEAF (zone mapping)      │
│     b. Build iptables rule:                                 │
│        iptables -I FORWARD 1 -s <src_ip> -j DROP            │
│     c. Push qua SSH/telnet console tới LEAF                 │
│     d. Schedule auto-unblock (e.g., 5 min TTL)              │
│  3. Status feedback:                                        │
│     a. POST event "BLOCKED" về dashboard                    │
│     b. Log audit trail                                      │
└─────────────────────────────────────────────────────────────┘
```

### 9.4 Zone Mapping Helper (for SDNC)

```python
def ip_to_leaf(src_ip: str) -> str:
    """Map source IP → LEAF switch để biết apply rule ở đâu."""
    if src_ip.startswith("10.1.100.") or src_ip.startswith("10.1.200."):
        return "SONIC-LEAF-1"
    if src_ip.startswith("10.2.100.") or src_ip.startswith("10.2.50."):
        return "SONIC-LEAF-2"
    return None

def ip_to_zone(src_ip: str) -> str:
    if src_ip.startswith("10.1.100."): return "WEB"
    if src_ip.startswith("10.1.200."): return "DB"
    if src_ip.startswith("10.2.100."): return "APP"
    if src_ip.startswith("10.2.50."):  return "MGT"
    return None
```

---

## 10. Verification & Test Status

| Test | Result | Date |
|------|--------|------|
| 8-path connectivity matrix | 8/8 PASS | 2026-04-13 |
| 12-flow ZT policy enforcement | 12/12 correct | 2026-04-14 |
| Suricata detection (4 violations) | 4/4 detected | 2026-04-18 |
| End-to-end SC-1 → SC-5 | 5/5 PASS | 2026-04-19 |
| False Positive Rate (SC-5 baseline) | 0% | 2026-04-19 |
| Browser dashboard | 8/8 PASS | 2026-04-19 |
| **Total live alerts captured** | **38** | **2026-04-19** |
| **Intelligence Layer automated enforcement (10-run eval)** | | **2026-05-04** |
| — Outcome: ENFORCED (rule pushed to LEAF) | 10/10 PASS | 2026-05-04 |
| — Enforcement Correctness (M3): correct IP blocked | 10/10 (100%) | 2026-05-04 |
| — Alert→Decision latency (M1) avg | 4.75s | 2026-05-04 |
| — LLM confidence avg | 0.955 | 2026-05-04 |
| — 9-layer safety guardrails: all adversarial tests pass | PASS | 2026-05-04 |
| Scenario compromise-web → SID 9000001 → auto-block → restore | full round-trip verified | 2026-05-04 |

---

## 11. Files / Scripts Reference

| File | Purpose |
|------|---------|
| `/3s-com/zma/dc-fabric-setup/05-setup-all.py` | Full fabric setup automation |
| `/3s-com/zma/dc-fabric-setup/06-verify.py` | Connectivity matrix verification |
| `/3s-com/zma/dc-fabric-setup/07-apply-policy.py` | iptables apply/rollback (target for SDNC replacement) |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf1.sh` | Raw iptables rules LEAF-1 |
| `/3s-com/zma/dc-fabric-setup/07-iptables-leaf2.sh` | Raw iptables rules LEAF-2 |
| `/3s-com/zma/dc-fabric-setup/08-verify-policy.py` | 12-flow policy verification |
| `/3s-com/zma/dc-fabric-setup/14-ids-webapi.py` | IDS REST API restore (legacy) |
| `/usr/local/bin/ids-api.py` (inside IDS VM) | Active REST API server (147 LOC, stdlib only) |
| `/3s-com/zma/suricata/suricata-zt.yaml` | Suricata config (af-packet eth0+eth1, eve-log alert+flow) |
| `/3s-com/zma/suricata/rules/zt-lab.rules` | 8 active detection rules (host-side, mounted into VM) |
| `/3s-com/dataplane/bootstrap/web-host.sh` | WEB zone provisioning (banner :80 + sshd + shopper cron) |
| `/3s-com/dataplane/bootstrap/db-host.sh`  | DB zone provisioning (pg-mock :5432 SQL-aware + sshd) |
| `/3s-com/dataplane/bootstrap/app-host.sh` | APP zone provisioning (banner :8080 + sshd + noise→DB cron) |
| `/3s-com/dataplane/bootstrap/mgt-host.sh` | MGT zone provisioning (sshd + audit/scrape/logpull + scenario controllers) |
| `/tmp/paste_bootstrap.py` | Base64-encoded push of bootstrap script via GNS3 console proxy |

---

## 12. Intelligence Layer — Implementation Status (2026-05-04)

All items previously listed as "open for SDNC Agent" are now complete via the Intelligence Layer service.

| Item | Status | Implementation |
|------|--------|---------------|
| Rule push to LEAF | ✅ DONE | Intelligence Layer → `POST ids-agent:8766/rules` → SF `/api/rules` → gNMI → nos-acl-bridge → iptables |
| Subscribe IDS SSE stream | ✅ DONE | `pipeline/consumer.py` subscribes `http://ids-agent:8766/events`, auto-reconnect |
| Auto-block workflow (P1 alert → DROP) | ✅ DONE | LangGraph: classify → reason → validate → enforce. Confidence gate ≥0.85 |
| Auto-unblock TTL | ✅ DONE | `ttl_seconds` field in rule (default 3600s for P1); SF enforces via nos-acl-bridge timer |
| Block event back to dashboard | ✅ DONE | `record_decision` node: Postgres audit + Redis history + SSE `/stream`; Frontend polls `/api/intel/decisions` |
| Audit trail / compliance log | ✅ DONE | Postgres `decisions` table: full ReAct trace, safety check results, confidence, latency |
| SSH/telnet connector to SONiC console | ❌ NOT needed | Route goes through SF gNMI — no direct console access required for enforcement |

**Architecture:** No direct SSH/console to SONiC needed. Control path is: Intelligence Layer → ids-agent (REST) → Secure Framework (gNMI mTLS) → nos-acl-bridge → iptables FORWARD. All persistence in LEAF ConfigDB (Redis DB4) — survives restart.
