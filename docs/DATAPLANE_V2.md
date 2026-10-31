# 3S-NOS Data Plane — V2 As-Deployed Spec (2-spine / 4-leaf / 8-zone Clos DCN)

> **For: ONAP SDNC / Control Plane AI Agent.**
> **Status: Deployed and operational on `micro-segmentation-lab` GNS3 project.** Verified 2026-05-31.
> All IPs, paths, console ports, and config patterns below reflect the **live state** of the fabric, not a plan.

**GNS3 Server**: `112.137.129.232:3080` (public NAT) / `10.10.6.238:3080` (LAN)
**Project**: `micro-segmentation-lab` (id `b6bf1cd6-8d58-41d4-941c-893020abd2a3`)
**Total resources**: 27 nodes (2 SPINE + 4 LEAF + 16 host + 1 IDS + 4 NAT) / 32 links / ~24GB RAM nominal

---

## 0. Invariants (control plane MUST respect)

1. **Passive mirror IDS, never L3 in-path.** IDS captures *copied* streams via `tc clsact` + `mirred` on each LEAF. IDS has `ip_forward=0`, no route into lab subnets. Capture NICs `promisc on`, no IP. Never give IDS an IP in 10.x or any route into lab zones.
2. **Deny-by-default enforcement at every LEAF.** `iptables -P FORWARD DROP` + one `conntrack ESTABLISHED,RELATED ACCEPT` first + explicit ACCEPTs from the 8×8 matrix + trailing `-j DROP`. SPINEs never enforce (transit only).
3. **/30 underlay + /24-per-zone overlay.** Every LEAF↔SPINE link is a `/30` point-to-point. Every zone = one VLAN/SVI = one `/24`, gateway `.1`, hosts `.10` and `.11`.
4. **ECMP over 2 spines.** Each LEAF has 2 uplinks (eth0→SPINE-1, eth5→SPINE-2) and installs ECMP routes (`nexthop via … nexthop via …`) for every remote `/16`.
5. **Mirror covers all data NICs.** On each LEAF, `mirred` ingress+egress on all six data NICs (`eth0,eth2,eth3,eth5,eth6,eth7`) → `eth4` → IDS. Both uplinks mirrored ⇒ inter-leaf reply captured regardless of ECMP hash.
6. **Single IDS, single eve.json, single REST API** (`:8765`). 4 capture NICs (one per LEAF mirror), each in its own `af-packet` cluster.
7. **Runtime enforcement via Secure Framework gNMI**, not console. Console/telnet is build-time/recovery only.

---

## 1. Topology

Full Clos: every LEAF connects to BOTH spines (8 spine-leaf links). 8 zones (2 per leaf). 16 hosts (2 per zone). All zones are internal east-west tiers (no DMZ).

The legitimate east-west chain (backbone of threat-response scenarios):

```
  WEB ──▶ APP-GW ──▶ APP-CORE ──┬──▶ WORKER ──▶ DB-OLTP ──▶ DB-ANALYTICS
                                └──▶ DB-OLTP
   MONITORING ──(scrape)──▶ all tiers          MGT ──(admin)──▶ all tiers
```

```
            NAT-mgmt-LEAF-1   NAT1   NAT2          NAT-mgmt-LEAF-2
                    \         /        \                /
                     \       /          \              /
                   SONIC-SPINE  ←ECMP→  SONIC-SPINE-2
                   /  /  \  \           /  /  \  \
                  /  /    \  \         /  /    \  \
                 IDS-Suricata (passive SPAN, 4 capture NICs)
                  |  |     |  |        |  |     |  |
              SONIC-LEAF-1  LEAF-2  LEAF-3  SONIC-LEAF-4
              /|\\         /|\\    /|\\         /|\\
        WEB DB-OLTP    APP MGT  APP-GW DB-ANLT  WORKER MON
        (×2 each)      (×2)     (×2)            (×2)
```

---

## 2. Node Inventory (live console ports)

| Node | Role | Console | OS | Persistence |
|---|---|---|---|---|
| **SONIC-SPINE** | Core 1 (transit) | `telnet …:5006` | SONiC-VS (sonic-30-1-2026-test) | disk → `/etc/sonic/fix-routes.sh` |
| **SONIC-SPINE-2** | Core 2 (transit, NEW) | `telnet …:5023` | SONiC-VS | disk → `/etc/sonic/fix-routes.sh` |
| **SONIC-LEAF-1** | PEP for WEB + DB-OLTP | `telnet …:5010` | SONiC-VS | disk → setup-mirror.sh + fix-routes.sh |
| **SONIC-LEAF-2** | PEP for APP-CORE + MGT | `telnet …:5015` | SONiC-VS | same |
| **SONIC-LEAF-3** | PEP for APP-GW + DB-ANLT (NEW) | `telnet …:5025` | SONiC-VS | same |
| **SONIC-LEAF-4** | PEP for WORKER + MON (NEW) | `telnet …:5027` | SONiC-VS | same |
| **IDS-Suricata** | Passive IDS (4 captures + 1 mgmt) | `telnet …:5012` | Alpine 3.23 ISO **tmpfs** | bundle `ids-vm/`, redeploy each reboot |
| WEB-1 (.10), WEB-2 (.11) | hosts (LEAF-1 Vlan100) | 5008 / 5029 | Alpine ISO tmpfs | bootstrap each reboot |
| DB-OLTP-1, DB-OLTP-2 | hosts (LEAF-1 Vlan200) | 5011 / 5031 | Alpine ISO tmpfs | bootstrap |
| APP-CORE-1, APP-CORE-2 | hosts (LEAF-2 Vlan100) | 5014 / 5033 | Alpine ISO tmpfs | bootstrap |
| MGT-1, MGT-2 | hosts (LEAF-2 Vlan300) | 5016 / 5035 | Alpine ISO tmpfs | bootstrap |
| APP-GW-1, APP-GW-2 | hosts (LEAF-3 Vlan100, NEW) | 5037 / 5039 | Alpine ISO tmpfs | bootstrap |
| DB-ANALYTICS-1, DB-ANALYTICS-2 | hosts (LEAF-3 Vlan200, NEW) | 5041 / 5043 | Alpine ISO tmpfs | bootstrap |
| WORKER-1, WORKER-2 | hosts (LEAF-4 Vlan100, NEW) | 5045 / 5047 | Alpine ISO tmpfs | bootstrap |
| MONITORING-1, MONITORING-2 | hosts (LEAF-4 Vlan200, NEW) | 5049 / 5051 | Alpine ISO tmpfs | bootstrap |

**Login credentials:**
- SONiC: `admin` / `YourPaSsWoRd`
- Alpine: `root` (no password)

> Telnet console host = `127.0.0.1` if running on the GNS3VM directly, else `112.137.129.232` (public NAT) or `10.10.6.238` (LAN).

---

## 3. IP Plan

### 3.1 Underlay /30 (8 point-to-point links)

| Link | Subnet | SPINE side | LEAF side | LEAF NIC |
|---|---|---|---|---|
| SPINE-1 ↔ LEAF-1 | 10.0.1.0/30 | 10.0.1.1 (eth1) | 10.0.1.2 | eth0 |
| SPINE-1 ↔ LEAF-2 | 10.0.2.0/30 | 10.0.2.1 (eth2) | 10.0.2.2 | eth0 |
| SPINE-1 ↔ LEAF-3 | 10.0.3.0/30 | 10.0.3.1 (eth3) | 10.0.3.2 | eth0 |
| SPINE-1 ↔ LEAF-4 | 10.0.4.0/30 | 10.0.4.1 (eth4) | 10.0.4.2 | eth0 |
| SPINE-2 ↔ LEAF-1 | 10.0.5.0/30 | 10.0.5.1 (eth1) | 10.0.5.2 | eth5 |
| SPINE-2 ↔ LEAF-2 | 10.0.6.0/30 | 10.0.6.1 (eth2) | 10.0.6.2 | eth5 |
| SPINE-2 ↔ LEAF-3 | 10.0.7.0/30 | 10.0.7.1 (eth3) | 10.0.7.2 | eth5 |
| SPINE-2 ↔ LEAF-4 | 10.0.8.0/30 | 10.0.8.1 (eth4) | 10.0.8.2 | eth5 |

### 3.2 Overlay /24 per zone

| Zone | LEAF | VLAN | SVI gw | CIDR | host-1 / host-2 |
|---|---|---|---|---|---|
| WEB | LEAF-1 | Vlan100 | 10.1.100.1 | 10.1.100.0/24 | .10 / .11 |
| DB-OLTP | LEAF-1 | Vlan200 | 10.1.200.1 | 10.1.200.0/24 | .10 / .11 |
| APP-CORE | LEAF-2 | Vlan100 | 10.2.100.1 | 10.2.100.0/24 | .10 / .11 |
| MGT | LEAF-2 | Vlan300 | 10.2.50.1 | 10.2.50.0/24 | .10 / .11 |
| APP-GW | LEAF-3 | Vlan100 | 10.3.100.1 | 10.3.100.0/24 | .10 / .11 |
| DB-ANALYTICS | LEAF-3 | Vlan200 | 10.3.200.1 | 10.3.200.0/24 | .10 / .11 |
| WORKER | LEAF-4 | Vlan100 | 10.4.100.1 | 10.4.100.0/24 | .10 / .11 |
| MONITORING | LEAF-4 | Vlan200 | 10.4.200.1 | 10.4.200.0/24 | .10 / .11 |

### 3.3 Out-of-band management

| Interface | IP | Purpose |
|---|---|---|
| GNS3VM host eth0 | 10.10.6.238 (LAN) / 112.137.129.232 (public NAT) | Control plane entrypoint |
| virbr0 (libvirt bridge) | 192.168.122.1/24 | Mgmt network → SONiC mgmt + IDS eth2 |
| LEAF-1 eth1 (NAT-mgmt) | 192.168.122.20 | SONiC mgmt |
| LEAF-2 eth1 (NAT-mgmt) | 192.168.122.21 | SONiC mgmt |
| **IDS eth2** | **192.168.122.205** | **REST API `:8765` exposure** (libvirt DNAT host:8765 → guest:8765) |

> SPINE-1 and SPINE-2 mgmt: SPINE-1:eth0 ↔ NAT1; SPINE-2 does not have a dedicated mgmt NAT link in current deployment (transit-only).
> LEAF-3 and LEAF-4: no mgmt NAT in current deployment (console-only access during build).

---

## 4. VLAN / SVI per LEAF (as configured in SONiC config_db)

| LEAF | Vlan100 SVI | Vlan200 SVI | Vlan300 SVI | Vlan100 members | Vlan200/300 members |
|---|---|---|---|---|---|
| LEAF-1 | 10.1.100.1/24 (WEB) | 10.1.200.1/24 (DB-OLTP) | — | Ethernet4 (eth2), Ethernet24 (eth6) | V200: Ethernet8, Ethernet28 |
| LEAF-2 | 10.2.100.1/24 (APP-CORE) | — | 10.2.50.1/24 (MGT) | Ethernet4, Ethernet24 | V300: Ethernet8, Ethernet28 |
| LEAF-3 | 10.3.100.1/24 (APP-GW) | 10.3.200.1/24 (DB-ANLT) | — | Ethernet4, Ethernet24 | V200: Ethernet8, Ethernet28 |
| LEAF-4 | 10.4.100.1/24 (WORKER) | 10.4.200.1/24 (MON) | — | Ethernet4, Ethernet24 | V200: Ethernet8, Ethernet28 |

> **SONiC port-name mapping (offset!):** GNS3 adapter N → kernel ethN → SONiC `Ethernet(N×4-4)` for N≥1. So adapter 2 (eth2) = SONiC `Ethernet4`, adapter 6 (eth6) = `Ethernet24`, adapter 7 (eth7) = `Ethernet28`. Adapter 0 (eth0) = SONiC `Ethernet0`.

---

## 5. Routing — ECMP over both spines

### 5.1 LEAF static routes (live on every LEAF)

```bash
# Example: LEAF-1 (uplink_1=10.0.1.2 to SPINE-1, uplink_2=10.0.5.2 to SPINE-2)
ip route add 10.0.1.1/32 dev eth0 src 10.0.1.2     # /32 host route (SONiC-VS ARP-fail bypass)
ip route add 10.0.5.1/32 dev eth5 src 10.0.5.2     # same for 2nd spine
ip route replace 10.2.0.0/16 nexthop via 10.0.1.1 dev eth0 nexthop via 10.0.5.1 dev eth5
ip route replace 10.3.0.0/16 nexthop via 10.0.1.1 dev eth0 nexthop via 10.0.5.1 dev eth5
ip route replace 10.4.0.0/16 nexthop via 10.0.1.1 dev eth0 nexthop via 10.0.5.1 dev eth5
```

Per-leaf nexthops:

| LEAF | SPINE-1 nh | SPINE-2 nh | Remote /16 routed via ECMP |
|---|---|---|---|
| LEAF-1 | 10.0.1.1 | 10.0.5.1 | 10.2/16, 10.3/16, 10.4/16 |
| LEAF-2 | 10.0.2.1 | 10.0.6.1 | 10.1/16, 10.3/16, 10.4/16 |
| LEAF-3 | 10.0.3.1 | 10.0.7.1 | 10.1/16, 10.2/16, 10.4/16 |
| LEAF-4 | 10.0.4.1 | 10.0.8.1 | 10.1/16, 10.2/16, 10.3/16 |

### 5.2 SPINE static routes (live on each SPINE)

```bash
# SPINE-1
ip route replace 10.1.0.0/16 via 10.0.1.2       # → LEAF-1
ip route replace 10.2.0.0/16 via 10.0.2.2       # → LEAF-2
ip route replace 10.3.0.0/16 via 10.0.3.2       # → LEAF-3
ip route replace 10.4.0.0/16 via 10.0.4.2       # → LEAF-4
# SPINE-2 (symmetric via 10.0.5.2 / 10.0.6.2 / 10.0.7.2 / 10.0.8.2)
```

### 5.3 SONiC-VS gotcha — `/32` host route per spine nexthop

SONiC-VS install route `10.0.X.0/30 dev EthernetN metric 0` (virtual NIC ARP fail) that shadows kernel `dev eth0`. Inject `/32` host route per spine nexthop on EVERY leaf to bypass:

```bash
ip route add SPINE_NH/32 dev eth0 src LEAF_UPLINK_IP   # for each spine uplink
```

---

## 6. Traffic Tap — IDS as Passive Mirror (SPAN)

### 6.1 Mechanism

East-west traffic flows the normal way `host → LEAF → SPINE → LEAF → host`. **Each LEAF mirrors a copy** to its eth4 cable, directly wired to one IDS capture NIC. IDS is **passive** (ip_forward=0, no lab routes, never touched by data plane).

```
   hosts (zone A, zone B)
        │
        ▼
   SONIC-LEAF-N
   ┌──────────────────────────────────────┐
   │ tc clsact + mirred ingress + egress  │
   │   on eth0 (SPINE-1 uplink)            │  → eth4 ──→ IDS:ethN
   │   on eth5 (SPINE-2 uplink)            │            (promiscuous, no IP)
   │   on eth2,eth3,eth6,eth7 (host ports)│
   └──────────────────────────────────────┘
```

### 6.2 Wiring (verify via GNS3 API)

| LEAF | LEAF mirror dest | ↔ | IDS capture NIC | af-packet cluster |
|---|---|---|---|---|
| LEAF-1 | eth4 (Ethernet16) | ↔ | IDS:eth0 | cluster-id 98 |
| LEAF-2 | eth4 | ↔ | IDS:eth1 | cluster-id 99 |
| LEAF-3 | eth4 | ↔ | IDS:eth3 | cluster-id 100 |
| LEAF-4 | eth4 | ↔ | IDS:eth4 | cluster-id 101 |
| (IDS:eth2 ↔ NAT2) | | | mgmt 192.168.122.205, REST :8765 | — |

### 6.3 Per-LEAF mirror config (live shell commands; auto-applied by `/etc/sonic/setup-mirror.sh` on boot)

```bash
for iface in eth0 eth2 eth3 eth5 eth6 eth7; do
    /usr/sbin/tc qdisc del dev $iface clsact 2>/dev/null
    /usr/sbin/tc qdisc add dev $iface clsact
    /usr/sbin/tc filter add dev $iface ingress matchall action mirred egress mirror dev eth4
    /usr/sbin/tc filter add dev $iface egress  matchall action mirred egress mirror dev eth4
done
ip link set eth4 up promisc on
```

> ⚠️ Use full path `/usr/sbin/tc` because admin shell `PATH` lacks `/sbin`.
> ⚠️ To verify, use `tc filter show dev XXX ingress` (or `egress`) — `tc filter show dev XXX` alone does NOT list clsact filters and will report empty.

### 6.4 Asymmetric capture artifact

A single inter-leaf flow may show up as multiple flow-records in eve.json (request and reply mirrored on different LEAVES → different `cluster-id` → different in_iface). This is normal SPAN dup behavior, not a defect. Rules use `flags:S` + `flow:to_server` to be robust.

---

## 7. Microsegmentation Policy — 8×8 East-West Matrix

### 7.1 Policy matrix (source row → dest col)

| src ↓ \ dst → | WEB | APP-GW | APP-CORE | WORKER | DB-OLTP | DB-ANLT | MON | MGT |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **WEB** | — | A | D | D | D | D | D | D |
| **APP-GW** | D | — | A | D | D | D | D | D |
| **APP-CORE** | D | D | — | A | A | A | D | D |
| **WORKER** | D | D | D | — | A | D | D | D |
| **DB-OLTP** | D | D | D | D | — | A | D | D |
| **DB-ANALYTICS** | D | D | D | D | D | — | D | D |
| **MONITORING** | A | A | A | A | A | A | — | D |
| **MGT** | A | A | A | A | A | A | A | — |

A = ALLOW, D = DENY. Legend: DB-ANLT = DB-ANALYTICS, MON = MONITORING.

### 7.2 Enforcement (per LEAF, iptables FORWARD)

Each LEAF gets a fresh ruleset covering every flow where source OR destination is a local zone (defense-in-depth):

```bash
iptables -P FORWARD DROP
iptables -F FORWARD
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# per allowed cell touching local zones:
iptables -A FORWARD -s <src_cidr> -d <dst_cidr> -j ACCEPT
# … repeat …
iptables -A FORWARD -j DROP
```

**Generator script**: [`dc-fabric-setup/v2-apply-policy.py`](dc-fabric-setup/v2-apply-policy.py) — push to all 4 leaves via GNS3 console. Idempotent.

### 7.3 Zone / leaf helper for control plane

```python
ZONES = {
  "10.1.100.": "WEB",        "10.1.200.": "DB-OLTP",
  "10.2.100.": "APP-CORE",   "10.2.50.":  "MGT",
  "10.3.100.": "APP-GW",     "10.3.200.": "DB-ANALYTICS",
  "10.4.100.": "WORKER",     "10.4.200.": "MONITORING",
}
LEAF_OF_PREFIX = {
  "10.1.": "SONIC-LEAF-1", "10.2.": "SONIC-LEAF-2",
  "10.3.": "SONIC-LEAF-3", "10.4.": "SONIC-LEAF-4",
}

def ip_to_zone(ip):
    for p, z in ZONES.items():
        if ip.startswith(p): return z
    return None

def ip_to_leaf(ip):
    for p, leaf in LEAF_OF_PREFIX.items():
        if ip.startswith(p): return leaf
    return None
```

---

## 8. Realistic Datacenter Traffic (cron-driven east-west)

### 8.1 Service inventory per zone (live on each host)

| Zone | Service(s) | Port(s) | Implementation |
|---|---|---|---|
| WEB | http banner | 80 | `nc -l -p 80 < /tmp/banner-80` (busybox extras) |
| APP-GW | api-gateway banner | 8080 | `nc -l -p 8080 < /tmp/banner-8080` |
| APP-CORE | core-service banner | 8090 | `nc -l -p 8090 < /tmp/banner-8090` |
| WORKER | job-intake | 8082 | `nc -l -p 8082 < /tmp/banner-8082` |
| DB-OLTP | pg-mock SQL responder | 5432 | `socat TCP-LISTEN:5432,fork EXEC:/usr/local/bin/db-reply.sh,pipes` |
| DB-ANALYTICS | pg-mock SQL responder | 5432 | same |
| MONITORING | metrics endpoint | 9090 | `nc -l -p 9090 < /tmp/banner-9090` |
| MGT | (admin source only) | — | no service |

**pg-mock behavior**: returns terse `PG_OK row_count=42 ts=<epoch>` for normal queries; returns 80 rows of `row_NNN | …` (~5KB) when query contains `JOIN` or `SELECT *` (triggers DB-bulk-reply detection rule).

### 8.2 Cron-driven east-west generators (verified active 2026-05-31)

Verified by eve.json analysis — all 10 chains firing:

| Cron source | → Flow | Cadence | Status |
|---|---|---|---|
| WEB → APP-GW:8080 | 30s | ✓ 18 flows captured |
| APP-GW → APP-CORE:8090 | 30s | ✓ 18 flows |
| APP-CORE → DB-OLTP:5432 (SQL) | 30s | ✓ 18 flows |
| APP-CORE → WORKER:8082 (dispatch) | 45s | ✓ 16 flows |
| WORKER → DB-OLTP:5432 (persist) | 45s | ✓ 18 flows |
| APP-CORE → DB-ANALYTICS:5432 | 60s | ✓ 10 flows |
| DB-OLTP → DB-ANALYTICS:5432 (ETL) | 2 min | ✓ 8 flows |
| MONITORING → {WEB:80, APP-GW:8080, APP-CORE:8090, WORKER:8082, DB-OLTP:5432, DB-ANALYTICS:5432} (scrape) | 60s | ✓ ~16 flows/dest |
| MGT → {WEB/APP-CORE/WORKER/APP-GW}:22 (audit, rotating) | 2 min | ✓ 4-8 flows |
| MGT → APP-CORE:22 (logpull) | 5 min | ✓ counted in audit |

Generator script: [`dc-fabric-setup/v2-bootstrap-hosts.py`](dc-fabric-setup/v2-bootstrap-hosts.py) — call with hostname or zone name to (re)bootstrap.

**Steady-state baseline**: ~250-500 flows/min; ~1-2 P4 audit alerts/min total (SID 9000080 MGT access, 9000081 MON aggregation — both `threshold:limit` rate-capped); **0 P1/P2/P3 false positives** on baseline DCN cron (verified 2026-05-31 14:46 UTC).

### 8.3 Attack scenarios (templates for control plane to trigger)

Each scenario compromises one tier and attempts a forbidden east-west move. The control plane agent must contain the source without breaking the legitimate chain. Expected SIDs reference §9.1.1 V2 mapping.

| Scenario | Host | Forbidden move (matching DENY cell) | Expected V2 SIDs |
|---|---|---|---|
| compromise-web-dbbypass | WEB-1 | WEB → DB-OLTP:5432 | 9000001 + 9000012 (defense-in-depth) |
| compromise-web-gwbypass | WEB-1 | WEB → APP-CORE:8090 (skip APP-GW) | 9000002 |
| compromise-appgw-dbbypass | APP-GW-1 | APP-GW → DB-OLTP:5432 | 9000004 + 9000012 |
| compromise-appcore-exfil | APP-CORE-1 | APP-CORE → DB-ANALYTICS bulk SELECT + outbound | 9000070 / 9000071 (SQL content) + 9000062 (DB exfil to external) |
| compromise-appcore-lateral | APP-CORE-1 | APP-CORE → WEB:22 / GW:any | 9000006 (P2 reverse) + 9000011 if dest=MGT |
| compromise-worker-reverse | WORKER-1 | WORKER → APP-GW:8080 (reverse) | 9000008 |
| compromise-dboltp-c2 | DB-OLTP-1 | DB-OLTP → external:443 (C2 beacon) | 9000009 (DB-OLTP outbound) + 9000062 (DB exfil) + 9000060 (beacon dsize) |
| compromise-dbanalytics-pivot | DB-ANALYTICS-1 | DB-ANALYTICS → anything | 9000010 (sink violated) |

---

## 9. Detection Rules — Suricata 8.0.0

### 9.1 Active rule set (live, 29 SIDs — V2 rewrite 2026-05-31)

File `/etc/suricata/rules/zt-lab.rules` (source `ids-vm/rules/zt-lab.rules`).
Loaded: `29 rules successfully loaded, 0 rules failed`. Smoke-tested: 4 deliberate
violations from WEB host fired 8 alerts across 4 expected SIDs, baseline DCN
cron traffic fires zero P1/P2 (only P4 audit limited to 1/min).

All rules use per-zone vars from `suricata-zt.yaml` (§9.3) — no hard-coded CIDRs.

| Cat | SID range | Count | Description | Priority |
|---|---|---|---|---|
| 1. V2 policy violations (8×8 DENY cells) | 9000001–9000013 | 13 | One rule per critical DENY cell of §7.1 matrix | P1 (12), P2 (1) |
| 2. Reconnaissance — Yatesbury | 9000040–9000044 | 5 | ICMP sweep, vertical scan, key-ports probe, UDP scan, multi-stage chain | P3 |
| 3. Flooding — Yatesbury | 9000050–9000052 | 3 | SYN flood single-src, SYN DDoS contribution, UDP flood | P2 |
| 4. C2 / tunneling / exfil | 9000060–9000062 | 3 | Beacon, DNS amp, DB-tier outbound-to-external | P1/P2 |
| 5. DB content — Yatesbury L7 | 9000070–9000072 | 3 | UNION SELECT, OR 1=1, destructive SQL (DROP/TRUNCATE/DELETE) | P1 |
| 6. Audit (low-rate logging) | 9000080–9000081 | 2 | MGT-initiated session, MON aggregation — `threshold:limit` 1/60s and 1/300s | P4 |

#### 9.1.1 V2 policy-violation SID map (Category 1)

Each SID encodes one or more DENY cells from the 8×8 matrix (§7.1). Control plane
agent can use this map to translate alert → which policy cell was violated.

| SID | Source zone | Destination zones | Rationale |
|-----|-------------|-------------------|-----------|
| 9000001 | `Z_WEB` | `Z_DBO`, `Z_DBA` :5432/3306/1433/27017 | WEB direct to any DB — bypass APP-GW + APP-CORE |
| 9000002 | `Z_WEB` | `Z_APP`, `Z_WK` :any | WEB skips APP-GW into app tier |
| 9000003 | `Z_WEB` | `Z_MGT`, `Z_MON` :any | WEB to control/observability tier |
| 9000004 | `Z_GW`  | `Z_DBO`, `Z_DBA` :DB-ports | APP-GW direct to DB — skips APP-CORE |
| 9000005 | `Z_GW`  | `Z_WEB`, `Z_WK`, `Z_MGT`, `Z_MON` :any | APP-GW lateral / reverse |
| 9000006 | `Z_APP` | `Z_WEB`, `Z_GW` :any | APP-CORE reverse call to web tier (P2 — lateral) |
| 9000007 | `Z_APP` | `Z_MGT`, `Z_MON` :any | APP-CORE to control tier |
| 9000008 | `Z_WK`  | `Z_WEB`, `Z_GW`, `Z_APP`, `Z_DBA`, `Z_MGT`, `Z_MON` :any | WORKER lateral (only DB-OLTP allowed) |
| 9000009 | `Z_DBO` | all non-DBA :any | DB-OLTP outbound — sink role, only replication to DBA allowed |
| 9000010 | `Z_DBA` | `Z_ALL` :any | DB-ANALYTICS outbound — pure sink, must never init |
| 9000011 | `![Z_MGT,Z_MON]` | `Z_MGT` :any | Inbound to MGT from non-control |
| 9000012 | `![Z_APP,Z_WK,Z_MON,Z_MGT,Z_DBO,Z_DBA]` | `Z_DB_ANY` :DB-ports | Generic unauthorized DB connection (defense-in-depth with 9000001/9000004) |
| 9000013 | `Z_WK`  | `Z_DBA` :any | WORKER cross-tier to analytics DB |

**Defense-in-depth design**: most violations fire **2 SIDs** — one specific (zone-pair) and one generic (`9000011` MGT, `9000012` DB). Control plane can correlate: same flow + 2 SIDs = high confidence; 1 SID = lower.

#### 9.1.2 Smoke-test result (2026-05-31 14:46 UTC, verified)

```
Attack injected from WEB (10.1.100.10)         Fired SIDs
─────────────────────────────────────────────  ──────────────────────────
→ DB-OLTP    (10.1.200.10:5432)                9000001 + 9000012  ✓
→ APP-CORE   (10.2.100.10:8090)                9000002             ✓
→ MGT        (10.2.50.10:22)                   9000003 + 9000011   ✓
→ DB-ANALYT  (10.3.200.10:5432)                9000001 + 9000012  ✓
```

Baseline DCN cron traffic (§8.2) during smoke window fired **only** `9000080`
(MGT audit) and `9000081` (MON aggregation) at their threshold-limited rate.
Zero false positives on P1/P2 SIDs.

### 9.2 Config (`suricata-zt.yaml` on IDS)

```yaml
vars:
  address-groups:
    HOME_NET: "[10.1.0.0/16,10.2.0.0/16,10.3.0.0/16,10.4.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    # V2 per-zone CIDRs — used by zt-lab.rules to encode 8x8 matrix
    Z_WEB: "10.1.100.0/24"
    Z_DBO: "10.1.200.0/24"
    Z_APP: "10.2.100.0/24"
    Z_MGT: "10.2.50.0/24"
    Z_GW:  "10.3.100.0/24"
    Z_DBA: "10.3.200.0/24"
    Z_WK:  "10.4.100.0/24"
    Z_MON: "10.4.200.0/24"
    Z_DB_ANY:   "[$Z_DBO,$Z_DBA]"
    Z_APP_TIER: "[$Z_APP,$Z_GW,$Z_WK]"
    Z_ALL:      "[$Z_WEB,$Z_DBO,$Z_APP,$Z_MGT,$Z_GW,$Z_DBA,$Z_WK,$Z_MON]"
af-packet:
  - { interface: eth0, cluster-id: 98,  cluster-type: cluster_flow, defrag: yes }  # LEAF-1 mirror
  - { interface: eth1, cluster-id: 99,  cluster-type: cluster_flow, defrag: yes }  # LEAF-2 mirror
  - { interface: eth3, cluster-id: 100, cluster-type: cluster_flow, defrag: yes }  # LEAF-3 mirror
  - { interface: eth4, cluster-id: 101, cluster-type: cluster_flow, defrag: yes }  # LEAF-4 mirror
stream:
  midstream: true              # tolerate cluster-split asymmetric capture
  midstream-policy: pass-flow
  async-oneside: true
outputs:
  - fast:    { enabled: yes, filename: fast.log }
  - eve-log: { enabled: yes, filename: eve.json, types: [alert, flow] }
default-rule-path: /etc/suricata/rules
rule-files: [zt-lab.rules]
app-layer:
  protocols: { tls: {enabled: yes}, dns: {enabled: yes}, http: {enabled: yes} }
detect: { profile: low }
max-pending-packets: 512
```

⚠️ **Reload**: `kill -USR2` is a **NO-OP** on this build (no `detect-engine: rule-reload` in yaml). To reload rules, **must** `rc-service suricata-zt restart`. Always `suricata -T -c /etc/suricata/suricata-zt.yaml` first.

### 9.3 Note for control plane — closing the SF→IDS feedback loop

Suricata SIDs in Category 1 (9000001–9000013) are designed so the control plane
can map alert → violated policy cell mechanically:

1. Parse `eve.json` alert → extract `alert.signature_id` + `src_ip` + `dest_ip` + `dest_port`.
2. Map `signature_id` → policy cell via §9.1.1 table.
3. Lookup `src_ip` zone and `dest_ip` zone using §7.3 zone-of(ip) helper.
4. If cell is still DENY in current matrix → push counter-action (e.g., refine
   iptables rule via SF→bridge gNMI Set, or trigger workload isolation).

Compared to V1: V2 alerts include the source zone in the SID semantics, so
control plane can reason "which microsegmentation boundary was breached" without
running a CIDR-classifier on every alert.

---

## 10. Persistence & Recovery (critical for paper reproducibility)

### 10.1 SONiC LEAF / SPINE (persistent disk)

Files installed at `/etc/sonic/`, auto-invoked by `/etc/rc.local`:

```bash
# /etc/rc.local additions (verified on all 6 SONiC nodes)
/etc/sonic/fix-routes.sh &
/etc/sonic/setup-mirror.sh &    # LEAVES only — SPINEs don't mirror
```

**`/etc/sonic/setup-mirror.sh`** (LEAF only):
```bash
#!/bin/bash
sleep 100                        # wait for SONiC services
for iface in eth0 eth2 eth3 eth5 eth6 eth7; do
    tc qdisc del dev $iface clsact 2>/dev/null
    tc qdisc add dev $iface clsact
    tc filter add dev $iface ingress matchall action mirred egress mirror dev eth4
    tc filter add dev $iface egress  matchall action mirred egress mirror dev eth4
done
ip link set eth4 up promisc on
```

**`/etc/sonic/fix-routes.sh`** (per-leaf, different IPs):
```bash
#!/bin/bash
sleep 90
sysctl -w net.ipv4.ip_forward=1
for iface in $(ls /proc/sys/net/ipv4/conf/); do sysctl -w net.ipv4.conf.$iface.forwarding=1 2>/dev/null; done
ip link set eth0 up; ip addr add LEAF_UPLINK_1/30 dev eth0 2>/dev/null
ip link set eth5 up; ip addr add LEAF_UPLINK_2/30 dev eth5 2>/dev/null
ip route add SPINE1_NH/32 dev eth0 src LEAF_UPLINK_1
ip route add SPINE2_NH/32 dev eth5 src LEAF_UPLINK_2
# ECMP for each remote /16
ip route replace 10.X.0.0/16 nexthop via SPINE1_NH dev eth0 nexthop via SPINE2_NH dev eth5
# Mgmt (LEAF-1/-2 only): ip addr add 192.168.122.20/24 dev eth1
```

### 10.2 IDS-Suricata (Alpine ISO **tmpfs** — wiped on reboot)

Bundle at `/3s-com/zma/ids-vm/`:
- `redeploy.sh` — **self-contained** (network up, internet apk repos, install python3+suricata+curl, install bundle files, start services)
- `suricata-zt.yaml` — config (4-cluster, HOME_NET 10.1-4)
- `rules/zt-lab.rules` — 29-SID V2 ruleset (8×8 policy violations + Yatesbury benchmark)
- `ids-api.py` — REST + SSE server
- `ids-api.openrc` + `suricata.openrc` — OpenRC services

**Post-reboot recovery**: push bundle via GNS3 console heredoc/base64 + run `redeploy.sh`. See script comments.

### 10.3 Alpine hosts (Alpine ISO **tmpfs**)

Bootstrap via [`dc-fabric-setup/v2-bootstrap-hosts.py`](dc-fabric-setup/v2-bootstrap-hosts.py) — per-host bootstrap script sets IP, default route, installs services (nc banner / socat pg-mock), starts cron generators. Idempotent.

### 10.4 Known gotchas (from build experience)

- **QEMU NIC carrier bug** after `adapters` count change: requires cold-plug (stop node → delete link → recreate link → start node) per affected link.
- **SONiC console `tc` PATH issue**: admin shell lacks `/sbin`, so `tc` errors with "command not found". Use full path `/usr/sbin/tc`.
- **SONiC `config vlan member add` requires port out of "routed" mode first**:
  ```bash
  config interface ip remove EthernetN <auto_IP>     # detect via `ip addr show EthernetN`
  config interface shutdown EthernetN
  config vlan member add -u <vid> EthernetN
  config interface startup EthernetN
  ```
- **SONiC port-name mapping is OFFSET**: kernel ethN ↔ SONiC `Ethernet((N-1)×4)` for N≥1, plus `Ethernet0` = eth0. See §4 note.
- **GNS3 GUI red link labels** after cold-plug = GUI cache stale, not real DOWN. Close+reopen project to refresh.
- **Alpine ISO has no internet apk repos by default** (CDROM only with ~100 packages). Bundle scripts add `dl-cdn.alpinelinux.org/.../main + community` then `apk add` works.

---

## 11. North-Bound API for Control Plane Integration

### 11.1 IDS Alert API (Suricata side)

Base URL: `http://10.10.6.238:8765` (LAN) / `http://112.137.129.232:8765` (public NAT)
Source: `/usr/local/bin/ids-api.py` in IDS VM. Memory-bounded ring buffers (alerts + flows, deque maxlen 2000 each), background tail of eve.json.

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{status, suricata: bool, ring_alerts, ring_flows, sse_clients, uptime_sec, ts}` |
| GET | `/alerts?last=N&since=ts` | `{count, summary{sid:n}, alerts[]}` — slice from ring |
| GET | `/alerts/clear` | `{cleared_at: ts}` — anchor for client `?since=` |
| GET | `/flows?last=N&since=ts` | `[flow objects]` — slice, cap 500/req |
| GET | `/stream` | SSE — alert events; heartbeat `: hb` every 15s; cap 8 clients |
| GET | `/service-health` | passive flow-inference: `{services:[{name,ip,port,zone,status:up\|unknown}], method}` |

### 11.2 Enforcement Targets — only LEAVES enforce policy

| Switch | Enforce microseg? | Reason |
|---|:-:|---|
| SONIC-SPINE, SONIC-SPINE-2 | ❌ | Pure transit, no host attached |
| **SONIC-LEAF-1..4** | ✅ | Terminate Vlan SVIs, enforce per §7 matrix via iptables |

**Rule push path**: control plane → Secure Framework gNMI → nos-acl-bridge → iptables FORWARD on target LEAF.

### 11.3 Suggested control plane workflow

```
1. Subscribe SSE: GET /stream (or fallback poll /alerts?since=anchor)
2. On P1/P2 alert:
   a. ip_to_zone(src_ip) + ip_to_leaf(src_ip) → identify offending zone & enforcement LEAF
   b. Validate against §7 matrix (is this flow truly forbidden?)
   c. Generate targeted DROP rule (e.g., `iptables -I FORWARD 1 -s <src> -j DROP`)
   d. Push via gNMI → applies on the source LEAF (best) and dest LEAF (defense-in-depth)
   e. Schedule TTL unblock (e.g., 5 min P1, 30 min P2, 1h P3)
3. Status feedback:
   a. POST decision event → dashboard + Postgres audit trail
   b. Update Knowledge Graph (zone trust score, MITRE mapping)
```

### 11.4 Alert JSON schema (eve.json `event_type: alert`)

```json
{
  "timestamp": "2026-05-31T09:34:14Z",
  "event_type": "alert",
  "src_ip": "10.1.100.10",
  "dest_ip": "10.1.200.10",
  "src_port": 54321,
  "dest_port": 5432,
  "proto": "TCP",
  "in_iface": "eth0",
  "alert": {
    "signature": "[ZT-VIOLATION] WEB direct to DB - microsegmentation bypass",
    "signature_id": 9000001,
    "severity": 1,
    "category": "policy-violation"
  }
}
```

### 11.5 Flow JSON schema (eve.json `event_type: flow`)

```json
{
  "timestamp": "...",
  "event_type": "flow",
  "src_ip": "10.2.100.10",
  "dest_ip": "10.1.200.10",
  "dest_port": 5432,
  "proto": "TCP",
  "in_iface": "eth1",
  "app_proto": "failed",
  "flow": { "pkts_toserver": 27, "pkts_toclient": 40, "bytes_toserver": 1932, "bytes_toclient": 2860, "state": "closed", "reason": "timeout" }
}
```

> `app_proto: "failed"` for port 5432 = pg-mock isn't real PostgreSQL wire-protocol; Suricata 8 build also lacks pgsql parser. Cosmetic, does not affect content/raw-match rules.

---

## 12. Verification Cookbook (for agent to self-check)

| Check | Method | Expected |
|---|---|---|
| Underlay reachable | from each SONiC node: `ping <peer-/30-ip>` | all 16 directions pass (8 LEAF→SPINE + 8 SPINE→LEAF) |
| ECMP active | `ip route get <remote-zone-ip>` on a LEAF | 2 nexthops (one per spine) — or singleton if one path linkdown (still OK) |
| Cross-leaf host-host | from host: `ping <remote-zone-host>` | reply received if ALLOW per §7 |
| Policy DROP | from forbidden src: `nc -zv <DENY-dst-ip> <port>` | connection refused/timeout; alert fires on IDS |
| Mirror active | on each LEAF: `tc filter show dev eth0 ingress \| grep -c mirred` | should return 1 (clsact + mirred installed) |
| IDS sees all 4 LEAVES | `curl :8765/flows?last=500` then count `in_iface` | flows present on eth0, eth1, eth3, eth4 |
| Suricata 29 rules (V2) | startup log on IDS | `29 rules successfully loaded, 0 rules failed` |
| eve.json types | `tail -200 /var/log/suricata/eve.json \| jq -r .event_type \| sort -u` | only `alert` and `flow` |
| East-west chain | `curl :8765/flows?last=2000` + count zone→zone | 10 expected chains from §8.2 all > 0 |
| 0 P1/P2 false positives on baseline | `curl :8765/alerts?last=200 \| jq '.summary'` (during clean baseline) | only 9000080 (MGT audit) + 9000081 (MON audit) |
| Smoke-test policy SIDs fire | `nc -w2 10.1.200.10 5432` from WEB host | within 5s: 9000001 + 9000012 in fast.log |

---

## 13. Resource Footprint (current)

Host: 20 cores / 46 GB RAM.

| Component | Count | RAM nominal | RAM actual |
|---|:-:|---|---|
| SONIC-SPINE (orig) | 1 | 24 GB | ~6-8 GB |
| SONIC-SPINE-2 (new) | 1 | 8 GB | ~3-5 GB |
| SONIC-LEAF-1/-2 (orig) | 2 | 24 GB each | ~6-8 GB each |
| SONIC-LEAF-3/-4 (new) | 2 | 8 GB each | ~3-5 GB each |
| IDS-Suricata | 1 | 1.5 GB | ~33 MB constant (Suricata) + ~50 MB Python ids-api |
| Alpine hosts | 16 | 512 MB each | ~80-150 MB each (with services) |

Live measured: **~24-28 GB used**, ~18-20 GB free. Comfortable for full lab + experiments + alert burst.

---

## 14. File / Script Reference

| Path | Purpose |
|---|---|
| `/3s-com/zma/DATAPLANE_V2.md` | this doc (as-deployed spec) |
| `/3s-com/zma/ids-vm/` | IDS bundle: `redeploy.sh`, `suricata-zt.yaml`, `ids-api.py`, `rules/zt-lab.rules`, openrc |
| `/3s-com/zma/dc-fabric-setup/v2-apply-policy.py` | 8×8 iptables matrix generator/pusher |
| `/3s-com/zma/dc-fabric-setup/v2-bootstrap-hosts.py` | Per-host bootstrap (IP, services, crons) |
| `/3s-com/zma/dc-fabric-setup/07-apply-policy.py` | v1 policy push (legacy; for reference) |
| `/3s-com/zma/dc-fabric-setup/13-fix-ids-full.py` | Reference for cold-plug + IDS install patterns |
| Inside IDS VM: `/usr/local/bin/ids-api.py` | Active REST API server |
| Inside IDS VM: `/etc/suricata/suricata-zt.yaml` | Active Suricata config |
| Inside IDS VM: `/etc/suricata/rules/zt-lab.rules` | Active 29 SIDs (V2 — encodes 8×8 matrix) |
| On each LEAF: `/etc/sonic/setup-mirror.sh` | Mirror persistence (rc.local auto-run) |
| On each LEAF: `/etc/sonic/fix-routes.sh` | Routes + uplink IPs persistence |
| On SPINEs: `/etc/sonic/fix-routes.sh` | SPINE routes persistence |

---

## 15. Quick-Reference for Control Plane Agent

```python
# Topology constants
GNS3_API   = "http://10.10.6.238:3080/v2"          # or 112.137.129.232:3080
PROJECT_ID = "b6bf1cd6-8d58-41d4-941c-893020abd2a3"
IDS_API    = "http://10.10.6.238:8765"             # or 112.137.129.232:8765

LEAVES = {  # name → console port
    "SONIC-LEAF-1": 5010, "SONIC-LEAF-2": 5015,
    "SONIC-LEAF-3": 5025, "SONIC-LEAF-4": 5027,
}
SPINES = {"SONIC-SPINE": 5006, "SONIC-SPINE-2": 5023}

# Per-leaf enforcement: which zones the leaf owns (for targeted DROP)
LEAF_ZONES = {
    "SONIC-LEAF-1": ["10.1.100.0/24 WEB", "10.1.200.0/24 DB-OLTP"],
    "SONIC-LEAF-2": ["10.2.100.0/24 APP-CORE", "10.2.50.0/24 MGT"],
    "SONIC-LEAF-3": ["10.3.100.0/24 APP-GW", "10.3.200.0/24 DB-ANALYTICS"],
    "SONIC-LEAF-4": ["10.4.100.0/24 WORKER", "10.4.200.0/24 MONITORING"],
}

# ALLOW matrix as data
ALLOW = {
    "WEB":          {"APP-GW"},
    "APP-GW":       {"APP-CORE"},
    "APP-CORE":     {"WORKER", "DB-OLTP", "DB-ANALYTICS"},
    "WORKER":       {"DB-OLTP"},
    "DB-OLTP":      {"DB-ANALYTICS"},
    "DB-ANALYTICS": set(),
    "MONITORING":   {"WEB","APP-GW","APP-CORE","WORKER","DB-OLTP","DB-ANALYTICS"},
    "MGT":          {"WEB","APP-GW","APP-CORE","WORKER","DB-OLTP","DB-ANALYTICS","MONITORING"},
}
```

---

**End of spec.** This document reflects the live state of `micro-segmentation-lab` GNS3 project as of 2026-05-31. Updates should be made as runtime changes occur (rebuild, re-cable, re-policy).
