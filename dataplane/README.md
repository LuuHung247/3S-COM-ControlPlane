# Dataplane — Realistic DCN Simulation

> Phase A: biến 4 Alpine hosts thành 3-tier DCN giả lập với hành vi liên tục
> Mỗi host chạy đúng vai trò của nó — attack xuất phát từ đúng host bị compromise
>
> **Update 2026-05-09:** Suricata SID set refactored — bỏ 3 SIDs redundant (9000003/4/5
> ở DENY paths) + thêm 6 SIDs anomaly trên ALLOW paths (9000030-9000035) để chứng minh
> AI agent essentiality. Tổng 11 SIDs. Xem §"SID mapping" và §"Anomaly scenarios" bên dưới.

---

## Repo location vs running hosts (deployment context)

**Repo này nằm ở Server 1 (control plane)** — nơi chạy ONAP + Docker stack.
**Running hosts nằm ở Server 2 (10.10.6.238)** — GNS3 lab + Suricata IDS VM.

Deployment workflow theo từng component:

| Component | Source trong repo | Cách deploy | Tự động? |
|---|---|---|---|
| **Suricata IDS VM** | `ids-vm/` (full bundle) | rsync → SF host → SCP vào VM `192.168.122.205` → `sh redeploy.sh` | ✅ |
| **Secure Framework** | `secure-framework/` | `secure-framework/deploy_gns3vm.sh` (SCP tarball + SSH bash) | ✅ |
| **Alpine hosts (WEB/DB/APP/MGT)** | `dataplane/bootstrap/*.sh` | Manual paste qua telnet console (5008/5011/5014/5016) | ❌ |
| `dataplane/suricata/` | (stale copy) | — | ⚠️ Không deploy — dùng `ids-vm/` thay vì cái này |

→ **Quan trọng:** Khi sửa Suricata rules, edit `ids-vm/rules/zt-lab.rules` (NOT `dataplane/suricata/`).

---

## Mô hình hành vi

```
[Internet]
    │ HTTP
    ▼
┌─────────────────────┐     ┌─────────────────────┐
│  WEB (Alpine-1)     │────▶│  APP (Alpine-3)      │
│  10.1.100.10        │     │  10.2.100.10         │
│  nginx :80          │     │  python :8080        │
│                     │     │  baseline-noise cron │
│  IF compromised:    │     └──────────┬───────────┘
│    WEB→DB:5432      │                │ APP→DB query (ALLOW)
│    WEB→MGT:22       │                ▼
└─────────────────────┘     ┌─────────────────────┐
                            │  DB (Alpine-2)       │
                            │  10.1.200.10         │
                            │  socat :5432 mock    │
                            │                      │
                            │  IF compromised:     │
                            │    DB→8.8.8.8:443    │
                            └─────────────────────┘

┌─────────────────────┐
│  MGT (Alpine-5)     │──SSH audit→ WEB/DB/APP every 2min (SID 9000020)
│  10.2.50.10         │
│  scenario scripts   │──compromise-web.sh / compromise-db.sh
└─────────────────────┘
```

### Hai chế độ mỗi host (WEB và DB):

| Mode | Kích hoạt | Hành vi |
|------|-----------|---------|
| **Normal** | mặc định | chỉ chạy service (nginx / db-mock) |
| **Compromised** | `touch /tmp/compromised` | cron attacker chạy attack traffic mỗi 90s |
| **Restore** | `rm /tmp/compromised` | cron check → exit, attack dừng |

---

## Setup — 4 bước

### Bước 1: Bootstrap 4 hosts (paste vào telnet console)

| Host | Console | Script |
|------|---------|--------|
| Alpine-1 (WEB) | `telnet 112.137.129.232 5008` | `bootstrap/web-host.sh` |
| Alpine-2 (DB)  | `telnet 112.137.129.232 5011` | `bootstrap/db-host.sh` |
| Alpine-3 (APP) | `telnet 112.137.129.232 5014` | `bootstrap/app-host.sh` |
| Alpine-5 (MGT) | `telnet 112.137.129.232 5016` | `bootstrap/mgt-host.sh` |

Mỗi host: đăng nhập `root` (không cần password) → paste toàn bộ nội dung file `.sh`.

### Bước 2: Phân phối SSH key MGT → các tier

`mgt-host.sh` in ra public key sau khi chạy. Copy key đó, paste vào **từng host** còn lại:

```sh
# Trên Alpine-1, 2, 3 (mỗi host console):
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo "ssh-rsa AAAA...key...== root@localhost" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### Bước 3: Verify connectivity từ MGT

```sh
# Trên Alpine-5 (MGT):
sh /root/scenario/status.sh
# phải in "clean" cho cả 3 host
ssh root@10.1.100.10 'curl -s http://localhost/health'     # web-ok
ssh root@10.2.100.10 'curl -s http://localhost:8080/health' # app-ok
ssh root@10.1.200.10 'echo q | nc -w1 localhost 5432'      # PG_OK ...
```

### Bước 4: Xác nhận baseline traffic

APP host tự sinh legitimate traffic mỗi phút. Kiểm tra:
```sh
# Trên Alpine-3 (APP):
tail -f /var/log/noise.log
# → APP→DB: PG_OK row_count=42 ts=...
```

---

## Chạy demo

### Option A — Manual, từng bước

```sh
# Trên MGT (Alpine-5):

# Bước 1: Compromise WEB → WEB bắt đầu lateral sang DB + MGT
sh /root/scenario/compromise-web.sh

# (chờ 60-90s cho cron chạy) rồi xem agent react:
# curl -N http://localhost:8767/stream   (từ máy dev)

# Bước 2: Compromise DB → DB bắt đầu exfil ra internet
sh /root/scenario/compromise-db.sh

# Kiểm tra trạng thái
sh /root/scenario/status.sh

# Restore về sạch
sh /root/scenario/restore-web.sh
sh /root/scenario/restore-db.sh
```

### Option B — Full kill chain tự động

```sh
# Trên MGT (Alpine-5) — copy orchestrator/scenario-full.sh vào /root rồi:
sh /root/scenario-full.sh
```

Sequence: Recon → WEB compromised → wait 100s → DB compromised → wait 100s → restore all.

### Option C — Anomaly scenarios (ALLOW-path abuse, agent essential)

5 scenario controllers mới trên Alpine-5 trigger các SIDs 9000030–9000035. Mỗi scenario
mở 1 attacker mode trên host tương ứng thông qua flag file `/tmp/compromised-*`.

```sh
# Trên MGT (Alpine-5):

sh /root/scenario/compromise-web-burst.sh    # WEB→APP flood (SID 9000030)
sh /root/scenario/compromise-app-burst.sh    # APP→DB rate flood (SID 9000031)
sh /root/scenario/compromise-app-bulk.sh     # bulk SELECT → DB reply >4KB (SID 9000032)
sh /root/scenario/compromise-app-sql.sh      # DROP TABLE / TRUNCATE (SID 9000033)
sh /root/scenario/compromise-app-ssh.sh      # cross-tier SSH probe (SID 9000035)

sh /root/scenario/restore-web-burst.sh       # clear WEB burst flag
sh /root/scenario/restore-app.sh             # clear all APP flags
```

**APP attacker flag-file reference** (created on Alpine-3 by scenario controllers):

| Flag file | Mode | Suricata SID |
|---|---|---|
| `/tmp/compromised-burst` | 100 parallel SYN APP→DB:5432 trong vài giây | 9000031 |
| `/tmp/compromised-bulk`  | 15 lần JOIN query lặp → DB reply >4KB | 9000032 |
| `/tmp/compromised-sql`   | `echo "DROP TABLE users" \| nc DB 5432` + TRUNCATE | 9000033 |
| `/tmp/compromised-ssh`   | `nc 10.1.200.10 22` + `nc 10.1.100.10 22` | 9000035 |

**WEB attacker flag-file reference** (Alpine-1):

| Flag file | Mode | Suricata SID |
|---|---|---|
| `/tmp/compromised`        | legacy lateral WEB→DB + WEB→MGT | 9000001 |
| `/tmp/compromised-burst`  | 250 parallel SYN WEB→APP:8080 | 9000030 |

→ Cron trên các host poll flag files mỗi 30-60s và chạy attack payload tương ứng.

### Theo dõi intelligence-layer

```bash
# Từ máy dev — stream real-time decisions:
curl -N http://localhost:8767/stream

# Hoặc logs:
docker compose logs intelligence-layer -f | grep -E "classified|decision_made|filtered"

# Decisions đã ghi:
curl -s http://localhost:8767/decisions?limit=10 | python3 -m json.tool
```

---

## SID mapping — attack → expected agent outcome

11 SIDs sau refactor 2026-05-09. Đường ALLOW path là **win condition của agent** — LEAF
iptables không drop, chỉ agent có thể detect anomaly.

### Class A — DENY-path violations (LEAF đã drop, agent thêm audit + cross-leaf)
| SID | Trigger | Severity | MITRE | Expected agent action |
|---|---|---|---|---|
| 9000001 | WEB→DB:5432 lateral | P1 | T1021 | DROP src=10.1.100.10 dst=10.1.200.10:5432 |
| 9000002 | DB→external:443 exfil | P1 | T1041 | DROP src=10.1.200.10 dst=any |

### Class B — Recon (context — agent giảm trust score nhưng không enforce)
| SID | Trigger | Severity | Expected |
|---|---|---|---|
| 9000010 | ICMP ping sweep ≥3/10s | P3 | log_only — feeds trust score |
| 9000011 | TCP port scan ≥10/5s | P3 | log_only — feeds trust score |

### Class C — Audit baseline (compliance, không phải incident)
| SID | Trigger | Severity | Expected |
|---|---|---|---|
| 9000020 | MGT zone access (1/min) | P4 | log_only — filtered by severity gate |

### Class D — East-West anomaly trên ALLOW paths (★ agent essential ★)
| SID | Trigger | Severity | MITRE | Expected agent action |
|---|---|---|---|---|
| 9000030 | WEB→APP:8080 burst (>200/min) | P2 | T1499 | DROP src=10.1.100.10 dst=10.2.100.10:8080 |
| 9000031 | APP→DB:5432 burst (>100/min) | P2 | T1041 | DROP src=10.2.100.10 dst=10.1.200.10:5432 |
| 9000032 | DB→APP reply >4KB | P2 | T1567 | DROP src=10.2.100.10 dst=10.1.200.10:5432 |
| 9000033 | DROP TABLE / TRUNCATE | P1 | T1485 | DROP + escalate SOC |
| 9000034 | APP→DB time-window probe | P3 | T1078 | agent eval: log_only in 08-18 UTC, DROP off-hours |
| 9000035 | Cross-tier SSH attempt | P1 | T1021.004 | DROP + flag host suspicious |

→ **Class D là 6 SIDs mới chứng minh AI essential**: LEAF accept (match `zt-*-allow`), agent là layer duy nhất detect behavioral anomaly trong legitimate path.

---

## Deploy Suricata rules to IDS VM

Bundle live ở `/home/dis/deploy/zerotrust/ids-vm/`. Sửa rules file ở repo rồi push qua
hai hop: control plane → GNS3 host (Server 2) → IDS VM `192.168.122.205`.

```bash
# Từ Server 1 (control plane):
rsync -av /home/dis/deploy/zerotrust/ids-vm/ dis@10.10.6.238:/tmp/ids-vm/

# SSH vào Server 2 và push tiếp xuống IDS VM
ssh dis@10.10.6.238 'scp -r /tmp/ids-vm root@192.168.122.205:/root/'

# Chạy redeploy.sh trong IDS VM — install rules + restart suricata + ids-api
ssh dis@10.10.6.238 'ssh root@192.168.122.205 "cd /root/ids-vm && sh redeploy.sh"'
```

**Alternative (paste qua console 5018):** Nếu SSH path không khả dụng, telnet vào IDS VM
console rồi paste nội dung `redeploy.sh` cùng các file `rules/zt-lab.rules` + `suricata-zt.yaml`.

Verify post-deploy:
```bash
curl http://10.10.6.238:8765/health     # status: ok, suricata: true
# Trigger a scenario rồi:
curl "http://10.10.6.238:8765/alerts?last=10" | jq '.[].alert.signature_id'
# Phải thấy SID mới (9000030-9000035) cho scenario tương ứng
```

---

## Troubleshooting

| Vấn đề | Khắc phục |
|--------|-----------|
| `apk add` network unreachable | `ip route add default via 10.1.x.1` và `echo nameserver 1.1.1.1 > /etc/resolv.conf` |
| `mgt-host.sh` SSH timeout tới WEB/DB | Cần distribute key trước (Bước 2) |
| Suricata không bắt attack | Confirm tc mirror còn active: `tc filter show dev eth1 ingress` trên LEAF |
| Agent không nhận SSE | `curl http://10.10.6.238:8765/stream` từ máy dev — phải có JSON output |
| Attack cron không fire | `cat /etc/crontabs/root` và `service crond status` trên host |
