# Dataplane — Realistic DCN Simulation

> Phase A: biến 4 Alpine hosts thành 3-tier DCN giả lập với hành vi liên tục
> Mỗi host chạy đúng vai trò của nó — attack xuất phát từ đúng host bị compromise

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

| Attack nguồn | SID | Severity | MITRE | Expected |
|---|---|---|---|---|
| WEB→DB:5432 (WEB compromised) | 9000001 | P1 | T1021 | `dry_run DROP` src=10.1.100.10 dst=10.1.200.10:5432 |
| WEB→MGT:22  (WEB compromised) | 9000004 | P2 | T1078 | `dry_run DROP` src=10.1.100.10 dst=10.2.50.10:22 |
| DB→8.8.8.8:443 (DB compromised) | 9000002 | P1 | T1041 | `dry_run DROP` src=10.1.200.10 dst=8.8.8.8:443 |
| MGT SSH audit → hosts | 9000020 | P4 | T1082 | `filtered` (severity gate) |
| APP→DB query | — | — | — | không fire (legitimate flow) |

---

## Troubleshooting

| Vấn đề | Khắc phục |
|--------|-----------|
| `apk add` network unreachable | `ip route add default via 10.1.x.1` và `echo nameserver 1.1.1.1 > /etc/resolv.conf` |
| `mgt-host.sh` SSH timeout tới WEB/DB | Cần distribute key trước (Bước 2) |
| Suricata không bắt attack | Confirm tc mirror còn active: `tc filter show dev eth1 ingress` trên LEAF |
| Agent không nhận SSE | `curl http://10.10.6.238:8765/stream` từ máy dev — phải có JSON output |
| Attack cron không fire | `cat /etc/crontabs/root` và `service crond status` trên host |
