# Yatesbury Benchmark — Dataplane Deploy Bundle

Hand-off bundle để dataplane triển khai 7 attacker scenarios mới (Yatesbury
benchmark per NetVigil NSDI'24 Table 3) lên 3 Alpine hosts.

## Mục đích

Bộ này bổ sung 7 scenarios mới vào lab để chạy eval suite đầy đủ. Hiện tại
control plane (intel-layer) đã sẵn sàng:
- ✅ 13 Suricata SIDs Yatesbury (9000040-9000052) đã deploy trên IDS-VM
- ✅ KG `threat-patterns.md` + `sids.md` đã có 20 patterns + 21 SID entries
- ✅ 8 eval wrapper `.py` files đã tạo trong `experiments/eval_yates_*.py`

Phần còn thiếu (do bundle này): **attacker scripts trên Alpine hosts + scenario
controllers trên MGT**.

## Mapping scenarios → SIDs → eval wrappers

| # | Scenario | Attacker host | SID expected | Eval wrapper |
|---|---|---|---|---|
| 1 | Vertical port scan | APP (10.2.100.10) | 9000040 | `eval_yates_vertical_scan.py` |
| 2 | SYN flood DoS | APP | 9000043 | `eval_yates_syn_flood_dos.py` |
| 3 | SYN flood DDoS | APP + WEB | 9000044 | `eval_yates_syn_flood_ddos.py` |
| 4 | UDP DDoS | APP + WEB | 9000045 | `eval_yates_udp_ddos.py` |
| 5 | Distributed TCP scan | APP + WEB | 9000041 | `eval_yates_distributed_scan.py` |
| 6 | Infection Monkey chain | APP | 9000040 + 9000052 | `eval_yates_infection_monkey.py` |
| 7 | C&C beacon | APP → external | 9000046 | `eval_yates_c2_beacon.py` |

(Scenario `yates-unauth-db` reuses existing `compromise-web.sh` — không cần script mới.)

## Files trong bundle

| File | Purpose | Where to deploy |
|---|---|---|
| `PROMPT-FOR-DATAPLANE.md` | Prompt hoàn chỉnh để user forward cho dataplane agent | (Đọc trước khi triển khai) |
| `01-app-host-yates.sh` | 5 attacker scripts (vscan, synflood, monkey, c2, sqli) + cron entries | Paste vào console APP (telnet :5014) |
| `02-web-host-yates.sh` | 3 attacker scripts (synddos, udpddos, distscan) + cron entries | Paste vào console WEB (telnet :5008) |
| `03-mgt-host-yates.sh` | 8 scenario controllers + restore-yates.sh | Paste vào console MGT (telnet :5016) |
| `04-verify.sh` | Smoke test: trigger từng scenario, check SID fired | Chạy từ Server 1 (cần SSH MGT) |
| `scenario-map.md` | Chi tiết technical mỗi scenario | (Reference doc) |

## Cách triển khai (quick start)

```
# Bước 1: SCP bundle sang dataplane server (Server 2)
scp -r /home/dis/deploy/zerotrust/dataplane-yatesbury dis@10.10.6.238:/tmp/

# Bước 2: Paste content của 3 file `*-host-yates.sh` vào console tương ứng
#   - APP host (Alpine-3): telnet 112.137.129.232:5014 → root → paste 01-app-host-yates.sh
#   - WEB host (Alpine-1): telnet 112.137.129.232:5008 → root → paste 02-web-host-yates.sh
#   - MGT host (Alpine-5): telnet 112.137.129.232:5016 → root → paste 03-mgt-host-yates.sh

# Bước 3: Verify từ MGT (hoặc Server 1 nếu đã setup SSH key)
sh /tmp/dataplane-yatesbury/04-verify.sh

# Bước 4: Báo control plane → tôi sẽ chạy eval wrappers tương ứng
```

## Lưu ý kỹ thuật

- Mỗi attacker script được flag-gated (`[ -f /tmp/compromised-yates-X ] || exit 0`)
  để chỉ fire khi scenario controller set flag, không gây nhiễu baseline traffic.
- Cron tick mỗi 1 phút. Scenario có cron + sleep30 cho 2 lần fire/phút.
- `restore-yates.sh` đóng tất cả scenario bằng cách xoá toàn bộ flag files.
- Cần `apk add` thêm 1 package: `hping3` (cho SYN/UDP flood) và `nmap` (cho scan).
  Install script tự handle.

## Sau khi deploy xong

Báo lại với 1 trong:
- "OK, tất cả 8 scenarios fire SID đúng" → control plane chạy eval batch
- "Scenario X fire SID Y thay vì Z" → tôi update preset mapping
- "Scenario X không fire alert" → debug attacker script logic

## Rollback

Để wipe Yatesbury attacker scripts hoàn toàn:
```sh
# Trên mỗi Alpine host (paste vào console):
rm -f /usr/local/bin/yates-*.sh
rm -f /tmp/compromised-yates-*
sed -i '/yates-/d' /etc/crontabs/root
# Trên MGT:
rm -f /root/scenario/compromise-yates-*.sh /root/scenario/restore-yates.sh
```

Baseline lab vẫn nguyên (web-host.sh, db-host.sh, app-host.sh, mgt-host.sh không bị đụng).
