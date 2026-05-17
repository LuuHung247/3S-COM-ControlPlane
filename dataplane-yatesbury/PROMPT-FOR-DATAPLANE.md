# Prompt cho dataplane agent

Copy đoạn dưới đây forward cho dataplane agent.

---

```
═══════════════════════════════════════════════════════════════
GOAL: Deploy 8 Yatesbury attacker scenarios lên 3 Alpine hosts
      để control plane chạy được eval_yates_*.py suite (NetVigil
      NSDI'24 Table 3 benchmark).
═══════════════════════════════════════════════════════════════

CONTEXT đã sẵn sàng từ control plane:
  ✅ 13 Suricata SIDs Yatesbury (9000040-9000052) đã deploy trên IDS-VM
  ✅ KG threat-patterns.md + sids.md đã có entries tương ứng
  ✅ 8 eval wrappers /home/dis/deploy/zerotrust/experiments/eval_yates_*.py

CẦN dataplane impl (bundle này):
  ❌ 5 attacker scripts trên APP (yates-vscan, synflood, monkey, c2, sqli)
  ❌ 3 attacker scripts trên WEB (synddos, udpddos, distscan)
  ❌ 8 scenario controllers + restore-yates trên MGT

───────────────────────────────────────────────────────────────
BUNDLE LOCATION
───────────────────────────────────────────────────────────────

User đã scp bundle sang Server 2:
  /tmp/dataplane-yatesbury/
  
Files:
  README.md                      → đọc trước
  01-app-host-yates.sh           → paste vào console APP (telnet :5014)
  02-web-host-yates.sh           → paste vào console WEB (telnet :5008)
  03-mgt-host-yates.sh           → paste vào console MGT (telnet :5016)
  04-verify.sh                   → smoke test sau khi deploy
  scenario-map.md                → reference mapping (đọc nếu cần debug)

───────────────────────────────────────────────────────────────
STEP 1 — Deploy 3 install scripts vào 3 Alpine consoles
───────────────────────────────────────────────────────────────

Pattern giống base bootstrap (đã quen):
  - Mở telnet console của host tương ứng
  - Login root (no password)
  - Paste toàn bộ nội dung file `0[1-3]-...sh`
  - Script tự `apk add hping3 nmap ncat`, tạo /usr/local/bin/yates-*.sh,
    add cron entries, rc-service crond restart, verify list

APP console: telnet 112.137.129.232:5014
  → paste content of /tmp/dataplane-yatesbury/01-app-host-yates.sh
  → expect output: "DONE: APP yatesbury attacker scripts installed"
  → expect 5 yates-*.sh files trong /usr/local/bin/

WEB console: telnet 112.137.129.232:5008
  → paste /tmp/dataplane-yatesbury/02-web-host-yates.sh
  → expect 3 yates-*.sh files

MGT console: telnet 112.137.129.232:5016
  → paste /tmp/dataplane-yatesbury/03-mgt-host-yates.sh
  → expect 8 compromise-yates-*.sh + 1 restore-yates.sh trong /root/scenario/

(Có thể dùng /tmp/paste_bootstrap.py base64 helper nếu console paste lag.)

───────────────────────────────────────────────────────────────
STEP 2 — Verify SSH path MGT → APP và MGT → WEB
───────────────────────────────────────────────────────────────

MGT scenario controllers SSH vào APP/WEB để touch flag. Verify:

  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.2.50.10
  # On MGT:
  ssh -o StrictHostKeyChecking=no root@10.2.100.10 'echo OK'
  ssh -o StrictHostKeyChecking=no root@10.1.100.10 'echo OK'

Both phải return "OK". Nếu fail:
  - APP sshd: telnet :5014 → rc-service sshd start
  - WEB sshd: telnet :5008 → rc-service sshd start (đã fix lần trước)
  - SSH key: copy MGT pubkey vào target authorized_keys (existing base bootstrap)

───────────────────────────────────────────────────────────────
STEP 3 — Smoke test 8 scenarios
───────────────────────────────────────────────────────────────

Từ Server 2 (có ssh reach MGT) hoặc copy /tmp/dataplane-yatesbury/04-verify.sh
vào MGT và chạy:

  sh /tmp/dataplane-yatesbury/04-verify.sh

Hoặc test từng scenario riêng:

  sh /tmp/dataplane-yatesbury/04-verify.sh yates-vscan
  sh /tmp/dataplane-yatesbury/04-verify.sh yates-synflood
  ...

Expected PASS criteria (per scenario_map.md):
  vscan    → SID 9000040 fired (within 70s)
  synflood → SID 9000043 fired
  synddos  → SID 9000044 fired ≥2 lần (APP + WEB sources)
  udpddos  → SID 9000045 fired
  distscan → SID 9000041 fired ≥2 lần
  monkey   → SID 9000040 + 9000052 cùng fire
  c2       → SID 9000046 fired (need wait ~310s for threshold)
  sqli     → SID 9000048/9/50 fire (content match)

Verify shortcut:
  curl -s 'http://10.10.6.238:8765/alerts?last=50' | python3 -c "
import sys, json; d=json.load(sys.stdin)
[print(a.get('alert',{}).get('signature_id'), a.get('src_ip')) 
 for a in (d.get('alerts',d) if isinstance(d,dict) else d)]"

───────────────────────────────────────────────────────────────
REPORT FORMAT
───────────────────────────────────────────────────────────────

Cần báo lại 1 trong:

A. "Tất cả 8 scenarios PASS"
   → Control plane chạy eval_yates_*.py × 8 wrappers ngay

B. "Scenario X fire SID Y thay vì Z"
   → Báo SID cụ thể (vd: "monkey fire 9000040 nhưng không có 9000052")
   → Control plane update eval preset mapping

C. "Scenario X không fire alert"
   → Paste output của test:
     sh /usr/local/bin/yates-<X>.sh   (chạy trực tiếp trên host, kiểm /tmp/output)
     tail -20 /var/log/messages | grep yates-<X>   (logger output)
   → Có thể attacker script logic sai, fix script đó

───────────────────────────────────────────────────────────────
ROLLBACK (nếu cần wipe sạch)
───────────────────────────────────────────────────────────────

Trên mỗi Alpine APP + WEB:
  rm -f /usr/local/bin/yates-*.sh
  rm -f /tmp/compromised-yates-*
  sed -i '/yates-/d' /etc/crontabs/root
  rc-service crond restart

Trên MGT:
  rm -f /root/scenario/compromise-yates-*.sh
  rm -f /root/scenario/restore-yates.sh

KHÔNG đụng baseline bootstrap (web-host.sh, app-host.sh, mgt-host.sh giữ nguyên).
```

---

## Sau khi dataplane báo PASS

Control plane (tôi) sẽ:
1. Chạy `python3 experiments/eval_yates_<name>.py` × 8 wrappers (~16 phút total cho 8×120s + cleanup)
2. Báo PASS/FAIL count + decisions per scenario
3. Update docs/EXPERIMENT.md với section Yatesbury benchmark results

## Sau khi dataplane báo có FAIL

Tùy nhóm:
- Threshold quá cao → tăng burst trong attacker script
- SSH timeout → fix sshd trên target host
- SID không match → update KG sids.md threshold hoặc rule rev

Tôi sẽ giúp debug khi có report cụ thể.
