#!/bin/sh
# Yatesbury smoke test — trigger từng scenario, đếm SID fire trong IDS API
# Chạy từ Server 1 (cần curl reach 10.10.6.238:8765 + MGT console reach)
#
# Usage:
#   sh 04-verify.sh                      # test all 8 scenarios
#   sh 04-verify.sh yates-vscan          # test 1 scenario
#
# Note: requires script to be able to ssh-from-MGT (so paste vào console
# Alpine-5 và run từ đó; hoặc cài SSH key MGT→ trên Server 1).

IDS_API="${IDS_API:-http://10.10.6.238:8765}"
MGT_HOST="${MGT_HOST:-10.2.50.10}"   # set to "console" if running via telnet paste

SCENARIOS="vscan synflood synddos udpddos distscan monkey c2 sqli"
[ -n "$1" ] && SCENARIOS="$1"

# Expected SID per scenario (regex pattern for grep -E)
sid_for() {
  case "$1" in
    vscan)    echo "9000040" ;;
    synflood) echo "9000043" ;;
    synddos)  echo "9000044" ;;
    udpddos)  echo "9000045" ;;
    distscan) echo "9000041" ;;
    monkey)   echo "9000040|9000052" ;;
    c2)       echo "9000046" ;;
    sqli)     echo "9000048|9000049|9000050" ;;
  esac
}

WAIT_SECONDS=70   # most scenarios fire within 60s (cron tick + threshold)
[ "$1" = "c2" ] && WAIT_SECONDS=310  # C2 beacon needs 300s threshold

echo "===== Yatesbury smoke test ====="
echo "IDS_API=$IDS_API  MGT_HOST=$MGT_HOST"
echo

PASS=0
FAIL=0
for s in $SCENARIOS; do
  expected=$(sid_for "$s")
  echo "─────────────────────────────────────────────────────"
  echo "[$s] trigger compromise-yates-$s.sh — expect SID $expected"

  # Snapshot alert count before
  before=$(curl -s "$IDS_API/alerts?last=200" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
alerts = d.get('alerts', d) if isinstance(d, dict) else d
pat = re.compile(r'^($expected)\$')
cnt = sum(1 for a in alerts if pat.match(str(a.get('alert',{}).get('signature_id',''))))
print(cnt)" 2>/dev/null || echo 0)

  # Trigger via MGT (use SSH or assume already on MGT)
  if [ "$MGT_HOST" = "console" ]; then
    echo "  [INFO] Running via console — manually paste:"
    echo "         sh /root/scenario/compromise-yates-$s.sh"
    echo "  [INFO] Press ENTER when triggered..."
    read _dummy
  else
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$MGT_HOST \
      "sh /root/scenario/compromise-yates-$s.sh" 2>&1 | tail -3
  fi

  # Wait for SID to fire
  echo "  [wait] up to ${WAIT_SECONDS}s for SID $expected..."
  end=$(($(date +%s) + $WAIT_SECONDS))
  found=0
  while [ $(date +%s) -lt $end ]; do
    after=$(curl -s "$IDS_API/alerts?last=200" | python3 -c "
import sys, json, re
d = json.load(sys.stdin)
alerts = d.get('alerts', d) if isinstance(d, dict) else d
pat = re.compile(r'^($expected)\$')
cnt = sum(1 for a in alerts if pat.match(str(a.get('alert',{}).get('signature_id',''))))
print(cnt)" 2>/dev/null || echo 0)
    if [ "$after" -gt "$before" ]; then
      delta=$((after - before))
      echo "  [PASS] SID $expected fired $delta time(s) — scenario OK"
      PASS=$((PASS + 1))
      found=1
      break
    fi
    sleep 5
  done
  if [ $found -eq 0 ]; then
    echo "  [FAIL] SID $expected did NOT fire within ${WAIT_SECONDS}s"
    FAIL=$((FAIL + 1))
  fi

  # Restore
  if [ "$MGT_HOST" = "console" ]; then
    echo "  [INFO] Paste: sh /root/scenario/restore-yates.sh"
    read _dummy
  else
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$MGT_HOST \
      'sh /root/scenario/restore-yates.sh' 2>&1 | tail -1
  fi
  sleep 5
done

echo
echo "===== SUMMARY ====="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "TOTAL: $((PASS + FAIL))"
[ $FAIL -eq 0 ] && exit 0 || exit 1
