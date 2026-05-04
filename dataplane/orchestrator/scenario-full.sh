#!/bin/sh
# Full demo: staged APT-style attack kill chain
# Run this on Alpine-5 (MGT) after all 4 hosts bootstrapped + SSH keys distributed
#
# Kill chain:
#   Phase 1 — Recon:       MGT runs nmap scan from management side
#   Phase 2 — Initial pwn: WEB host compromised → lateral WEB→DB, WEB→MGT
#   Phase 3 — Escalation:  DB host compromised → exfil DB→internet
#   Phase 4 — Observe:     watch intelligence-layer react, then restore
#
# Watch from dev machine:
#   curl -N http://localhost:8767/stream
#   docker compose logs intelligence-layer -f | grep -E "classified|decision_made"

AGENT_URL="http://10.10.6.238:8767"

wait_agent() {
  echo "  ⏳ waiting ${1}s for agent reasoning..."
  sleep "$1"
  echo "  📋 latest decisions:"
  curl -sf "$AGENT_URL/decisions?limit=3" 2>/dev/null \
    | python3 -c "
import json,sys
try:
  ds=json.load(sys.stdin)
  for d in ds:
    print(f'    SID {d[\"alert_sid\"]} → {d[\"outcome\"]}  conf={d[\"safety_checks\"][\"confidence\"][\"score\"]}  latency={d[\"latency_ms\"]:.0f}ms')
except: print('    (no data)')
" 2>/dev/null || echo "    (agent unreachable from here)"
}

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ZERO TRUST DCN — APT Attack Kill Chain Demo            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

# ── Phase 1: Recon ──────────────────────────────────────────────
echo "▶ Phase 1 — Reconnaissance ($(date +%H:%M:%S))"
echo "  MITRE T1018 + T1046: network discovery from MGT perspective"
nmap -sn 10.1.100.0/24 -T3 2>&1 | grep -E "Host is|Nmap scan" | head -5
wait_agent 10

# ── Phase 2: WEB compromised ────────────────────────────────────
echo
echo "▶ Phase 2 — WEB host compromised ($(date +%H:%M:%S))"
echo "  MITRE T1021: attacker on WEB laterals to DB:5432 and MGT:22"
sh /root/scenario/compromise-web.sh
echo "  attack cron now active on WEB (fires every 60-90s)"
wait_agent 100

# ── Phase 3: DB compromised ─────────────────────────────────────
echo
echo "▶ Phase 3 — DB host compromised ($(date +%H:%M:%S))"
echo "  MITRE T1041: attacker on DB exfiltrates to 8.8.8.8:443"
sh /root/scenario/compromise-db.sh
echo "  exfil cron now active on DB"
wait_agent 100

# ── Phase 4: Status + restore ───────────────────────────────────
echo
echo "▶ Phase 4 — Status + restore ($(date +%H:%M:%S))"
sh /root/scenario/status.sh
echo
echo "  Restoring hosts (removing attacker persistence)..."
sh /root/scenario/restore-web.sh
sh /root/scenario/restore-db.sh
echo
sh /root/scenario/status.sh

echo
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   DEMO COMPLETE                                           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "  Decisions log: curl http://localhost:8767/decisions?limit=20"
