# Demo — Single Scenario "Agent Works"

> **Mục đích:** Chứng minh Intelligence Layer (LLM Agent) hoạt động end-to-end trên 1 attack scenario có sẵn. Không phải full evaluation, không phải 3 configs. **Chỉ cần demo Agent decides + enforces correctly.**
> **Phạm vi:** 1 scenario × 1 config (Config C — Full proposed). Build minimal scripts để run demo + reset + verify.
> **Sau khi demo này pass:** mới scale lên full evaluation (3 configs × N scenarios × 8 metrics).

---

## 1. Mục tiêu cụ thể

Demo flow:

```
[Reset state]
   ↓
[Run baseline 30s — confirm no false positives]
   ↓
[Trigger compromise-web]
   ↓
[Suricata fires SID 9000001 P1 within 30s]
   ↓
[Agent receives alert via SSE → reasons → produces decision]
   ↓
[Agent enforces DROP rule on LEAF-1 via ids-agent → SF → iptables]
   ↓
[Verify: rule exists on LEAF-1, decision logged in Postgres]
   ↓
[Restore + reset]
```

**Acceptance:** Demo này thành công khi:
- Agent produces ≥ 1 decision với `outcome=enforced` (not `dry_run`, not `filtered`)
- iptables FORWARD trên LEAF-1 có rule mới với src=10.1.100.10
- `GET /decisions` của Agent trả về decision với full reasoning trace
- Sau reset, state về clean (no agent rules, no attacker cron armed)

---

## 2. Prerequisites

### 2.1. Infra phải sẵn sàng

- [ ] GNS3 testbed running (Spine + 2 LEAFs + 4 Alpines)
- [ ] Static policy applied (12-flow iptables rules trên cả 2 LEAF)
  - Verify: `python3 /3s-com/zma/dc-fabric-setup/08-verify-policy.py` → 12/12 PASS
- [ ] Suricata running, 8 rules loaded
  - Verify: `curl http://10.10.6.238:8765/health` → status ok
- [ ] ids-agent running
  - Verify: `curl http://10.10.6.238:8766/health` → status ok
- [ ] Intelligence Layer container running
  - Verify: `curl http://localhost:8767/health` → status ok, ids_agent connected

### 2.2. Config phải đúng

**Intelligence Layer `.env`:**
```
AGENT_DRY_RUN=false   # ← REAL enforcement, not dry_run
LLM_PROVIDER=openai_compat
LLM_PRIMARY_BASE_URL=https://api.cerebras.ai/v1
LLM_PRIMARY_MODEL=zai-glm-4.7
... (các env khác giữ nguyên)
```

**Apply env change:**
```sh
cd /home/dis/deploy/zerotrust
sed -i 's/^AGENT_DRY_RUN=.*/AGENT_DRY_RUN=false/' intelligence-layer/.env
docker compose up -d --force-recreate intelligence-layer
```

⚠️ **Lưu ý:** Khi flip `AGENT_DRY_RUN=false`, Agent sẽ enforce thật. Đảm bảo NEVER_BLOCK whitelist hardcoded đã chứa management plane (10.10.6.0/24, 192.168.122.0/24) để tránh tự khóa control plane.

---

## 3. Scripts cần build

Chỉ 3 scripts — đặt trong `scripts/demo/`:

```
scripts/demo/
├── reset.sh        # Đưa dataplane về clean state
├── run.sh          # Run scenario + observe
└── verify.sh       # Verify Agent đã enforce thành công
```

### 3.1. `scripts/demo/reset.sh`

**Mục đích:** Đưa dataplane về clean state để demo tiếp theo không bị nhiễu.

**Quan trọng — KHÔNG reset:**
- Static iptables policy (12 rules baseline) — phải GIỮ
- Postgres `decisions` table — giữ để cross-run analysis
- ChromaDB MITRE KB — giữ
- Cron baseline traffic — giữ chạy continuous
- Services trên Alpine hosts — giữ

**Cần reset:**
- Attacker crons trên Alpine-1 và Alpine-2 → disarm
- Agent-pushed iptables rules → DELETE qua ids-agent
- Redis cache → FLUSHDB (alert history, dedup, rate counters)
- Suricata alert anchor → đánh dấu mốc time mới

```sh
#!/bin/sh
# scripts/demo/reset.sh
# Reset dataplane to clean state between demo runs.
# Preserves: static policy, services, baseline cron, KB.
# Clears: attacker crons, agent rules, Redis cache, alert anchor.

set -e

echo "[reset] Starting at $(date -u)"

# 1. Disarm attacker scenarios via MGT controllers
echo "[reset] Disarming attack scenarios..."
ssh root@10.2.50.10 "/root/scenario/restore-web.sh" 2>/dev/null || echo "  (compromise-web already restored or unreachable)"
ssh root@10.2.50.10 "/root/scenario/restore-db.sh" 2>/dev/null || echo "  (compromise-db already restored or unreachable)"

# 2. Verify attacker crons disarmed
WEB_STATE=$(ssh root@10.2.50.10 "/root/scenario/status-web.sh" 2>/dev/null || echo "unknown")
DB_STATE=$(ssh root@10.2.50.10 "/root/scenario/status-db.sh" 2>/dev/null || echo "unknown")
echo "[reset] Attacker state: web=${WEB_STATE} db=${DB_STATE}"

# 3. Delete all agent-pushed iptables rules via ids-agent
echo "[reset] Clearing agent-pushed rules..."
RULES_JSON=$(curl -s "http://10.10.6.238:8766/rules?source=agent" || echo "[]")
RULE_IDS=$(echo "$RULES_JSON" | python3 -c "
import json, sys
try:
    rules = json.load(sys.stdin)
    if isinstance(rules, dict):
        rules = rules.get('rules', [])
    for r in rules:
        rid = r.get('rule-id') or r.get('rule_id') or r.get('id')
        if rid: print(rid)
except Exception as e:
    pass
" 2>/dev/null || echo "")

if [ -n "$RULE_IDS" ]; then
    for rid in $RULE_IDS; do
        curl -sf -X DELETE "http://10.10.6.238:8766/rules/${rid}" >/dev/null 2>&1 \
            && echo "  ✓ Deleted rule $rid" \
            || echo "  ✗ Failed to delete $rid"
    done
else
    echo "  (no agent rules to clear)"
fi

# 4. Flush Redis (Agent's warm cache: alert history, dedup, rate counter)
echo "[reset] Flushing Redis cache..."
docker compose -f /home/dis/deploy/zerotrust/docker-compose.yml exec -T redis redis-cli FLUSHDB >/dev/null
echo "  ✓ Redis flushed"

# 5. Anchor Suricata alert stream — alerts before this point will be filtered out
echo "[reset] Anchoring Suricata alert stream..."
curl -sf "http://10.10.6.238:8765/alerts/clear" >/dev/null
echo "  ✓ Alert anchor set"

# 6. Verify static policy still intact (12-flow check)
echo "[reset] Verifying static policy still active..."
cd /3s-com/zma/dc-fabric-setup
RESULT=$(python3 08-verify-policy.py 2>&1 | tail -3)
echo "$RESULT" | sed 's/^/  /'

# 7. Wait for baseline traffic to settle (let cron-driven flows establish)
echo "[reset] Waiting 15s for baseline traffic to stabilize..."
sleep 15

# 8. Final health check
INTEL_HEALTH=$(curl -s http://localhost:8767/health | python3 -c "
import json, sys
try:
    h = json.load(sys.stdin)
    print(f\"status={h.get('status')} dry_run={h.get('dry_run')} cb_open={h.get('circuit_breaker',{}).get('is_open')}\")
except: print('unreachable')
")
echo "[reset] Intelligence Layer: $INTEL_HEALTH"

echo "[reset] ✓ Done at $(date -u)"
```

### 3.2. `scripts/demo/run.sh`

**Mục đích:** Trigger scenario, capture data trong lúc Agent xử lý.

```sh
#!/bin/sh
# scripts/demo/run.sh
# Run single demo scenario: compromise-web for 90s, capture all data.

set -e

DURATION=${1:-90}
RUN_DIR="results/demo-$(date -u +%Y%m%d-%H%M%SZ)"
mkdir -p "$RUN_DIR"

echo "[run] Demo scenario: compromise-web (duration=${DURATION}s)"
echo "[run] Output dir: $RUN_DIR"

# === Pre-flight ===
echo "[run] Pre-flight checks..."
curl -sf http://localhost:8767/health >/dev/null || { echo "ERROR: Intelligence Layer down"; exit 1; }
curl -sf http://10.10.6.238:8766/health >/dev/null || { echo "ERROR: ids-agent down"; exit 1; }

# Confirm AGENT_DRY_RUN=false
DRY_RUN=$(curl -s http://localhost:8767/health | python3 -c "import json,sys; print(json.load(sys.stdin).get('dry_run'))")
if [ "$DRY_RUN" = "True" ] || [ "$DRY_RUN" = "true" ]; then
    echo "WARNING: AGENT_DRY_RUN=true — Agent sẽ KHÔNG enforce thật"
    echo "Continue anyway? (y/N)"
    read confirm
    [ "$confirm" != "y" ] && exit 1
fi

# === T+0: Snapshot pre-attack iptables state ===
echo "[run] T+0: Capturing pre-attack iptables snapshot..."
ssh leaf1 "iptables -L FORWARD -n -v --line-numbers" > "$RUN_DIR/iptables-leaf1-pre.txt"
ssh leaf2 "iptables -L FORWARD -n -v --line-numbers" > "$RUN_DIR/iptables-leaf2-pre.txt"

# === T+0: Start background pollers ===
echo "[run] T+0: Starting collectors..."
START_TS=$(date -u +%s)
echo "$START_TS" > "$RUN_DIR/start.ts"

# Poller 1: Suricata alerts every 5s
(while true; do
    curl -s "http://10.10.6.238:8765/alerts?last=50" >> "$RUN_DIR/alerts.jsonl"
    echo "" >> "$RUN_DIR/alerts.jsonl"
    sleep 5
done) &
ALERTS_PID=$!

# Poller 2: Agent decisions every 5s
(while true; do
    curl -s "http://localhost:8767/decisions?limit=20" >> "$RUN_DIR/decisions.jsonl"
    echo "" >> "$RUN_DIR/decisions.jsonl"
    sleep 5
done) &
DECISIONS_PID=$!

# Poller 3: Active rules every 15s
(while true; do
    TS=$(date -u +%s)
    curl -s "http://10.10.6.238:8766/rules" > "$RUN_DIR/rules-${TS}.json"
    sleep 15
done) &
RULES_PID=$!

# Cleanup pollers on exit
trap "kill $ALERTS_PID $DECISIONS_PID $RULES_PID 2>/dev/null" EXIT

# === T+5: Trigger attack ===
echo "[run] T+5: Triggering compromise-web..."
sleep 5
ssh root@10.2.50.10 "/root/scenario/compromise-web.sh"
echo "[run] Attacker cron armed: WEB→DB:5432 every 15s"

# === Wait for attack window ===
echo "[run] Running attack for ${DURATION}s..."
sleep $DURATION

# === Restore + post-attack snapshot ===
echo "[run] Disarming attacker..."
ssh root@10.2.50.10 "/root/scenario/restore-web.sh"

echo "[run] Capturing post-attack iptables snapshot..."
ssh leaf1 "iptables -L FORWARD -n -v --line-numbers" > "$RUN_DIR/iptables-leaf1-post.txt"
ssh leaf2 "iptables -L FORWARD -n -v --line-numbers" > "$RUN_DIR/iptables-leaf2-post.txt"

# === Stop collectors ===
sleep 5  # let last poll cycle complete
kill $ALERTS_PID $DECISIONS_PID $RULES_PID 2>/dev/null
wait 2>/dev/null

END_TS=$(date -u +%s)
echo "$END_TS" > "$RUN_DIR/end.ts"

echo "[run] ✓ Demo complete at $(date -u)"
echo "[run] Data captured in: $RUN_DIR"
echo "[run] Run verify.sh next: ./scripts/demo/verify.sh $RUN_DIR"
```

### 3.3. `scripts/demo/verify.sh`

**Mục đích:** Kiểm tra Agent đã work — output PASS/FAIL với chi tiết.

```sh
#!/bin/sh
# scripts/demo/verify.sh
# Verify demo run: did Agent detect, decide, and enforce correctly?

set -e

RUN_DIR=${1:?"Usage: verify.sh <run-dir>"}

echo "[verify] Analyzing run: $RUN_DIR"
echo ""

PASS=0
FAIL=0

check_pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

# === Check 1: Suricata fired P1 alerts ===
echo "[Check 1] Suricata fired P1 alerts (SID 9000001)?"
P1_COUNT=$(grep -o '"signature_id":9000001' "$RUN_DIR/alerts.jsonl" 2>/dev/null | wc -l)
if [ "$P1_COUNT" -ge 3 ]; then
    check_pass "P1 alerts fired: $P1_COUNT (expected ≥ 3)"
else
    check_fail "P1 alerts insufficient: $P1_COUNT (expected ≥ 3)"
fi

# === Check 2: Agent received alerts ===
echo ""
echo "[Check 2] Agent processed alerts?"
DECISIONS_TOTAL=$(python3 -c "
import json
seen = set()
with open('$RUN_DIR/decisions.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            items = data if isinstance(data, list) else data.get('decisions', [])
            for d in items:
                key = d.get('id') or (d.get('alert_sid'), d.get('created_at'))
                seen.add(str(key))
        except: pass
print(len(seen))
" 2>/dev/null || echo 0)

if [ "$DECISIONS_TOTAL" -ge 1 ]; then
    check_pass "Agent decisions logged: $DECISIONS_TOTAL"
else
    check_fail "No decisions found in Agent log"
fi

# === Check 3: At least 1 decision with outcome=enforced ===
echo ""
echo "[Check 3] Agent enforced (not dry_run/filtered)?"
ENFORCED_COUNT=$(python3 -c "
import json
seen = set()
enforced = []
with open('$RUN_DIR/decisions.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            items = data if isinstance(data, list) else data.get('decisions', [])
            for d in items:
                key = d.get('id') or (d.get('alert_sid'), d.get('created_at'))
                if key in seen: continue
                seen.add(key)
                outcome = d.get('outcome', '')
                if outcome in ('enforced', 'real'):
                    enforced.append(d)
        except: pass
print(len(enforced))
" 2>/dev/null || echo 0)

if [ "$ENFORCED_COUNT" -ge 1 ]; then
    check_pass "Enforced decisions: $ENFORCED_COUNT"
else
    check_fail "No enforced decisions (Agent did not block source)"
fi

# === Check 4: New iptables rule on LEAF-1 ===
echo ""
echo "[Check 4] New iptables rule on LEAF-1?"
RULES_PRE=$(grep -c '^' "$RUN_DIR/iptables-leaf1-pre.txt" 2>/dev/null || echo 0)
RULES_POST=$(grep -c '^' "$RUN_DIR/iptables-leaf1-post.txt" 2>/dev/null || echo 0)
RULES_DIFF=$((RULES_POST - RULES_PRE))

if [ "$RULES_DIFF" -ge 1 ]; then
    check_pass "New rules added on LEAF-1: $RULES_DIFF"
    echo "    New rules:"
    diff "$RUN_DIR/iptables-leaf1-pre.txt" "$RUN_DIR/iptables-leaf1-post.txt" | grep '^> ' | head -3 | sed 's/^/    /'
else
    check_fail "No new rules on LEAF-1 (pre=$RULES_PRE post=$RULES_POST)"
fi

# === Check 5: Rule mentions attacker IP ===
echo ""
echo "[Check 5] Rule blocks attacker source IP (10.1.100.10)?"
if grep -q "10.1.100.10" "$RUN_DIR/iptables-leaf1-post.txt" 2>/dev/null; then
    POST_MATCH=$(grep "10.1.100.10" "$RUN_DIR/iptables-leaf1-post.txt" | wc -l)
    PRE_MATCH=$(grep -c "10.1.100.10" "$RUN_DIR/iptables-leaf1-pre.txt" 2>/dev/null || echo 0)
    NEW_BLOCKS=$((POST_MATCH - PRE_MATCH))
    if [ "$NEW_BLOCKS" -ge 1 ]; then
        check_pass "Attacker IP blocked by $NEW_BLOCKS new rule(s)"
    else
        check_fail "Attacker IP appears in iptables but not in new rules"
    fi
else
    check_fail "Attacker IP 10.1.100.10 not found in post-attack iptables"
fi

# === Sample decision detail ===
echo ""
echo "[Sample] First enforced decision detail:"
python3 -c "
import json
with open('$RUN_DIR/decisions.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            data = json.loads(line)
            items = data if isinstance(data, list) else data.get('decisions', [])
            for d in items:
                if d.get('outcome') in ('enforced', 'real'):
                    print(f\"  Alert SID:    {d.get('alert_sid')}\")
                    print(f\"  Outcome:      {d.get('outcome')}\")
                    print(f\"  Latency:      {d.get('latency_ms')}ms\")
                    intent = d.get('intent', {})
                    print(f\"  Action:       {intent.get('action')}\")
                    print(f\"  Target IP:    {intent.get('src_ip')}\")
                    print(f\"  TTL:          {intent.get('ttl_seconds')}s\")
                    safety = d.get('safety_checks', {}).get('confidence', {})
                    print(f\"  Confidence:   {safety.get('score')}\")
                    sys_exit = True; raise SystemExit
        except SystemExit: raise
        except: pass
" 2>/dev/null || echo "  (no enforced decision found)"

# === Summary ===
echo ""
echo "═══════════════════════════════════════"
echo "RESULT: $PASS PASS / $FAIL FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "✓ DEMO PASSED — Agent works end-to-end"
    exit 0
else
    echo "✗ DEMO FAILED — see details above"
    exit 1
fi
```

---

## 4. Expected Demo Run

### 4.1. Trình tự thực hiện

```sh
# Step 1: Setup (one-time)
cd /home/dis/deploy/zerotrust
sed -i 's/^AGENT_DRY_RUN=.*/AGENT_DRY_RUN=false/' intelligence-layer/.env
docker compose up -d --force-recreate intelligence-layer

# Step 2: Reset state
./scripts/demo/reset.sh

# Step 3: Run demo
./scripts/demo/run.sh 90

# Step 4: Verify
./scripts/demo/verify.sh results/demo-<timestamp>

# Step 5: Reset for next run (or keep state for analysis)
./scripts/demo/reset.sh
```

### 4.2. Expected output (success case)

```
[reset] Starting at 2026-05-04T...
[reset] Disarming attack scenarios...
[reset] Attacker state: web=disarmed db=disarmed
[reset] Clearing agent-pushed rules...
  (no agent rules to clear)
[reset] Flushing Redis cache...
  ✓ Redis flushed
[reset] Anchoring Suricata alert stream...
  ✓ Alert anchor set
[reset] Verifying static policy still active...
  Total: 12/12 PASS
[reset] Waiting 15s for baseline traffic to stabilize...
[reset] Intelligence Layer: status=ok dry_run=False cb_open=False
[reset] ✓ Done

[run] Demo scenario: compromise-web (duration=90s)
[run] Pre-flight checks...
[run] T+0: Capturing pre-attack iptables snapshot...
[run] T+0: Starting collectors...
[run] T+5: Triggering compromise-web...
[run] Attacker cron armed: WEB→DB:5432 every 15s
[run] Running attack for 90s...
[run] Disarming attacker...
[run] Capturing post-attack iptables snapshot...
[run] ✓ Demo complete

[verify] Analyzing run: results/demo-...
[Check 1] Suricata fired P1 alerts (SID 9000001)?
  ✓ P1 alerts fired: 5 (expected ≥ 3)

[Check 2] Agent processed alerts?
  ✓ Agent decisions logged: 1

[Check 3] Agent enforced (not dry_run/filtered)?
  ✓ Enforced decisions: 1

[Check 4] New iptables rule on LEAF-1?
  ✓ New rules added on LEAF-1: 1

[Check 5] Rule blocks attacker source IP (10.1.100.10)?
  ✓ Attacker IP blocked by 1 new rule(s)

[Sample] First enforced decision detail:
  Alert SID:    9000001
  Outcome:      enforced
  Latency:      8421ms
  Action:       DROP
  Target IP:    10.1.100.10
  TTL:          3600s
  Confidence:   0.92

═══════════════════════════════════════
RESULT: 5 PASS / 0 FAIL
✓ DEMO PASSED — Agent works end-to-end
```

---

## 5. Troubleshooting

| Triệu chứng | Nguyên nhân | Fix |
|------|------------|-----|
| Check 1 FAIL — no P1 alerts | Suricata không catch traffic | Check tc mirred trên LEAF-1: `tc qdisc show dev Vlan100 ingress`. Restart Suricata: `kill -USR2 $(cat /var/run/suricata.pid)` |
| Check 2 FAIL — no decisions | Agent không nhận alert | Check ids-agent SSE: `curl -N http://10.10.6.238:8766/events`. Check intelligence-layer logs: `docker logs intelligence-layer -f` |
| Check 3 FAIL — all dry_run | `AGENT_DRY_RUN=true` chưa flip | `sed -i 's/AGENT_DRY_RUN=true/AGENT_DRY_RUN=false/' .env && docker compose up -d --force-recreate intelligence-layer` |
| Check 3 FAIL — outcome=hold | Confidence < 0.85 (L7 layer) | Bình thường nếu LLM không confident. Check `safety_checks.confidence.score` trong decisions.jsonl. Có thể giảm threshold tạm thời để test |
| Check 4 FAIL — no new rules | Enforce path bị broken | Check ids-agent → SF: `curl http://10.10.6.238:9090/api/rules`. Check SF logs: `docker logs nos-sf` |
| Check 5 FAIL — wrong IP blocked | Agent reasoning sai hoặc topology sai | Check decision.intent.src_ip trong decisions.jsonl. Check KG snapshot trong system prompt |
| Latency > 30s | LLM provider chậm/timeout | Check Cerebras API status. Tạm reduce `AGENT_SELF_CONSISTENCY_RUNS=1` để test |
| Reset không xóa được rules | DELETE endpoint fail | Manual: `curl -X DELETE http://10.10.6.238:9090/api/rules` (qua SF trực tiếp) |

---

## 6. Acceptance Criteria

Demo task này **complete** khi:

- [ ] 3 scripts (`reset.sh`, `run.sh`, `verify.sh`) được implement đúng spec
- [ ] Chạy `./scripts/demo/reset.sh && ./scripts/demo/run.sh 90 && ./scripts/demo/verify.sh <run-dir>` end-to-end **không cần intervention manual**
- [ ] verify.sh return exit 0 (5 PASS / 0 FAIL) với expected output như section 4.2
- [ ] `reset.sh` chạy được nhiều lần liên tiếp, mỗi lần đưa về clean state đúng (verify static policy vẫn 12/12 PASS, no agent rules, Redis empty)
- [ ] Run lần thứ 2 ngay sau lần thứ 1 (có reset giữa) cho kết quả tương tự — chứng minh reproducible

---

## 7. Notes for Coding Agent

1. **DON'T over-engineer.** File này scope nhỏ — chỉ 3 scripts. Không cần config switching, không cần 8 metrics, không cần multi-scenario.

2. **DON'T modify static policy.** Reset script PHẢI giữ nguyên 12 iptables rules baseline. Nếu accident `iptables -F` thì cần re-apply qua `07-apply-policy.py apply`.

3. **NEVER_BLOCK whitelist quan trọng.** Khi flip `AGENT_DRY_RUN=false`, đảm bảo `src/agent/safety/guardrails.py` đã có whitelist `10.10.6.0/24` (mgmt) + `192.168.122.0/24` (LEAF NETCONF) + LEAF SVI gateways. Nếu Agent block nhầm các IP này → khóa control plane → phải console vào LEAF để fix.

4. **Reset script idempotent.** Chạy nhiều lần safe. Use `|| true` cho commands có thể fail (e.g., delete rule không tồn tại).

5. **Time sync.** Tất cả hosts (LEAF-1, LEAF-2, GNS3VM, intelligence-layer container) phải sync NTP. Nếu lệch giờ, MTTR/MTTD khó interpret.

6. **Verify script exit code:** Phải return 0 nếu pass, non-zero nếu fail. Để dùng được trong CI/automation sau này.

7. **Logging structured:** Use prefix `[reset]`, `[run]`, `[verify]` để dễ grep.

8. **Save run data trong `results/demo-<timestamp>/`.** Không xóa sau verify — giữ để debug khi fail.

9. **Nếu Check 2 (no decisions) fail nhưng Check 1 (alerts fired) pass:** vấn đề nằm ở SSE consumer hoặc trigger gate filter. Check `intelligence-layer` logs có `alert_received` event không. Nếu không có → ids-agent không forward được. Nếu có nhưng filter reject → check severity (P1=1 phải pass).

10. **Khi nào move sang full evaluation?** Sau khi demo này pass **3 lần liên tiếp** không lỗi. Lúc đó mới scale lên 3 configs × multiple scenarios.

---

**End of Demo Specification.**