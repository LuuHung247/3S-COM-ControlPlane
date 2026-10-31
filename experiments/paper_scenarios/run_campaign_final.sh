#!/usr/bin/env bash
# Final BIZM campaign on the upgraded agent + rebuilt testbed (29 custom SIDs, ET Open off).
#   S1–S5  live V2 controllers × RUNS            S6–S10 injected × REPEATS
#   S11    SOC containment scope, HELD-OUT set × REPEATS
#   S13    app-layer prompt injection × REPEATS
#   S12    public-dataset replay: one pass over all sessions, then the alerting sessions
#          (policy_verdict=DENY) repeated until each has S12_RUNS decisions
# Enforcement is switched on for the run and ALWAYS switched back to dry-run on exit.
# Usage:
#   DP_PASS=... bash paper_scenarios/run_campaign_final.sh            # full
#   DP_PASS=... SMOKE=1 bash paper_scenarios/run_campaign_final.sh    # one of each
set -u
cd "$(dirname "$0")/../.."                       # → zerotrust/
ENV=intelligence-layer/.env
PYV=/home/dis/deploy/venv/bin/python   # has rich + openpyxl used by the live harness
SMOKE=${SMOKE:-0}
RUNS=${RUNS:-10}; REPEATS=${REPEATS:-10}; S12_RUNS=${S12_RUNS:-10}
[ "$SMOKE" = 1 ] && { RUNS=1; REPEATS=1; S12_RUNS=1; }
TAG=$([ "$SMOKE" = 1 ] && echo smoke || echo final)_$(date -u +%Y%m%d_%H%M)
OUT=experiments/results/$TAG
mkdir -p "$OUT"/{real_traffic,synthetic,s11_heldout,s13_injection,s12_replay}
ABS_OUT=$(cd "$OUT" && pwd)
log() { echo "[$(date -u +%T)] $*" | tee -a "$OUT/campaign.log"; }

agent_rules() {
  curl -s -m15 localhost:8766/rules | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(sum(1 for l in d['leaves'].values() for n in (l.get('rules') or {}).get('notification',[])
          for u in n.get('update',[]) if u.get('val',{}).get('source')=='agent'))"
}
clean_rules() {
  for r in $(curl -s -m15 localhost:8766/rules | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(' '.join({u['val'].get('rule-id') for l in d['leaves'].values()
     for n in (l.get('rules') or {}).get('notification',[]) for u in n.get('update',[])
     if u.get('val',{}).get('source')=='agent'}))"); do
    curl -s -m15 -X DELETE "localhost:8766/rules/$r" >/dev/null
  done
}
set_dry_run() {
  sed -i "s/^AGENT_DRY_RUN=.*/AGENT_DRY_RUN=$1/" "$ENV"
  docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1
  # Poll until the value the container reports matches what was requested: during a
  # recreate the old container can still answer /health and return the stale value.
  want=$([ "$1" = true ] && echo True || echo False)
  for _ in $(seq 1 40); do
    got=$(curl -s --max-time 3 localhost:8767/health 2>/dev/null \
          | python3 -c 'import sys,json;print(json.load(sys.stdin)["dry_run"])' 2>/dev/null)
    [ "$got" = "$want" ] && break
    sleep 3
  done
  log "AGENT_DRY_RUN=$1 (reported $got)"
}
between() {
  local n; n=$(agent_rules)
  log "after $1: $n agent rules on fabric → cleaning"
  clean_rules
  curl -s -X POST localhost:8767/admin/reset >/dev/null
}
finish() {
  clean_rules
  set_dry_run true
  log "rules left: $(agent_rules)"
  date -u +%FT%TZ > "$OUT/FINISHED"
}
trap finish EXIT

date -u +%FT%TZ > "$OUT/STARTED"
log "campaign $TAG  RUNS=$RUNS REPEATS=$REPEATS S12_RUNS=$S12_RUNS image=$(docker inspect intelligence-layer --format '{{.Image}}' | cut -c8-19)"
clean_rules
set_dry_run false

cd experiments
# ── S1–S5 live ────────────────────────────────────────────────────────────────
for s in s01_web_db_bypass s05_appcore_reverse s07_dboltp_c2 s09_appcore_sql_destructive s10_baseline_mgt_mon_fp; do
  log "▶ live $s × $RUNS"
  IDS_API_URL=http://10.10.6.238:8765 SF_API_URL=http://10.10.6.238:9090 \
  MGT_CONSOLE_HOST=10.10.6.238 MGT_CONSOLE_PORT=5016 \
  EVAL_RESULTS_DIR="$ABS_OUT/real_traffic" EVAL_RUNS="$RUNS" "$PYV" "scenarios/$s.py" 2>&1 \
    | grep -iE "pass rate|Traceback|Error" | tee -a "../$OUT/campaign.log"
  mv results/eval_v2_*.json results/eval_v2_*.xlsx "../$OUT/real_traffic/" 2>/dev/null
  between "$s"
done

# ── S6–S10 injected ───────────────────────────────────────────────────────────
for i in $(seq 1 "$REPEATS"); do
  log "▶ synthetic repeat $i/$REPEATS"
  for s in generalization/s11_killchain_multistage.py safety/s12_privileged_neverblock.py \
           scenarios/s13_matrix_fp.py safety/s14_adversarial_safety.py generalization/s15_reasoning_ablation.py; do
    "$PYV" "$s" >/dev/null 2>&1 || log "  $s err"
    between "$(basename "$s")"
  done
  mv results/s1[1-5]_*.json "../$OUT/synthetic/" 2>/dev/null
done

log "DONE → $OUT"
