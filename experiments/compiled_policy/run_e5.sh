#!/usr/bin/env bash
# E5: compiled policy live on the testbed, enforcement on.
#   S1–S5 live controllers × RUNS (real traffic → Suricata → agent → SF → SONiC)
#   S6–S10 injected × REPEATS through common.reliable (rule presence checked on the fabric)
# Enforcement and the compiled flag are ALWAYS restored on exit (dry-run, previous flag).
# Usage: bash compiled_policy/run_e5.sh        RUNS=10 REPEATS=3 by default; SMOKE=1 for one each
set -u
cd "$(dirname "$0")/../.."                       # → zerotrust/
ROOT=$(pwd)                                      # every path below is absolute: finish() runs from any cwd
ENV=$ROOT/intelligence-layer/.env
PYV=/home/dis/deploy/venv/bin/python             # rich + openpyxl for the live harness
PYI=$ROOT/intelligence-layer/.venv/bin/python    # structlog etc. for the injected part
SMOKE=${SMOKE:-0}; RUNS=${RUNS:-10}; REPEATS=${REPEATS:-3}
LIVE=${LIVE:-"s01_web_db_bypass s05_appcore_reverse s07_dboltp_c2 s09_appcore_sql_destructive s10_baseline_mgt_mon_fp"}
export INJECT_ONLY=${INJECT_ONLY:-}              # e.g. "S9:M1-unknown,S9:M2-unknown" (re-runs)
[ "$SMOKE" = 1 ] && { RUNS=1; REPEATS=1; }
TAG=e5_${TAG_PREFIX:-}$([ "$SMOKE" = 1 ] && echo smoke_)$(date -u +%Y%m%d_%H%M)
OUT=$ROOT/experiments/results/$TAG; mkdir -p "$OUT/real_traffic"; ABS_OUT=$OUT
log() { echo "[$(date -u +%T)] $*" | tee -a "$OUT/campaign.log"; }
PREV_FLAG=$(grep -E '^COMPILED_POLICY_ENABLED=' "$ENV" | cut -d= -f2)

set_env() {   # set_env KEY VALUE  (adds the line if absent; never prints the file)
  if grep -qE "^$1=" "$ENV"; then sed -i "s/^$1=.*/$1=$2/" "$ENV"; else echo "$1=$2" >> "$ENV"; fi
}
recreate() {
  (cd "$ROOT" && docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1)
  "$PYI" -c "
import sys; sys.path.insert(0,'$ROOT/experiments')
from common import reliable
print(reliable.preflight(want_compiled=$1, want_dry_run=$2)['health']['dry_run'])" 2>&1 | tail -1
}
clean_rules() { "$PYI" -c "
import sys; sys.path.insert(0,'$ROOT/experiments')
from common import reliable; print(reliable.clean_rules())"; }
finish() {
  log "cleanup: removed $(clean_rules) agent rules"
  set_env AGENT_DRY_RUN true
  if [ -n "$PREV_FLAG" ]; then set_env COMPILED_POLICY_ENABLED "$PREV_FLAG"; else sed -i '/^COMPILED_POLICY_ENABLED=/d' "$ENV"; fi
  log "restored dry-run: $(recreate None True)"
  log "rules left: $(clean_rules) removed on final pass"
  date -u +%FT%TZ > "$OUT/FINISHED"
}
trap finish EXIT

date -u +%FT%TZ > "$OUT/STARTED"
set_env COMPILED_POLICY_ENABLED true
set_env AGENT_DRY_RUN false
[ "${SELFTEST:-0}" = 1 ] && { log "selftest: exiting before any recreate"; cd /tmp; exit 0; }
log "campaign $TAG RUNS=$RUNS REPEATS=$REPEATS image=$(docker inspect intelligence-layer --format '{{.Image}}' | cut -c8-19)"
log "service up (dry_run=$(recreate True False)); compiled: $(curl -s localhost:8767/admin/compiled)"
clean_rules >/dev/null

cd "$ROOT/experiments"
for s in $LIVE; do
  log "▶ live $s × $RUNS"
  IDS_API_URL=http://10.10.6.238:8765 SF_API_URL=http://10.10.6.238:9090 \
  MGT_CONSOLE_HOST=10.10.6.238 MGT_CONSOLE_PORT=5016 \
  EVAL_RESULTS_DIR="$ABS_OUT/real_traffic" EVAL_RUNS="$RUNS" "$PYV" "scenarios/$s.py" 2>&1 \
    | grep -iE "pass rate|Traceback|Error" | tee -a "$ABS_OUT/campaign.log"
  mv results/eval_v2_*.json results/eval_v2_*.xlsx "$ABS_OUT/real_traffic/" 2>/dev/null
  log "  cleaned $(clean_rules) rules"; curl -s -X POST localhost:8767/admin/reset >/dev/null
done
log "▶ injected S6–S10 × $REPEATS"
"$PYI" "$ROOT/experiments/compiled_policy/e5_injected.py" "$ABS_OUT" "$REPEATS" > "$ABS_OUT/injected.log" 2>&1 \
  || log "  injected part exited non-zero (see injected.log)"
tail -12 "$ABS_OUT/injected.log" | tee -a "$ABS_OUT/campaign.log"
log "compiled stats: $(curl -s localhost:8767/admin/compiled)"
log "DONE → $OUT"
cd "$ROOT"
