#!/usr/bin/env bash
# E7: decision-plane throughput, dry run (no rule reaches the fabric).
#   PHASE=compiled : synthesized program active, offered load RATES for DURATION s each
#   PHASE=runtime  : runtime-only configuration (program disabled), smaller load
# The alert dedup window is shortened and the blast-radius caps raised only so that the
# load measures the decision plane; every changed setting is restored on exit.
set -u
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
ENV=$ROOT/intelligence-layer/.env
PYI=$ROOT/intelligence-layer/.venv/bin/python
PHASE=${PHASE:-compiled}
if [ "$PHASE" = compiled ]; then RATES=${RATES:-"10 50 100 200 500 1000"}; DURATION=${DURATION:-120}
else RATES=${RATES:-"0.5 1 2"}; DURATION=${DURATION:-60}; fi
OUT=$ROOT/experiments/results/e7_$(date -u +%Y%m%d_%H%M)_$PHASE; mkdir -p "$OUT"
log() { echo "[$(date -u +%T)] $*" | tee -a "$OUT/campaign.log"; }
KEYS="COMPILED_POLICY_ENABLED AGENT_DRY_RUN FILTER_DEDUP_WINDOW_SECONDS SAFETY_MAX_RULES_PER_MINUTE SAFETY_MAX_TOTAL_AGENT_RULES SAFETY_MAX_RULES_PER_IP"
declare -A PREV
for k in $KEYS; do PREV[$k]=$(grep -E "^$k=" "$ENV" | cut -d= -f2); done
set_env() { if grep -qE "^$1=" "$ENV"; then sed -i "s/^$1=.*/$1=$2/" "$ENV"; else echo "$1=$2" >> "$ENV"; fi; }
unset_env() { sed -i "/^$1=/d" "$ENV"; }
recreate() {
  (cd "$ROOT" && docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1)
  "$PYI" -c "
import sys; sys.path.insert(0,'$ROOT/experiments')
from common import reliable
print(reliable.preflight(want_compiled=$1, want_dry_run=True)['health']['dry_run'])" 2>&1 | tail -1
}
finish() {
  for k in $KEYS; do if [ -n "${PREV[$k]}" ]; then set_env "$k" "${PREV[$k]}"; else unset_env "$k"; fi; done
  set_env AGENT_DRY_RUN true
  log "restored settings: dry_run=$(recreate None)"
  date -u +%FT%TZ > "$OUT/FINISHED"
}
trap finish EXIT

set_env AGENT_DRY_RUN true
set_env FILTER_DEDUP_WINDOW_SECONDS 1
set_env SAFETY_MAX_RULES_PER_MINUTE 100000000
set_env SAFETY_MAX_TOTAL_AGENT_RULES 100000000
set_env SAFETY_MAX_RULES_PER_IP 100000000
if [ "$PHASE" = compiled ]; then set_env COMPILED_POLICY_ENABLED true; WANT=True; FLAG=""
else set_env COMPILED_POLICY_ENABLED false; WANT=False; FLAG="--runtime"; fi
log "phase $PHASE: service up (dry_run=$(recreate $WANT))"
"$PYI" "$ROOT/experiments/compiled_policy/e7_load.py" "$OUT/e7.jsonl" --rates $RATES --duration "$DURATION" $FLAG \
  2>&1 | tee -a "$OUT/campaign.log"
log "DONE -> $OUT"
