#!/usr/bin/env bash
# S11: multi-source campaign, compiled policy live, enforcement on.
#   default limits: n_s in {3,5,8,12} x RUNS direct, decoy 12 x RUNS
#   raised limit L' (rules per minute): n_s = 12 x RUNS direct
# Dry-run, the compiled flag and the per-minute limit are ALWAYS restored on exit, and
# every agent rule is removed.
set -u
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
ENV=$ROOT/intelligence-layer/.env
PYI=$ROOT/intelligence-layer/.venv/bin/python
RUNS=${RUNS:-5}; LPRIME=${LPRIME:-12}; SMOKE=${SMOKE:-0}
OUT=$ROOT/experiments/results/s11_$(date -u +%Y%m%d_%H%M); mkdir -p "$OUT"
log() { echo "[$(date -u +%T)] $*" | tee -a "$OUT/campaign.log"; }
PREV_FLAG=$(grep -E '^COMPILED_POLICY_ENABLED=' "$ENV" | cut -d= -f2)
PREV_RPM=$(grep -E '^SAFETY_MAX_RULES_PER_MINUTE=' "$ENV" | cut -d= -f2)

set_env() { if grep -qE "^$1=" "$ENV"; then sed -i "s/^$1=.*/$1=$2/" "$ENV"; else echo "$1=$2" >> "$ENV"; fi; }
unset_env() { sed -i "/^$1=/d" "$ENV"; }
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
  if [ -n "$PREV_FLAG" ]; then set_env COMPILED_POLICY_ENABLED "$PREV_FLAG"; else unset_env COMPILED_POLICY_ENABLED; fi
  if [ -n "$PREV_RPM" ]; then set_env SAFETY_MAX_RULES_PER_MINUTE "$PREV_RPM"; else unset_env SAFETY_MAX_RULES_PER_MINUTE; fi
  log "restored dry-run: $(recreate None True)"
  log "rules left: $(clean_rules) removed on final pass"
  date -u +%FT%TZ > "$OUT/FINISHED"
}
trap finish EXIT

date -u +%FT%TZ > "$OUT/STARTED"
set_env COMPILED_POLICY_ENABLED true
set_env AGENT_DRY_RUN false
log "default limits: service up (dry_run=$(recreate True False)); compiled: $(curl -s localhost:8767/admin/compiled | head -c 200)"
if [ "$SMOKE" = 1 ]; then
  "$PYI" "$ROOT/experiments/compiled_policy/s11_campaign.py" "$OUT" --ns 3 --runs 1 --decoy 0 --label smoke 2>&1 | tee -a "$OUT/campaign.log"
  exit 0
fi
"$PYI" "$ROOT/experiments/compiled_policy/s11_campaign.py" "$OUT" --runs "$RUNS" --decoy 12 --decoy-runs "$RUNS" \
  --label default 2>&1 | tee -a "$OUT/campaign.log"
set_env SAFETY_MAX_RULES_PER_MINUTE "$LPRIME"
log "raised limit L'=$LPRIME: service up (dry_run=$(recreate True False))"
"$PYI" "$ROOT/experiments/compiled_policy/s11_campaign.py" "$OUT" --ns 12 --runs "$RUNS" --decoy 0 \
  --label "lprime$LPRIME" 2>&1 | tee -a "$OUT/campaign.log"
log "DONE -> $OUT"
