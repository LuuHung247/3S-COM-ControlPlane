#!/usr/bin/env bash
# Enforcement on, compiled policy off, for the listed S6 cases; always restores dry-run.
set -u
cd "$(dirname "$0")/../.."; ROOT=$(pwd); ENV=$ROOT/intelligence-layer/.env
PYI=$ROOT/intelligence-layer/.venv/bin/python
OUT=$ROOT/experiments/results/runtime_only_rerun_$(date -u +%Y%m%d_%H%M); mkdir -p "$OUT"
recreate() { (cd "$ROOT" && docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1); }
finish() {
  "$PYI" -c "import sys; sys.path.insert(0,'$ROOT/experiments'); from common import reliable; print('cleaned', reliable.clean_rules())"
  sed -i "s/^AGENT_DRY_RUN=.*/AGENT_DRY_RUN=true/" "$ENV"; recreate
  "$PYI" -c "import sys; sys.path.insert(0,'$ROOT/experiments'); from common import reliable; print('dry_run', reliable.preflight(want_dry_run=True)['health']['dry_run'], 'rules', len(reliable.agent_rules()))"
}
trap finish EXIT
sed -i '/^COMPILED_POLICY_ENABLED=/d' "$ENV"
sed -i "s/^AGENT_DRY_RUN=.*/AGENT_DRY_RUN=false/" "$ENV"; recreate
"$PYI" "$ROOT/experiments/compiled_policy/rerun_runtime_only.py" "$OUT/rerun.jsonl" "$@"
