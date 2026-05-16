#!/bin/bash
# Yatesbury benchmark sweep — 8 paper-aligned scenarios × 10 runs each.
# Requires compromise-*.sh + restore-*.sh on Alpine hosts (see DATAPLANE
# spec). Runs in flow-log batch mode (EVAL_MODE=batch).
#
# Total wall-clock: ~8 scenarios × ~21 min (10 runs × ~2-min window + pause) ≈ 2h45.
set -u
cd "$(dirname "$0")"
LOG="results/run_yatesbury_sweep_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results

export EVAL_MODE=batch

EVALS=(
  eval_yates_vertical_scan.py     # paper: vertical port scan
  eval_yates_syn_flood_dos.py     # paper: SYN flood DoS
  eval_yates_syn_flood_ddos.py    # paper: SYN flood DDoS
  eval_yates_udp_ddos.py          # paper: UDP DDoS
  eval_yates_distributed_scan.py  # paper: distributed scan
  eval_yates_infection_monkey.py  # paper: Infection Monkey 1/2/3 (collapsed)
  eval_yates_c2_beacon.py         # paper: C&C communication
  eval_yates_unauth_db.py         # paper: Unauthorized DB access
)

echo "=== Yatesbury sweep started $(date -u +%FT%TZ) ==="  | tee -a "$LOG"
echo "PID=$$ — detached, survives SSH disconnect"          | tee -a "$LOG"
echo "Mode: $EVAL_MODE · Total scenarios: ${#EVALS[@]} · runtime ~2h45" | tee -a "$LOG"

for ev in "${EVALS[@]}"; do
  echo ""                                                    | tee -a "$LOG"
  echo "########################################"           | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"                    | tee -a "$LOG"
  echo "########################################"           | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$?"                | tee -a "$LOG"
done

echo ""                                                       | tee -a "$LOG"
echo "=== Yatesbury sweep finished $(date -u +%FT%TZ) ==="    | tee -a "$LOG"
ls -lah results/eval_yates_*.xlsx 2>/dev/null | tail -10      | tee -a "$LOG"
