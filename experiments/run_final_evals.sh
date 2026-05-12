#!/bin/bash
# Run eval_app_db_sql + eval_app_mgt_ssh. Skips eval_app_db_bulk (SID 9000032
# blocked by asymmetric tc-mirred capture preventing flow:established match —
# requires dataplane rule change).
set -u
cd "$(dirname "$0")"
LOG="results/run_final_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results

EVALS=(
  eval_app_db_sql.py
  eval_app_mgt_ssh.py
)

echo "=== Final eval started $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "PID=$$ — survives SSH disconnect"             | tee -a "$LOG"
for ev in "${EVALS[@]}"; do
  echo ""                                              | tee -a "$LOG"
  echo "########################################"     | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"               | tee -a "$LOG"
  echo "########################################"     | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  rc=$?
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$rc"        | tee -a "$LOG"
done
echo "=== Final eval finished $(date -u +%FT%TZ) ===" | tee -a "$LOG"
ls -lah results/*.xlsx 2>/dev/null | tail -8          | tee -a "$LOG"
