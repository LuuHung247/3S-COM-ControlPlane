#!/bin/bash
# Resume from eval_app_db_burst onwards (first 3 already saved).
set -u
cd "$(dirname "$0")"
LOG="results/run_remaining_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results

EVALS=(
  eval_app_db_burst.py
  eval_app_db_bulk.py
  eval_app_db_sql.py
  eval_app_mgt_ssh.py
)

echo "=== Resume started $(date -u +%FT%TZ) ===" | tee -a "$LOG"
for ev in "${EVALS[@]}"; do
  echo ""                                       | tee -a "$LOG"
  echo "########################################"  | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"            | tee -a "$LOG"
  echo "########################################"  | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  rc=$?
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$rc"    | tee -a "$LOG"
done
echo "=== Resume finished $(date -u +%FT%TZ) ===" | tee -a "$LOG"
ls -lah results/*.xlsx 2>/dev/null | tail -5     | tee -a "$LOG"
