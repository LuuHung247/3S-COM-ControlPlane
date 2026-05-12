#!/bin/bash
# Sequentially run all eval wrappers (10 runs each). Logs to one master file.
# Each script produces its own results/eval_<name>_<ts>.xlsx + .json
set -u

cd "$(dirname "$0")"

LOG="results/run_all_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results

EVALS=(
  eval_iid.py
  eval_db_exfil.py
  eval_web_app_burst.py
  eval_app_db_burst.py
  eval_app_db_bulk.py
  eval_app_db_sql.py
  eval_app_mgt_ssh.py
)

echo "=== Master run started $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "Sequence: ${EVALS[*]}" | tee -a "$LOG"
echo "" | tee -a "$LOG"

for ev in "${EVALS[@]}"; do
  echo "" | tee -a "$LOG"
  echo "########################################" | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"          | tee -a "$LOG"
  echo "########################################" | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  rc=$?
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$rc" | tee -a "$LOG"
done

echo "" | tee -a "$LOG"
echo "=== Master run finished $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "Results in: $(pwd)/results/" | tee -a "$LOG"
ls -lah results/*.xlsx 2>/dev/null | tail -10 | tee -a "$LOG"
