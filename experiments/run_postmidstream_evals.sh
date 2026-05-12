#!/bin/bash
# Rerun bulk + sql after stream.midstream:true enabled on Suricata.
set -u
cd "$(dirname "$0")"
LOG="results/run_postmidstream_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results
EVALS=(eval_app_db_bulk.py eval_app_db_sql.py)
echo "=== Post-midstream rerun $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "PID=$$ — detached, survives SSH disconnect"     | tee -a "$LOG"
for ev in "${EVALS[@]}"; do
  echo ""                                              | tee -a "$LOG"
  echo "########################################"     | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"               | tee -a "$LOG"
  echo "########################################"     | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$?"          | tee -a "$LOG"
done
# Then ssh after both have run
echo ""                                                | tee -a "$LOG"
echo "########################################"       | tee -a "$LOG"
echo "# [$(date -u +%FT%TZ)] START eval_app_mgt_ssh.py" | tee -a "$LOG"
echo "########################################"       | tee -a "$LOG"
python3 eval_app_mgt_ssh.py 2>&1 | tee -a "$LOG"
echo "# [$(date -u +%FT%TZ)] END eval_app_mgt_ssh.py rc=$?" | tee -a "$LOG"
echo "=== finished $(date -u +%FT%TZ) ==="            | tee -a "$LOG"
ls -lah results/eval_app_db_bulk_*.xlsx results/eval_app_db_sql_*.xlsx results/eval_app_mgt_ssh_*.xlsx 2>/dev/null | tail -5 | tee -a "$LOG"
