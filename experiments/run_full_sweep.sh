#!/bin/bash
# Full 7-scenario sweep, 10 IID runs each, ~2.5 h total wall clock.
# Detached: survives SSH disconnect.
set -u
cd "$(dirname "$0")"
LOG="results/run_full_sweep_$(date +%Y%m%d_%H%M%S).log"
mkdir -p results

EVALS=(
  eval_iid.py            # SID 9000001 — WEB→DB direct
  eval_db_exfil.py       # SID 9000002 — DB outbound
  eval_web_app_burst.py  # SID 9000030 — WEB→APP burst
  eval_app_db_burst.py   # SID 9000031 — APP→DB burst
  eval_app_db_sql.py     # SID 9000033 — APP→DB DROP TABLE
  eval_app_mgt_ssh.py    # SID 9000035 — cross-tier SSH
)

echo "=== Full sweep started $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "PID=$$ — detached, survives SSH disconnect"   | tee -a "$LOG"
echo "Total scenarios: ${#EVALS[@]} × 10 runs ≈ 2.5 h" | tee -a "$LOG"

for ev in "${EVALS[@]}"; do
  echo ""                                             | tee -a "$LOG"
  echo "########################################"    | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] START $ev"             | tee -a "$LOG"
  echo "########################################"    | tee -a "$LOG"
  python3 "$ev" 2>&1 | tee -a "$LOG"
  echo "# [$(date -u +%FT%TZ)] END $ev rc=$?"         | tee -a "$LOG"
done

echo ""                                               | tee -a "$LOG"
echo "=== Full sweep finished $(date -u +%FT%TZ) ===" | tee -a "$LOG"
ls -lah results/eval_*.xlsx 2>/dev/null | tail -10    | tee -a "$LOG"
