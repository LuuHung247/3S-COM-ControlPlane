#!/usr/bin/env bash
# Run the curated Q1 paper experiment set → results/paper_exp/
# Usage:  bash paper_scenarios/run_paper.sh            # 1 run each (smoke)
#         RUNS=10 bash paper_scenarios/run_paper.sh    # campaign (real-traffic N runs)
#         GROUP=synthetic bash paper_scenarios/run_paper.sh   # only synthetic
set -u
cd "$(dirname "$0")/.."                      # → experiments/
PYV=../intelligence-layer/.venv/bin/python   # synthetic scripts (need only the agent)
RUNS=${RUNS:-1}
GROUP=${GROUP:-all}
mkdir -p results/paper_exp/real_traffic results/paper_exp/synthetic

if [[ "$GROUP" == "all" || "$GROUP" == "real" ]]; then
  echo "===== REAL-TRAFFIC (→ results/paper_exp/real_traffic/, RUNS=$RUNS) ====="
  # NOTE: s04_appcore_dba_exfil excluded from the pass/fail set — it is a genuinely
  # AMBIGUOUS case (bulk UNION SELECT on the legitimate analytics-report path) with no
  # clean ground truth: the agent legitimately flip-flops log_only(conf~0.90) ↔
  # DROP(conf~0.88) across runs. Kept in repo as a calibration/uncertainty example, not
  # a scored scenario. Content-L7 enforcement is covered cleanly by s09 (destructive SQL).
  for s in s01_web_db_bypass s05_appcore_reverse s07_dboltp_c2 \
           s09_appcore_sql_destructive s10_baseline_mgt_mon_fp; do
    echo "▶ scenarios/$s.py"
    EVAL_RESULTS_DIR=paper_exp/real_traffic EVAL_RUNS="$RUNS" uv run python "scenarios/$s.py" \
      2>&1 | grep -iE "PASS|FAIL|pass rate|outcome=|error|traceback" | tail -6
  done
fi

if [[ "$GROUP" == "all" || "$GROUP" == "synthetic" ]]; then
  echo "===== SYNTHETIC (controlled / ablation → results/paper_exp/synthetic/) ====="
  "$PYV" generalization/s11_killchain_multistage.py 2>&1 | tail -4
  "$PYV" safety/s12_privileged_neverblock.py        2>&1 | tail -4
  "$PYV" scenarios/s13_matrix_fp.py                 2>&1 | tail -4
  "$PYV" safety/s14_adversarial_safety.py           2>&1 | tail -4
  "$PYV" generalization/s15_reasoning_ablation.py   2>&1 | tail -4
  # synthetic scripts write to results/ flat → move into the organized subfolder
  mv results/s11_*.json results/s12_*.json results/s13_*.json \
     results/s14_*.json results/s15_*.json results/paper_exp/synthetic/ 2>/dev/null
fi
echo "Done → results/paper_exp/{real_traffic,synthetic}/"
