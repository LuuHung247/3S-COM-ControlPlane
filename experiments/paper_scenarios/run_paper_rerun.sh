#!/usr/bin/env bash
# RERUN campaign (gpt-oss-120b, 2026-10-18)  (N-run for metrics + CI)
# Usage:  bash paper_scenarios/run_paper_final.sh
#         RUNS=10 SYNTH_REPEATS=10 bash paper_scenarios/run_paper_final.sh   # defaults
#         SYNTH_REPEATS=3 bash ...                                           # faster synthetic
set -u
cd "$(dirname "$0")/.."                       # → experiments/
PYV=../intelligence-layer/.venv/bin/python
RUNS=${RUNS:-10}                              # real-traffic trials per scenario
SYNTH_REPEATS=${SYNTH_REPEATS:-10}            # synthetic repeats (for CI on rates)
OUT=${OUT:-paper_rerun_20261018}
mkdir -p "results/$OUT/real_traffic" "results/$OUT/synthetic"

echo "############ PAPER-FINAL CAMPAIGN  (RUNS=$RUNS, SYNTH_REPEATS=$SYNTH_REPEATS) ############"

echo "===== REAL-TRAFFIC × $RUNS → results/$OUT/real_traffic/ ====="
for s in s01_web_db_bypass s05_appcore_reverse s07_dboltp_c2 \
         s09_appcore_sql_destructive s10_baseline_mgt_mon_fp; do
  echo "▶ scenarios/$s.py  (RUNS=$RUNS)"
  EVAL_RESULTS_DIR="$OUT/real_traffic" EVAL_RUNS="$RUNS" uv run python "scenarios/$s.py" \
    2>&1 | grep -iE "pass rate|aggregate|MTTD \(s\)|Confidence|Agent latency" | tail -10
done

echo "===== SYNTHETIC × $SYNTH_REPEATS → results/$OUT/synthetic/ ====="
for i in $(seq 1 "$SYNTH_REPEATS"); do
  echo "-- synthetic repeat $i/$SYNTH_REPEATS --"
  "$PYV" generalization/s11_killchain_multistage.py  >/dev/null 2>&1 || echo "  s11 err"
  "$PYV" safety/s12_privileged_neverblock.py         >/dev/null 2>&1 || echo "  s12 err"
  "$PYV" scenarios/s13_matrix_fp.py                  >/dev/null 2>&1 || echo "  s13 err"
  "$PYV" safety/s14_adversarial_safety.py            >/dev/null 2>&1 || echo "  s14 err"
  "$PYV" generalization/s15_reasoning_ablation.py    >/dev/null 2>&1 || echo "  s15 err"
  mv results/s11_*.json results/s12_*.json results/s13_*.json \
     results/s14_*.json results/s15_*.json "results/$OUT/synthetic/" 2>/dev/null
done

echo "############ DONE → results/$OUT/  (real_traffic + synthetic) ############"
echo "real_traffic files: $(ls results/$OUT/real_traffic/*.json 2>/dev/null | wc -l)"
echo "synthetic files:    $(ls results/$OUT/synthetic/*.json 2>/dev/null | wc -l)"
