#!/usr/bin/env bash
# Second-model campaign for S6–S10 (injected). Temporarily switches intelligence-layer
# (and Baseline-B, which reads the same .env) to $MODEL, then restores the original .env.
set -u
cd "$(dirname "$0")/../.."                      # → zerotrust/
MODEL=${MODEL:-qwen-3.8-27b}
REPEATS=${REPEATS:-10}
ENV=intelligence-layer/.env
BAK=intelligence-layer/.env.bak.gptoss.20261025
OUT=experiments/results/multimodel_${MODEL}_$(date -u +%Y%m%d)
PYV=intelligence-layer/.venv/bin/python
mkdir -p "$OUT"

restore() {
  cp -p "$BAK" "$ENV"
  docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1
  echo "[restore] .env restored, intelligence-layer recreated on original model $(date -u +%T)"
}
trap restore EXIT

sed -i -E "s/^LLM_PRIMARY_MODEL=.*/LLM_PRIMARY_MODEL=${MODEL}/; s/^LLM_FAST_MODEL=.*/LLM_FAST_MODEL=${MODEL}/; \
           s/^LLM_PRIMARY_REASONING_EFFORT=.*/LLM_PRIMARY_REASONING_EFFORT=/; s/^LLM_FAST_REASONING_EFFORT=.*/LLM_FAST_REASONING_EFFORT=/" "$ENV"
docker compose up -d --no-deps --force-recreate intelligence-layer >/dev/null 2>&1
for i in $(seq 1 30); do curl -sf localhost:8767/health >/dev/null && break; sleep 5; done
echo "[start] $(date -u +%FT%TZ) model=$(docker exec intelligence-layer printenv LLM_PRIMARY_MODEL)" | tee "$OUT/STARTED"

cd experiments
for i in $(seq 1 "$REPEATS"); do
  echo "-- repeat $i/$REPEATS --"
  for s in generalization/s11_killchain_multistage.py safety/s12_privileged_neverblock.py \
           scenarios/s13_matrix_fp.py safety/s14_adversarial_safety.py generalization/s15_reasoning_ablation.py; do
    "../$PYV" "$s" >/dev/null 2>&1 || echo "  $s err"
  done
  mv results/s11_*.json results/s12_*.json results/s13_*.json results/s14_*.json results/s15_*.json "../$OUT/" 2>/dev/null
done
cd ..
date -u +%FT%TZ > "$OUT/FINISHED"
echo "[done] files: $(ls $OUT/*.json | wc -l)"
