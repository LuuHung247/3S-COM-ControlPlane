# Eval A — Independent runs (statistical baseline)

## Question

When the agent sees the same canonical attack repeated under identical conditions, **how reliably does it produce the right policy decision, and how variable is the latency?**

## Design

- **N independent trials** of the same scenario (default `RUNS=10`).
- Each trial: trigger an attack from the dataplane, wait for an alert, observe the agent's decision, measure latency, verify the SF rule got pushed correctly.
- Between trials, full state reset:
  - `decisions` workspace truncated (drops past-incident memory + asset reputation labels + embeddings)
  - Redis DB 0 (agent state) + DB 1 (events buffer) flushed
  - SF rules pushed by the agent removed
  - Rate limiter + circuit breaker reset
- `decisions_history` table is **never** touched, so every trial stays in the FE Policy History.

## Why i.i.d.

Statistical aggregates (mean, stdev, percentiles) are only meaningful when each observation comes from the same distribution. If trial N+1 inherits past-incident memory from trial N, the agent's prompt context is different across trials → different distribution → mean is uninterpretable.

The reset between runs ensures every trial starts from an empty workspace. This is the i.i.d. requirement standard ML evaluations assume.

## Metrics

For each run we record:

| Metric | What it captures |
|--------|------------------|
| `outcome` | `pass` / `fail` based on whether the agent enforced a correct DROP rule within timeout |
| `mttd_s` | Mean Time To Detect — alert timestamp − attack start |
| `t_alert_to_decision_s` | Wall-clock time from alert receipt to decision write |
| `t_decision_to_enforce_ms` | Latency from decision to SF rule visible on the leaf |
| `confidence` | LLM-self-reported confidence at decision time |
| `enforcement_correct` | Whether the rule's `src_ip` matches the attacker |

The Excel report aggregates these across runs (mean ± stdev, P50/P95).

## Interpretation guide

| Signal | What it means |
|--------|---------------|
| Pass rate < 100% | Pipeline reliability issue — investigate failed runs in the JSON |
| `confidence` low variance, high mean (>0.85) | Agent is calibrated and consistent |
| `confidence` high variance | Self-consistency vote may be flipping; check L2 layer |
| `t_alert_to_decision_s` P95 >> mean | LLM tail latency or Cerebras backpressure |
| `enforcement_correct` < 100% | L4b off-target check failing somewhere — critical bug |

## Configuration

Edit constants at the top of `eval_independent.py`:

```python
RUNS = 10                              # number of i.i.d. trials
DURATION_SECONDS = 120                 # per-run timeout
ATTACKER_IP = "10.1.100.10"            # web-01 (presentation tier)
TARGET_SID = 9000001                   # WEB→DB lateral movement
OUTPUT_PATH = "results/eval_independent_<timestamp>.xlsx"
```

No CLI flags — re-run with different parameters by editing the file.

## What this experiment does NOT show

- Whether the agent's memory (past-incident retrieval, asset reputation) helps at all — i.i.d. resets ensure each run sees empty memory. This is intentional; `eval_chain_attack.py` is the experiment that exercises memory.
- How the agent handles novel attacks — every trial is the same canonical scenario. To test generalization, vary `ATTACKER_IP` / `TARGET_SID` and run multiple campaigns.
