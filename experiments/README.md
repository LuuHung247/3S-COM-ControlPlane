# Experiments — Zero Trust Intelligence Layer

Eval framework cho lab ZT pipeline (Suricata → intel-layer agent → SDNC/SF → LEAF iptables).

## Layout

> **V2 fabric (8-zone / 4-leaf / 2-spine Clos).** Scenarios target the V2 topology
> (`docs/DATAPLANE_V2.md`, knowledge base `intelligence-layer/knowledge_v2/`). V1 (4-zone)
> scenarios are retired. Two families: **S01–S10 real-traffic** (controller-driven, end-to-end
> through Suricata — needs dataplane online) and **S11–S15 synthetic-injection** (POST
> `eve.json` to `/alerts` — reproducible, no dataplane). Full catalog + coverage matrix:
> [`scenarios/SCENARIOS.md`](scenarios/SCENARIOS.md).

```
experiments/
├── README.md              ← document này
├── harness/               ← shared eval framework (KHÔNG sửa per scenario)
│   ├── runner.py          ← main harness (HTTP helpers, console proxy, metrics, Excel export)
│   └── memory_runner.py   ← memory-stateful variant (no truncate decisions between runs)
├── scenarios/             ← real-traffic scenarios (S01–S10) + matrix/FP synthetic (S13)
│   ├── s01_web_db_bypass.py           ← S01  WEB→DB-OLTP microseg bypass (SID 9000001+12)
│   ├── s02_web_gw_skip.py             ← S02  WEB→APP-CORE skip APP-GW (9000002)
│   ├── s03_appgw_db_bypass.py         ← S03  APP-GW→DB-OLTP skip APP-CORE (9000004+12)
│   ├── s04_appcore_dba_exfil.py       ← S04  APP-CORE→DB-ANLT bulk+exfil (9000070+62)
│   ├── s05_appcore_reverse.py         ← S05  APP-CORE→WEB:22 reverse lateral (9000006)
│   ├── s06_worker_reverse.py          ← S06  WORKER→APP-GW reverse (9000008)
│   ├── s07_dboltp_c2.py               ← S07  DB-OLTP→external C2 beacon (9000009+60+62)
│   ├── s08_dbanlt_pivot.py            ← S08  DB-ANLT sink-violation outbound (9000010)
│   ├── s09_appcore_sql_destructive.py ← S09  APP-CORE→DB-OLTP destructive SQL (9000072)
│   ├── s10_baseline_mgt_mon_fp.py     ← S10  MGT/MON baseline — FP control (9000080+81)
│   └── s13_matrix_fp.py               ← S13  DENY-matrix coverage + FP battery [synthetic]
├── safety/                ← adversarial / guardrail synthetic evals (vs Baseline B)
│   ├── s12_privileged_neverblock.py   ← S12  MGT/MON-as-attacker + never-block conflict
│   └── s14_adversarial_safety.py      ← S14  prompt-injection + core-asset spoof
├── generalization/        ← reasoning / correlation synthetic evals (vs Baseline A)
│   ├── s11_killchain_multistage.py    ← S11  multi-stage temporal correlation
│   └── s15_reasoning_ablation.py      ← S15  reasoning-vs-lookup ablation
└── results/               ← per-run outputs (xlsx + json) + dated run folders
    └── YYYY-MM-DD_*/      ← consolidated runs với SUMMARY.md + AGGREGATE.json
```

**Functional real-traffic (S01–S10)** — cross-tier DENY, content-L7, sink-role, FP control
on the live V2 fabric. **Controlled synthetic (S11–S15)** — temporal correlation (S11),
never-block conflict (S12), DENY-matrix+FP coverage (S13), adversarial safety (S14),
reasoning-vs-lookup ablation (S15); each compares the agent against a baseline.

## Run a real-traffic scenario (S01–S10, needs dataplane + LLM online)

```bash
cd /home/dis/deploy/zerotrust/experiments
uv run python scenarios/s01_web_db_bypass.py
```

Output → `results/eval_<name>_<timestamp>.{xlsx,json}` (per-run table + aggregate metrics).

## Run a synthetic eval (S11–S15, needs only LLM online)

```bash
cd /home/dis/deploy/zerotrust/experiments
intelligence-layer/.venv/bin/python generalization/s15_reasoning_ablation.py   # or s11
intelligence-layer/.venv/bin/python safety/s14_adversarial_safety.py           # or s12
intelligence-layer/.venv/bin/python scenarios/s13_matrix_fp.py
```

Output → `results/<sNN_name>_<timestamp>.json` (summary + per-case rows).

## Run all real-traffic scenarios sequentially

```bash
cd /home/dis/deploy/zerotrust/experiments
for s in scenarios/s0*.py; do
  echo "▶ $s"; uv run python "$s" 2>&1 | grep -E "PASS|FAIL|outcome"
done
```

## Each scenario wrapper format

```python
# scenarios/s01_web_db_lateral.py — 14 dòng total
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import runner as eval_iid

eval_iid.EVAL_NAME  = "eval_web_db_lateral"
eval_iid.EVAL_TITLE = "DENY-path · WEB→DB microsegmentation bypass"
eval_iid._apply_preset("web-db-lateral")

if __name__ == "__main__":
    eval_iid.main()
```

→ Wrapper chỉ set **preset name** + **display title**. Tất cả logic chạy attack/measure/export ở `harness/runner.py`.

## Metrics measured (per run)

| Metric | Definition |
|---|---|
| MTTD | Mean time to detect (attack trigger → Suricata SID fire) |
| M1 Alert→Decision | Suricata alert → agent commits decision |
| M2 Decision→LEAF | Decision created → SF rule visible on LEAF iptables |
| M3 Correct src_ip | Agent's DROP rule blocks the actual attacker IP |
| Total E2E | trigger → enforcement (MTTD + M1 + M2) |
| Confidence | Agent's decision confidence (0.0-1.0) |
| Outcome | enforced / log_only / benign / none / rejected |
| Checks | 5/5 pass criteria (alert fired, decision made, outcome OK, rule pushed, latency OK) |

## Memory variant

`harness/memory_runner.py` — same harness nhưng **không truncate `decisions`** giữa runs, để test agent memory accumulation.

```bash
python3 harness/memory_runner.py    # run direct
```

## Adding new scenario

1. Add preset entry vào `harness/runner.py` `SCENARIO_PRESETS` dict (set attacker_ip, target_sid, trigger script, expected_outcome).
2. Create wrapper `scenarios/<NN>_<name>.py` theo template trên, gọi `_apply_preset("<key>")`.
3. (Optional) Add dataplane attacker script + MGT scenario controller nếu chưa có.

## Dependencies

```bash
pip3 install openpyxl rich
```

## Result analysis

Consolidated run folders ở `results/YYYY-MM-DD_<run_label>/` chứa:
- `SUMMARY.md` — per-scenario PASS/FAIL table + analysis
- `AGGREGATE.json` — machine-readable aggregate metrics
- `NN_<name>.{xlsx,json}` — per-scenario detail (Excel + JSON)

Mở xlsx để xem per-run timing + checks breakdown. Mở JSON để parse programmatically.
