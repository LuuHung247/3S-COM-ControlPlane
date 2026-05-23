# Experiments — Zero Trust Intelligence Layer

Eval framework cho lab ZT pipeline (Suricata → intel-layer agent → SDNC/SF → LEAF iptables).

## Layout

```
experiments/
├── README.md              ← document này
├── harness/               ← shared eval framework (KHÔNG sửa per scenario)
│   ├── runner.py          ← main harness (HTTP helpers, console proxy, metrics, Excel export)
│   └── memory_runner.py   ← memory-stateful variant (no truncate decisions between runs)
├── scenarios/             ← 1 file per attack scenario (thin wrapper, ~20 lines)
│   ├── s01_web_db_lateral.py          ← S1  (ZT microseg)
│   ├── s02_web_app_burst.py           ← S2
│   ├── s03_app_db_burst.py            ← S3
│   ├── s04_app_db_sql.py              ← S4  (Destructive SQL)
│   ├── s05_app_mgt_ssh.py             ← S5
│   ├── s06_vertical_scan.py           ← S6  (NetVigil benchmark)
│   ├── s07_syn_flood.py               ← S7
│   ├── s08_distributed_syn_flood.py   ← S8
│   ├── s09_udp_flood.py               ← S9
│   ├── s10_distributed_scan.py        ← S10
│   ├── s11_multistage_propagation.py  ← S11
│   ├── s12_c2_beacon.py               ← S12
│   └── s13_unauth_db.py               ← S13
├── safety/                ← S14 adversarial safety / anti-manipulation test
│   └── s14_adversarial_safety.py      ← proposed vs Baseline B (vanilla LLM)
├── generalization/        ← S15 reasoning-vs-lookup ablation
│   └── s15_reasoning_ablation.py      ← proposed vs Baseline A (signature-keyed SOAR)
└── results/               ← per-run outputs (xlsx + json) + dated run folders
    └── YYYY-MM-DD_*/      ← consolidated runs với SUMMARY.md + AGGREGATE.json
```

**13 functional scenarios** (S1–S13) — 5 ZT lab-specific (S1–S5) + 8 NetVigil-aligned
(S6–S13, per NetVigil NSDI'24 Table 3) — plus **S14**, the adversarial safety stress-test
comparing the full pipeline against a guardrail-free vanilla LLM agent.

## Run single scenario

```bash
cd /home/dis/deploy/zerotrust/experiments
python3 scenarios/s01_web_db_lateral.py
```

Output → `results/eval_<name>_<timestamp>.{xlsx,json}` (per-run table + aggregate metrics).

## Run all 13 sequentially

```bash
cd /home/dis/deploy/zerotrust/experiments
for s in scenarios/*.py; do
  python3 -u "$s" 2>&1 | grep -E "PASS|FAIL|outcome"
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
