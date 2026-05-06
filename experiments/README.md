# Experiments — Zero Trust Intelligence Layer

Hai eval cùng template (REAL attack qua console MGT → Suricata → intel-layer → SF), khác đúng **1 dòng** trong `reset()`:

| File | Purpose | Memory mode |
|------|---------|-------------|
| `eval_iid.py` | Statistical baseline — N i.i.d. trials | Reset `decisions` mỗi run → memory empty |
| `eval_memory.py` | Stateful — N runs với memory accumulating | **Preserve** `decisions` → run N thấy lịch sử run 1..N-1 |

Cả 2 dùng cùng:
- Scenario: WEB→DB microsegmentation bypass (`compromise-web.sh` → SID 9000001)
- Trigger path: console MGT (10.1.100.10) → Suricata mirror → ids-agent SSE → intel-layer
- Schema kết quả: xlsx + json với same columns
- Rich UI k6-style: header panel, per-run rule, summary table, metrics avg/min/max/p95

## Workflow đề xuất cho thesis

```bash
cd /home/dis/deploy/zerotrust/experiments

# 1. Baseline (memory OFF) — single-shot detection performance
python3 eval_iid.py

# 2. With memory (state preserved) — does memory help?
python3 eval_memory.py
```

So 2 file xlsx → delta confidence / latency / MTTD = **giá trị memory architecture**.

## What gets reset between runs

| Reset action | `eval_iid` | `eval_memory` |
|--------------|:--:|:--:|
| Disarm `compromise-web.sh` | ✓ | ✓ |
| Delete agent SF rules (else LEAF blocks SYN) | ✓ | ✓ |
| Flush Redis DB 0 (rate limiter / cache) | ✓ | ✓ |
| **TRUNCATE Postgres `decisions`** | **✓** | **✗ KEEP** |
| Reset intel-layer rate limiter | ✓ | ✓ |
| Preserve Redis DB 1 (FE Monitor 7-day buffer) | ✓ | ✓ |
| Preserve Postgres `decisions_history` (FE audit) | ✓ | ✓ |

## Outputs

```
experiments/results/
├── eval_iid_<timestamp>.xlsx       # per-run + aggregate stats
├── eval_iid_<timestamp>.json
├── eval_memory_<timestamp>.xlsx    # per-run + aggregate + memory effect
└── eval_memory_<timestamp>.json
```

`eval_memory.xlsx` có thêm **memory effect panel** trong stdout: Run 1 (cold) vs Run N (warm) delta cho confidence + latency.

## Dependencies

```bash
pip3 install openpyxl rich
```

## Adding new evals

Template chính thức là **`eval_iid.py`**. Mọi eval mới copy file này, sửa `reset()` cho phù hợp test goal:

| Test goal | Reset modification |
|-----------|--------------------|
| Stress test under load | Add concurrent attack triggers, no other change |
| Multi-source attack | Loop over multiple ATTACKER_IP, otherwise i.i.d. |
| Alert spoof / noise injection | Inject decoy alerts before trigger, measure FP rate |
| Long-window memory | Same as `eval_memory` but pause longer between runs |

Giữ nguyên: HTTP helpers, console_run, run_scenario, RunResult dataclass, export_excel, rich UI. Chỉ tinker với `reset()` và config constants.

## Per-experiment docs

- [`eval_iid.md`](./eval_iid.md) — statistical baseline methodology
- [`eval_memory.md`](./eval_memory.md) — stateful memory test methodology
