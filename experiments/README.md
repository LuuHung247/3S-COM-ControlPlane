# Experiments — Zero Trust Intelligence Layer

Hai experiment đánh giá agent từ 2 góc nhìn khác nhau:

| File | Purpose | Stat. mode | State giữa iterations |
|------|---------|-----------|------------------------|
| `eval_iid.py` | Statistical baseline — N i.i.d. trials của 1 attack scenario | mean / min / max / p95 across N runs | **Reset** giữa runs (workspace `decisions` + Redis DB 0 flushed) |
| `eval_killchain.py` | Case study — multi-stage kill chain (recon → lateral → exfil) | per-stage μ ± σ across chains | **Preserved** giữa các alerts trong cùng chain (cumulative state là point) |

Cả 2 chỉ truncate workspace `decisions`. Bảng `decisions_history` (frontend Policy History đọc) **không bao giờ** bị truncate — mọi decision vẫn inspectable trong UI sau khi experiment xoá workspace.

Redis DB 1 (EventsStore — FE Monitor 7-day buffer) **cũng không bị flush** — Monitor vẫn hiển thị live activity trong lúc eval chạy.

## How to run

```bash
cd /home/dis/deploy/zerotrust/experiments
python3 eval_iid.py          # 10 i.i.d. runs, exports xlsx + json
python3 eval_killchain.py    # 3-alert sequential case study × N chains, exports md + json
```

Cả 2 script **không có CLI flags** — mọi tham số (run count, attacker IP, target SID, gap seconds, output path) là constant ở đầu file. Edit constant nếu cần scenario khác.

**Dependencies:**
```bash
pip3 install openpyxl rich
```

`rich` cho output k6-style: live progress, colored badges (✓/✗ PASS/FAIL), tables với avg/min/max/p95.

## Outputs

```
experiments/results/
├── eval_iid_<timestamp>.xlsx        # per-run table + summary stats
├── eval_iid_<timestamp>.json        # raw RunResult dicts
├── eval_killchain_<timestamp>.md    # narrative timeline + reasoning per stage (1 file per chain)
└── eval_killchain_<timestamp>.json  # raw StageResult dicts
```

## Data model — vì sao 2 bảng

Intelligence layer persist mỗi decision 2 lần:

```
agent.process(alert)
        │
        ▼
   save_decision()  ──► INSERT into  decisions          (workspace)
                   ──► INSERT into  decisions_history  (audit)
```

| Table | Eval truncate? | Frontend đọc? | Purpose |
|-------|:-:|:-:|------|
| `decisions` | **Có** — mỗi `eval_iid` run, và đầu `eval_killchain` | Agent (asset reputation, multi-strategy past-incident search, operational memory) | Workspace — giữ mỗi iteration i.i.d. |
| `decisions_history` | **Không** | Frontend (Policy History page, Reasoning modal) | Full audit forever |

Split này cho phép statistical evaluation reproducible (mỗi run thấy workspace empty) trong khi FE vẫn hiển thị mọi decision agent từng đưa ra, kể cả từ session experiment trước đó.

## Per-experiment docs

- [`eval_iid.md`](./eval_iid.md) — statistical baseline methodology + interpretation
- [`eval_killchain.md`](./eval_killchain.md) — chain-attack case study methodology + interpretation
