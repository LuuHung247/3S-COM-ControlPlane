# Experiments — Zero Trust Intelligence Layer

Two experiments evaluate the agent from different angles:

| File | Purpose | Stat. mode | State between iterations |
|------|---------|-----------|--------------------------|
| `eval_independent.py` | Statistical baseline — repeated i.i.d. trials of one canonical attack | mean ± stdev across N runs | **Reset** between runs (DB workspace flushed) |
| `eval_chain_attack.py` | Case study — one multi-stage kill chain (recon → lateral → exfil) | qualitative timeline | **Preserved** between alerts (cumulative state is the point) |

Both scripts truncate only the workspace `decisions` table at start. The `decisions_history` table — read by the frontend Policy History page — is **never** truncated, so every decision stays inspectable in the UI even after experiments wipe the workspace.

## How to run

```bash
cd /home/dis/deploy/zerotrust/experiments
python3 eval_independent.py        # 10 i.i.d. runs, exports xlsx + json
python3 eval_chain_attack.py       # 3-alert sequential case study, exports md + json
```

Both scripts have **no CLI flags** — all parameters (run count, attacker IP, target SID, gap seconds, output path) are constants at the top of each file. Edit the constants if you want a different scenario.

## Outputs

```
experiments/results/
├── eval_independent_<timestamp>.xlsx     # per-run table + summary stats
├── eval_independent_<timestamp>.json     # raw RunResult dicts
├── chain_attack_<timestamp>.md           # narrative timeline + reasoning per stage
└── chain_attack_<timestamp>.json         # raw StageResult dicts
```

## Data model — why two tables

The intelligence layer persists every decision twice:

```
agent.process(alert)
        │
        ▼
   save_decision()  ──► INSERT into  decisions          (workspace)
                   ──► INSERT into  decisions_history  (audit)
```

| Table | Truncated by eval? | Read by | Purpose |
|-------|-------------------|---------|---------|
| `decisions` | **Yes** — at start of each `eval_independent` run, and at start of `eval_chain_attack` | Agent (asset reputation, multi-strategy past-incident search, operational memory) | Workspace — keeps each iteration i.i.d. |
| `decisions_history` | **No** — never | Frontend (Policy History page, Reasoning modal) | Full audit forever |

This split lets statistical evaluations stay reproducible (each run sees an empty workspace) while the FE can still display every decision the agent has ever made, including those from previous experiment sessions.

## Per-experiment docs

- [`eval_independent.md`](./eval_independent.md) — statistical baseline methodology + interpretation
- [`eval_chain_attack.md`](./eval_chain_attack.md) — chain-attack case study methodology + interpretation
