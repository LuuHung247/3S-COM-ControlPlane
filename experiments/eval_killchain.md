# Eval Killchain — Sequential multi-stage attack case study

## Question

When the agent sees a multi-stage kill chain (recon → lateral movement → exfiltration) from the same source IP within minutes, **does cumulative context (past-incident retrieval, asset reputation, alert history) actually change its behavior across stages?**

This is the experiment that exercises the agent's institutional knowledge — the part `eval_iid.py` deliberately suppresses with i.i.d. resets.

## Scenario

Three alerts in sequence from `web-01` (10.1.100.10), with a configurable gap between them (default 30 seconds):

| Stage | T+ | SID | Severity | Signature |
|------:|---:|----:|---------:|-----------|
| 1 | 0s | 9000010 | P3 | ICMP ping sweep — reconnaissance |
| 2 | 30s | 9000001 | P1 | WEB direct to DB — microsegmentation bypass |
| 3 | 60s | 9000002 | P1 | DB initiating outbound — possible exfiltration |

The kill chain matches the `presentation-tier-breach-to-data-exfiltration` playbook in `threat_playbook.py`.

## Design

Unlike `eval_iid.py`, this experiment is **state-dependent**:

- One initial cleanup at start (clear workspace + Redis + agent rules) so the chain begins from a known clean baseline.
- **No reset between stages** — alert N+1 sees the agent's memory built up by alerts 1..N.
- Output is a narrative timeline + per-stage reasoning trace dump, not statistical aggregates.

## What we expect to see

If the agent's memory works:

- **Stage 2 vs Stage 1**: Stage 2 confidence ≥ Stage 1 because past-incident retrieval surfaces stage-1 alert + asset reputation drops.
- **Stage 3 vs Stage 2**: Stage 3 confidence highest. Multi-strategy retrieval finds the same MITRE technique (lateral SID 9000001 with mitre T1021) plus the recurring-IP pattern.
- **Latency progression**: Stage 2 may be faster than Stage 1 (Cerebras response cache hit on similar shape). Stage 3 may push a different rule because target IP changed (DB outbound → external).
- **Containment**: by Stage 3, an enforced rule from Stage 2 may already block the attacker's continued attempts. Document if this happens.

If memory is not helping:

- Confidence flat across stages → reputation/multi-strategy retrieval not influencing the LLM as expected.
- This is also a useful finding — write it up.

## Output

After the run, the script writes:

```
experiments/results/chain_attack_<timestamp>.md      # human-readable timeline
experiments/results/chain_attack_<timestamp>.json    # raw StageResult per stage
```

The Markdown file contains:
- A timeline table (T+ offset, SID, outcome, action, confidence, latency, TTL).
- Per-stage primary hypothesis + first reasoning step (from V3 Stage 2 trace).
- A "Notes for thesis" hint section.

## Configuration

Edit constants at the top of `eval_killchain.py`:

```python
ATTACKER_IP = "10.1.100.10"        # web-01
TARGET_IP   = "10.1.200.10"        # db-01 — used for stages 1-2; stage 3 hits 8.8.8.8
GAP_SECONDS = 30                   # interval between alerts
RUN_INITIAL_CLEANUP = True         # set False to resume on existing state
OUTPUT_PATH = "results/chain_attack_<timestamp>.md"
```

No CLI flags. To compare different cadences, edit `GAP_SECONDS` and re-run.

## How this complements `eval_iid.py`

| Aspect | `eval_iid.py` | `eval_killchain.py` |
|--------|---------------|---------------------|
| Question | Reliability under repetition | Memory + correlation across stages |
| Output | Statistics (avg/min/max/p95) | Narrative + per-stage μ ± σ |
| State between trials | Reset (i.i.d.) | Preserved within chain (state-dependent) |
| Run count | N independent runs (default 10) | N chains × 3 stages |
| For thesis | Tables, charts | Case-study figure, reasoning excerpts |

Use both. `eval_iid.py` says "the baseline pipeline works"; `eval_killchain.py` says "the memory architecture pays off".
