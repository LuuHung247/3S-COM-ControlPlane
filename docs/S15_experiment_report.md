# Experiment S15 — Reasoning-vs-Lookup Ablation (signature-hint ablation)

> Self-contained report for the thesis-writing agent. Companion to
> [`docs/agent_reasoning_vs_lookup_findings.md`](./agent_reasoning_vs_lookup_findings.md)
> (which established, from the code, that a per-SID hint is injected into the
> decision prompt). S15 measures **empirically** whether the agent still decides
> correctly when that hint is removed — i.e. whether it *reasons* or merely
> *looks up*. **Result is nuanced and honest: it is not a clean win. Do not
> over-claim.**

---

## TL;DR

The agent is **not** a signature lookup, but it is **not** a reliable reasoner on
every attack class either:

- It **generalises to unknown signatures**: on novel SIDs absent from its table it
  still mitigates **6/9 (67%)** of attacks across 3 runs, while a signature-keyed
  SOAR (Baseline A) mitigates **0/9 (0%)** — the SOAR is structurally blind to any
  signature not in its playbook.
- It **reasons independently of the handed action**: in one run it *overrode* a
  known SID's recommended `block` with `log_only` (a pure lookup never overrides
  itself), and it correctly splits identical-metadata flows by zone policy
  (WEB→DB DROP vs APP→DB allow).
- **But it is non-deterministic**: the same input yields different outcomes across
  runs, concentrated on the **cross-tier SSH→MGT** class, which the agent
  under-reacts to (treating SSH-to-management as plausibly-admin) — *even with the
  hint present*. Non-deterministic security decisions are a real limitation.

Net: the agent buys **generalisation to novel signatures** that a SOAR cannot
provide, at the cost of **determinism**, with a measured weak spot on
cross-tier-SSH-to-management.

---

## Motivation

The code review (findings doc) confirmed the decision prompt is handed, for *known*
SIDs, the attack-type label and a recommended action. That makes the reviewer's
critique — "for known signatures, how is this different from a rule-based SOAR?" —
land for those cases. S15 isolates the question by **removing the hint** and seeing
whether the agent still decides correctly, and by comparing against a SOAR that
*only* has the signature table.

## Method

`experiments/generalization/s15_reasoning_ablation.py`. Each flow is posted as a
synthetic alert to the live agent (`POST /alerts`). Two hint levels per malicious
flow:

- **known**   — the real SID (full SID→action hint in the prompt).
- **unknown** — an out-of-table SID (`sid_context="Unknown SID"`) + a *generic*
  signature message (`"Generic protocol anomaly detected"`), so the agent must
  decide from the flow tuple + zone-policy + topology + baseline alone.

Two legitimate ALLOW-path flows are added at the unknown level as controls (correct
= do **not** DROP). **Killer comparison:** M1-unknown (WEB→DB) vs L1-unknown
(APP→DB) — identical unknown SID, generic msg, and severity; only the source zone
differs — so a correct split can only come from policy reasoning.

Systems compared:
- **Proposed** — the live agent.
- **Baseline A** — a Traditional SOAR: a fixed playbook keyed on Suricata SIDs. If
  the SID is in its known-dangerous set → DROP; else → no action. (Pure-Python
  lookup mirroring the system's own `SID_KNOWLEDGE` block-set; no model.)

The agent ran LIVE; rules enforced during the run were removed (per-case + final
cleanup; testbed verified clean afterwards). The per-IP rate limiter was reset per
case; Cerebras 429s were retried (an early run was invalidated by 429 and discarded).

Zone policy (knowledge/infra/policy-matrix.md): WEB→DB DENY, WEB→APP ALLOW,
WEB→MGT DENY, APP→DB ALLOW, APP→MGT DENY.

## Results (N = 3 runs)

Per-case outcome across the three runs (✓ = correct decision):

| Case | Flow | Hint | Run 1 | Run 2 | Run 3 | Agent correct |
|---|---|---|---|---|---|---|
| M1-known   | WEB→DB  | known SID | DROP ✓ | DROP ✓ | DROP ✓ | 3/3 |
| **M1-unknown** | WEB→DB  | none | DROP ✓ | DROP ✓ | DROP ✓ | **3/3 (stable)** |
| M2-known   | APP→MGT:22 | known SID | DROP ✓ | DROP ✓ | DROP ✓ | 3/3 |
| M2-unknown | APP→MGT:22 | none | benign ✗ | DROP ✓ | DROP ✓ | 2/3 |
| M3-known   | WEB→MGT:22 | known SID | DROP ✓ | rejected ✗ | DROP ✓ | 2/3 |
| M3-unknown | WEB→MGT:22 | none | benign ✗ | benign ✗ | DROP ✓ | 1/3 |
| L1-unknown | APP→DB (legit) | none | benign ✓ | benign ✓ | benign ✓ | 3/3 |
| L2-unknown | WEB→APP (legit) | none | not-drop ✓ | held ✓ | benign ✓ | 3/3 |

Aggregate (cells = case × run):

| Metric | Proposed | Baseline A (SOAR) |
|---|---|---|
| **Mitigation, unknown-SID malicious** (9 cells) | **6/9 (67%)** | **0/9 (0%)** |
| Mitigation, known-SID malicious (9 cells) | 8/9 (89%) | 9/9 (100%) |
| Mitigation, all malicious (18 cells) | 14/18 (78%) | 9/18 (50%) |
| Legitimate controls not wrongly dropped (6 cells) | 6/6 (100%) | 6/6 (100%) |
| Correct decision overall (24 cells) | 20/24 (83%) | 15/24 (63%) |

Per-run unknown-SID mitigation: 1/3, 2/3, 3/3.

## Analysis

**1. The agent is not a signature lookup.** Three independent pieces of evidence:
- *Generalisation.* On unknown SIDs it mitigates 6/9 vs the SOAR's 0/9. A
  signature-keyed playbook cannot act on a signature it does not have; the agent
  reaches the decision from zone policy + host/asset context.
- *Policy reasoning on identical metadata.* M1-unknown (WEB→DB) is DROPped 3/3 while
  L1-unknown (APP→DB) is never dropped 3/3 — same unknown SID, same generic message,
  same severity; only the source zone differs. The split is policy reasoning.
- *Action override.* In Run 2, M3-known (real SID 9000035, whose table entry
  recommends `block`) was decided `log_only` by the agent and then rejected by the
  L6 severity validator (`P1 only allows DROP`). A lookup table never contradicts
  its own recommended action; the agent does, because it reasons over the
  recommendation rather than applying it blindly.

**2. The agent is non-deterministic, with a concentrated weak spot.** The same
input produces different outcomes across runs (temperature 0.1): M2-unknown 2/3,
M3-known 2/3, M3-unknown 1/3. The instability is concentrated on **cross-tier
SSH→MGT** (M2, M3). M3-known being noisy *with the full hint present* shows the
weakness is in the agent's threat assessment of this class — it tends to treat
SSH-to-management as plausibly-legitimate admin access and under-react — not a mere
absence of the hint. By contrast, WEB→DB (a textbook lateral-movement violation) and
the legitimate controls are rock-solid across all runs.

**3. Fairness caveat.** The explicit policy verdict (`APP→MGT = DENY`,
`WEB→MGT = DENY`) is **not pre-loaded** into the decision prompt; it lives in the
Neo4j KG and is reachable only via the on-demand `query_kg` tool (consistent with
the kill-chain anti-leak design). The MGT under-reaction is therefore partly that
the agent does not proactively query the policy for non-obvious cases. Surfacing the
verdict (or forcing the query) might lift the MGT cases — but that is a
prompt/context change and was deliberately **not** done here (this run keeps the
system unmodified).

**4. Tradeoff vs the SOAR.** Baseline A is perfectly deterministic but generalises
to nothing (0/9 on novel signatures). The agent trades determinism for the ability
to reason about flows its signature table never anticipated.

## Honest framing for the thesis

Defensible claim: *the agent is not a signature lookup — it generalises to unknown
signatures, where a signature-keyed SOAR is structurally blind, and it can override
the recommended action, demonstrating independent reasoning; this comes at the cost
of non-determinism and a measured weakness on the cross-tier-SSH-to-management
class.* Do **not** claim deterministic or complete coverage. The non-determinism and
the MGT weak spot should be reported as limitations (examiners respect this), with
the policy-verdict-surfacing as proposed future work.

## Limitations

- Synthetic alerts injected via the API exercise the *decision path*; they do not
  prove detection of evasive *traffic* that Suricata under-classifies (that needs
  live traffic generation + Suricata tuning — out of scope).
- N = 3 is a small sample; the per-cell rates (e.g. M3-unknown 1/3) are indicative,
  not precise. The qualitative pattern (WEB→DB stable, SSH→MGT noisy, SOAR 0 on
  unknowns) is consistent across runs.
- Baseline A models a signature-keyed SOAR; a threshold-based SOAR is a separate
  axis not evaluated here.

## Artifacts

| Artifact | Path |
|---|---|
| Driver | `experiments/generalization/s15_reasoning_ablation.py` |
| Raw results (3 runs) | `experiments/results/s15_reasoning_ablation_20260523_{161657,163602,164321}.json` |
| LaTeX section | `docs/s15_reasoning_ablation.tex` |
| Code-level findings (prerequisite) | `docs/agent_reasoning_vs_lookup_findings.md` |
| This report | `docs/S15_experiment_report.md` |
