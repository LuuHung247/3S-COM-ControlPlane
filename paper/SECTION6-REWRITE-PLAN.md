# BIZM — plan for rewriting the evaluation around exposure reduction

Written for: the author, as the working plan for the revised §5.3–§6. All numbers below were
measured on 2026-10-26 on the rebuilt testbed (29 custom SIDs, ET Open disabled) with the
upgraded agent, from `experiments/results/matrix_sweep_*.json` (5 repeats) and
`experiments/results/s11_heldout/` (5 repeats).

## 1. What changes, and why

The submitted evaluation reports response correctness (precision / TCR / F1) on ten
author-designed scenarios. Three reviewers independently objected to the scale and to the
fact that the authors chose the scenarios. A deterministic rule that encodes the same
labelling criteria matches that score, so accuracy on a fixed, authored case set cannot
carry the paper's claim.

The revision keeps response correctness but makes it secondary, and leads with the
question the microsegmentation literature actually asks: **after a workload is
compromised, how much lateral exposure does the system remove, and at what cost to
legitimate traffic?** This is measured, not argued, and the evaluation space is defined by
the deployed architecture rather than by the authors.

## 2. New evaluation space: the complete policy matrix

The 8-zone matrix has 56 ordered off-diagonal zone pairs — 36 DENY and 20 ALLOW. Cases are
generated mechanically (`experiments/matrix_sweep/build_cases.py`) from three artefacts
authored before and independently of this evaluation: the policy matrix, the SID
catalogue, and the NEVER_BLOCK protected set. Ground truth follows from those artefacts:

| case family | condition | expected |
|---|---|---|
| denied cell, severe signature, source not protected | 35 cases | contain |
| permitted cell, content/behaviour override signature | 7 cases | contain |
| permitted cell, protected source | 13 cases | do not contain |
| permitted cell, informational signature (FP control) | 20 cases | do not contain |

75 cases, 42 contain / 33 do-not-contain. No case is hand-picked and no label is
hand-assigned. Alerts are injected at the agent interface, as in the submitted S6–S10.

**Detection blind spot found mechanically.** Of the 36 denied cells, exactly one —
MONITORING→MGT — is covered by no custom signature. This is a property of the deployed
ruleset, surfaced by intersecting the catalogue with the matrix, and is reported as a
detection-layer gap rather than an agent result.

**Fabric matches intent.** The 38 ACCEPT rules installed across the four leaves implement
all 20 ALLOW cells, with no missing cell and no permission absent from the matrix. The
knowledge the agent reasons over is therefore grounded in the fabric, which is a
precondition for every number that follows.

## 3. Exposure metrics

The fabric is modelled as a directed service graph: an edge (src zone, dst zone, port)
exists when the matrix permits the pair and the destination exposes that service.
Following the microsegmentation evaluation framework already cited as [4]:

- **ENICE** — ordered zone pairs reachable over permitted edges.
- **CJR** — reachable (source, crown-jewel) pairs. Crown jewels are the critical assets
  holding confidential or restricted data: DB-OLTP, DB-ANALYTICS, MGT.
- **MPL** — mean shortest hop count from a source to a reachable crown jewel.

| configuration | edges | ENICE | CJR | MPL |
|---|---|---|---|---|
| flat (no segmentation) | 105 | 56 | 21 | 1.00 |
| deployed static matrix | 40 | 28 | 13 | 1.54 |

Static microsegmentation halves lateral reach and pushes crown jewels one half-hop further
away. It provides, by construction, no runtime response.

Per incident the effect of the installed rule is measured at two granularities, because a
containment rule acts on a host and port while lateral reach is a zone property:
zone-level residual reach, and service-level residual edges from the compromised source.
Collateral is the set of legitimate baseline flows those same removed edges carry.

## 4. Results table (§6.1 replacement)

375 decisions (75 cases x 5 repeats), single tagged build, rebuilt testbed.

| system | accuracy | 95% CI | FN | Δ zone | Δ service | crown jewels contained | legit flows cut | critical cut |
|---|---|---|---|---|---|---|---|---|
| static matrix only | 0.440 | [38.9, 49.2] | 210 | 0 | 0 | 0 | 0 | 0 |
| SOAR, host isolation | 0.947 | [91.9, 96.7] | 20 | 465 | 440 | 160 | 220 | 90 |
| fixed flow-scope rule | 1.000 | [99.0, 100] | 0 | 0 | 35 | 0 | 35 | 15 |
| graph rule (BIZM without the LLM) | 1.000 | [99.0, 100] | 0 | 0 | 35 | 0 | 35 | 15 |
| BIZM | 1.000 | [99.0, 100] | 0 | 0 | 35 | 0 | 35 | 15 |

McNemar against BIZM: static matrix p = 1.2e-63; SOAR b = 20, c = 0, p = 1.9e-06; fixed
flow-scope and graph rule b = c = 0, p = 1. BIZM chose flow scope on all 210 enforced
decisions and produced no incorrect decision in any repeat.

### S1–S10 on the final build (§6.1, replacing the submitted numbers)

Single tagged build `intelligence-layer:paper-final-20261026`, rebuilt testbed, 2026-10-26.
S1–S5 drive the live V2 controllers over the fabric (10 runs each); S6–S10 inject alerts at
the agent interface (10 repeats each).

| scenario | pass | MTTD median | M1 alert→decision | M2 decision→LEAF | confidence |
|---|---|---|---|---|---|
| S1 WEB→DB-OLTP bypass | 10/10 | 2.95 s | 3.14 ± 0.65 s | 2.42 ± 1.62 s | 0.88–0.95 |
| S2 APP-CORE reverse | 10/10 | 3.00 s | 3.69 ± 0.62 s | 1.76 ± 1.11 s | 0.88–0.92 |
| S3 DB-OLTP C2 beacon | 10/10 | 0.55 s | 3.06 ± 0.51 s | 4.69 ± 2.72 s | 0.88–0.95 |
| S4 destructive SQL (permitted path) | 10/10 | 3.10 s | 3.34 ± 1.14 s | 3.15 ± 2.27 s | 0.92–0.94 |
| S5 MGT/MON baseline (FP control) | 10/10 none | n/a | n/a | n/a | n/a |

Pooled over the 40 enforced live runs: M1 median 3.12 s (p95 4.51 s), M2 median 2.28 s
(p95 7.57 s), end-to-end median 6.00 s. MTTD median is 2.95 s but its p95 is 39 s, set by
how long the sensor takes to raise threshold-based alerts, not by the response loop.

| scenario | BIZM | baseline |
|---|---|---|
| S6 matrix coverage + FP | TP 48, FN 2, FP 0, TN 40 | — |
| S7 adversarial (90 decisions) | 0 unsafe enforcements; core availability 1.000 | Baseline-B 90/90 unsafe; availability 0.111 |
| S8 never-block (40 decisions) | 40/40 respected | Baseline-B blocked the protected host 40/40 |
| S9 signature ablation (90) | 88/90; unknown signatures 28/30 | SOAR-A 60/90; unknown signatures 0/30 |
| S10 kill chain (10) | correlation detected 10/10; cold run enforced 10/10 | confidence lift 0.000 |

**Response correctness over the 140 labelled decisions (S1–S5 plus S6):**

| metric | value | 95% CI |
|---|---|---|
| Precision | 100.00% | [95.9, 100] |
| TCR | 97.78% | [92.2, 99.7] |
| F1 | 98.88% | — |
| FPR | 0.00% | [0.0, 7.1] |
| Accuracy | 98.57% | [94.9, 99.8] |

TP 88, FN 2, FP 0, TN 50. The two missed threats are one run of D1 lost to a transient
HTTP 500 from the enforcement path and one run of D4 (inbound management) answered
log_only. S9's two misses are an unknown-signature case held at confidence 0.66 for review
and one answered log_only, i.e. both fall on the review path rather than on enforcement.

**Cost per decision (R4-5).** Measured per model call on this build: prompt 10,095 tokens
mean (median 10,397, max 12,534), completion 357 (median 271), of which 91 are reasoning
tokens; model latency median 1.1 s. The prompt dominates and is dominated in turn by the
retrieved knowledge context. A decision issues one reasoning call plus one audit-trace
call, so roughly 21K tokens per enforced decision.

### Scope selection on the held-out set (§6.3)

30 decisions (6 held-out cases x 5 repeats). Hosts, zones and signatures are disjoint from
the set used while developing the prompt; the case set and every baseline were frozen
before the run.

| system | correct | accuracy | 95% CI | legit flows cut |
|---|---|---|---|---|
| SOAR, host isolation | 10/30 | 0.333 | [17.3, 52.8] | 70 |
| fixed flow-scope rule | 15/30 | 0.500 | [31.3, 68.7] | 5 |
| graph rule (BIZM without the LLM) | 30/30 | 1.000 | [88.4, 100] | 25 |
| BIZM | 30/30 | 1.000 | [88.4, 100] | 25 |

McNemar against BIZM: SOAR b = 20, c = 0, p = 1.9e-06; fixed flow-scope b = 15, c = 0,
p = 6.1e-05; graph rule b = c = 0, p = 1.

Scope choice was identical in all five repeats of every case. On the pivot case BIZM named
the upstream root-cause source in 5/5 repeats, and the rule it installed already contained
the attacker's next step in 4/5 repeats (the follow-up alert was suppressed before reaching
the model).

Reported with Clopper–Pearson intervals, and McNemar on the paired per-decision outcomes
for each comparison against BIZM. Because the repeats of one case are not independent,
accuracy intervals are computed per case and the repeat count is reported separately;
aggregate intervals over all decisions are given only as a lower bound on uncertainty.

### Confidence-threshold sensitivity (§6.4, answers R2-6)

Recomputed offline from the 140 recorded decisions, so no further runs are needed. Observed
confidence takes eight distinct values between 0.78 and 0.95.

| tau_c | TP | FN | FP | TN | TCR | FPR | sent to review |
|---|---|---|---|---|---|---|---|
| 0.70 | 88 | 2 | 0 | 50 | 97.78% | 0% | 0 |
| 0.85 (deployed) | 88 | 2 | 0 | 50 | 97.78% | 0% | 0 |
| 0.88 | 88 | 2 | 0 | 50 | 97.78% | 0% | 0 |
| 0.90 | 83 | 7 | 0 | 50 | 92.22% | 0% | 5 |
| 0.95 | 2 | 88 | 0 | 50 | 2.22% | 0% | 86 |

The threshold is flat between 0.70 and 0.88 and then trades containment for human review:
raising it to 0.90 moves five decisions to the queue and costs 5.6 points of TCR, and at
0.95 it suppresses almost all enforcement. The false positive rate is 0% throughout, so on
this case set the threshold buys nothing in precision — the deterministic policy-conflict
and protected-asset checks, not the confidence gate, are what prevent over-blocking. This
also shows the model's confidence is not calibrated as a probability: it concentrates on a
few coarse values, so the gate functions as a floor rather than as a discriminator.

## 5. The three findings to lead with

1. **Static microsegmentation leaves the containment gap this paper addresses.** It halves
   the attack surface but answers none of the 42 containment cases.
2. **Scope selection, not detection, is where runtime response costs or saves business
   traffic.** Host isolation contains the most and cuts 6.3x more legitimate flows
   than flow-scope containment. Over 375 decisions the correctness difference is
   significant (p = 1.9e-06) and runs *against* host isolation: it over-blocks the
   protected-source cases.
3. **Runtime containment adds exposure reduction only on permitted paths.** On denied
   cells the static matrix has already removed the edge, so the runtime rule is redundant
   for that flow; every service-level reduction measured in the sweep falls on ALLOW cells.
   This locates the contribution of a runtime layer precisely.

## 6. What the sweep does not show, and what covers it

On single-alert decisions BIZM is statistically indistinguishable from the deterministic
graph rule: both choose flow scope, because no escalation signal is present. On the 140
labelled decisions the deterministic context rule is in fact two cases ahead (TP 90, FN 0
against BIZM's TP 88, FN 2), although one of BIZM's two misses is a transient HTTP 500 from
the enforcement path rather than a decision error, and the rule is scored offline and never
pushes a rule, so it cannot encounter that failure mode at all. The sweep
therefore establishes scale, an architecture-defined space, the exposure metrics and the
cost of the two extreme policies — but not a contribution from the language model.

That contribution is evaluated separately on multi-alert sequences, where the scope
decision depends on context the alert does not carry (a prior pivot into the source, fan-out
to several targets, several ports probed on one target, and whether a crown-jewel path
remains open under the narrower scope). The held-out set for that experiment (H1–H6) uses
hosts, zones and signatures disjoint from the set used while developing the prompt, and was
frozen before the run. On it BIZM and the graph rule are both correct on all 30 decisions,
while the two naive policies reach 0.333 and 0.500; the results are in Section 4.

The paper states plainly that a rule which encodes the same scope criteria reaches the same
decisions on anticipated cases. The claim made for the language model is narrower and
defensible: it consumes the operational knowledge base as prose and selects scope without
the decision table being enumerated in code, inside a safety contract that bounds it either
way.

## 7. Corrections to the submitted version that the revision must state

1. **I3 was implemented more narrowly than claimed, and has been corrected.** The protected
   set checked in code omitted the management and monitoring hosts, the leaf management
   addresses and the IDS; the authored invariant list contains them. The two are now
   merged, with a regression test. A run with a second model had in fact enforced a rule
   against a monitoring host, so the submitted S8 result ("never-block respected") held
   because the model chose correctly, not because the guardrail rejected the action.
2. **I2 accepted any CIDR containing the alert source.** A rule naming 10.0.0.0/8 passed
   target fidelity. It is now exact: the rule must name the source host.
3. **I3 also forbade restricting access *to* a protected asset**, which is a different
   property from isolating it. A source-scoped rule `-s S/32 -d D` drops only what S
   initiates towards D and leaves everything D initiates untouched, so it cannot isolate D.
   The original check rejected such rules, which made the system unable to contain
   unauthorised access to the management plane — the condition SID 9000011 exists to
   report. This is the mechanism behind the submitted version's largest false-negative
   cluster, which §6.1 attributed to deliberate conservatism.
4. **Rules never expired.** Rules carried a TTL that neither the framework nor the bridge
   enforced. The agent now owns rule lifetime and revokes on expiry.
5. **The circuit breaker opens on failed enforcement attempts**, not on rejected decisions
   as §5.2 states.
6. **Reported numbers come from one system version.** The submitted numbers were produced
   with a model the provider has since withdrawn; all numbers in the revision come from a
   single tagged build on the rebuilt testbed.
