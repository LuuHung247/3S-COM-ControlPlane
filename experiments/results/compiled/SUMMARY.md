# BIZM-Compile — results (2026-10-27)

Model gpt-oss-120b (reasoning_effort=medium). Deployed KB = knowledge_v2, snapshot digest
`c4f2323b3f9ec8dc` (zones, policy-matrix, sids, invariants, assets, severity-scoring, baselines).
Input domain: 136,080 points (30 signature values × 4 severities × 9×9 zones × protected flag ×
7 history buckets); 19,824 realizable. Verification of one program ≈ 5 s, ensemble of 5 ≈ 25 s.

Ground truth (compiled_policy/evaluate.py): mechanical from the KB — a catalogued signature's
documented **Response** governs (severity-scoring.md applies only to SID-less events).
Points the KB does not settle are "ambiguous" and ungraded (correlation-conditioned SID with no
prior alert; log_only-documented P1/P2 SID on a DENY pair).

## E1 — compile the deployed KB (15,792 known points; 3,160 graded contain/no-contain sets)

| System | acc. on decided | coverage | FN | FP | unknown-SID auto-DROP |
|---|---|---|---|---|---|
| Baseline-C as deployed (zone protection) | 0.9454 | 1.000 | 544 | 273 | 518 |
| Baseline-C strongest (host protection) | 0.9607 | 1.000 | 0 | 588 | 532 |
| Compiled, single, t=0 (no review) | 1.0000 | 0.975 | 0 | 0 | 0 |
| Compiled, single, t=0 (self-review) | 1.0000 | 0.975 | 0 | 0 | 0 |
| Compiled, ensemble K=5, t=0.7 | **1.0000** | **1.000** | 0 | 0 | 0 |
| ensemble members (individually) | 0.9355–1.0 | 0.690–1.000 | 0–966 | 0 | 0 |

All programs verified (0 violating points). t=0 compiles are byte-identical across 5 runs.
Baseline-C errors come from its hand-written override list (9000051/52/61 are documented
`log_only`) and zone-level protection. Compile cost: single 61–96k tokens, 22–36 s;
ensemble 341k tokens, 117 s (≈ 16 runtime decisions at ~21k tokens each).
Files: v2r_single.json, v2r_noreview.json, v2r_ens5.json, e1_eval_v2r.json.

## E2 — drift (compiled_policy/make_variants.py; recompiled, Baseline-C unchanged)

| Variant | C stale (deployed code) | C strongest (reads KB) | Compiled single | Compiled ensemble |
|---|---|---|---|---|
| v1 six new signatures | 0.9373 (FN 922) | 0.9498 (FN 364, FP 616) | 1.0000 / cov 0.931 | 1.0000 / cov 0.950 |
| v2 new zone PAYMENTS | 0.9303 (FN 1009) | 0.9626 (FP 693) | 1.0000 / cov 1.000 | 1.0000 / cov 0.975 |
| v3 three responses retuned (prose only) | 0.9446 | 0.9609 (FP 588) | 1.0000 / cov 1.000 | 1.0000 / cov 1.000 |
| v4 all of the above | 0.9203 (FN 1624) | 0.9524 (FN 441, FP 721) | 1.0000 / cov 0.905 | 0.9997 / cov 0.923 (FN 7) |

The 7 v4 FN are SID 9000012 on PAYMENTS→DB-OLTP: the variant made that pair ALLOW without
updating 9000012's detection logic, so the KB itself is inconsistent there.
Files: v{1..4}_*_{single,ens5}.json, e2_v*.json, compiled_policy/kb_variants/.

## Matrix sweep (75 cases, offline, compiled_policy/sweep_offline.py)
compiled ensemble: 75/75 decided, accuracy 1.000, legit flows cut 7 (= fixed-flow, graph-rule);
SOAR-host 0.947, cut 44; BIZM-runtime (recorded, 375 decisions) 1.000, cut 35 (7 per repeat).

## Paper scenarios (offline, compiled_policy/scenario_eval.py; abstentions → recorded runtime)
S1–S5 6/6 decided correctly · S6 9/9 combined (D1, the HTTP-500 case, now decided by the program;
FP1–3 send P3 signatures at severity 2 → inconsistent with the catalogue → abstain → runtime 1.0)
· S7 0/9 violations · S8 4/4 never-block · S9 3 known decided correctly, 6 unknown → runtime (8.8/9)
· S10 stage 3 DROP in sequence and cold.

## E5 harness check (dry-run, 1 repeat, compiled_policy/e5_injected.py --dry)
33 rows, 0 infra errors, 24/24 graded correct, 0 S7 violations, 0 persist errors, 0 rules left.
Compiled path 15 decisions, agent latency 2–17 ms (138 ms with history); runtime path 18,
5–40 s (provider slow that day). Live E5: see below.

## Infrastructure fixes in this build (image intelligence-layer:paper-compile-20261027)
- Embedding model baked into the image (FASTEMBED_CACHE_PATH, HF_HUB_OFFLINE=1); it was downloaded
  from HuggingFace on the first alert after every container recreate, on the decision path.
  embed_text now times out at 3 s; model warmed at startup.
- POST /alerts never returns 500: agent.process, gate, Postgres/Redis persistence and embedding
  scheduling are guarded; a storage fault is returned as persist_error with the decision.
- ids-agent push retried (3 attempts) on transport errors/5xx; idempotent by rule_id.
- Harness: common/reliable.py — preflight, retries on infra faults, docker-log snapshot to
  results/_infra_logs/, infra faults recorded as infra_error, never as a miss.

## E5 — live, enforcement on (results/e5_20261027_0656, image ab85207424a9)
Real traffic S1–S5 × 10: 49/50 pass (S3 run 8: Suricata raised no alert, alert_count_p1=0 — a
detection miss, no decision involved). Decision + push to SONiC: median 0.69 s, p90 1.98 s,
max 3.93 s (n=39), vs runtime agent on 26/10: median 3.12 s, p90 4.34 s (n=40).
Injected S6–S10 × 3 (99 rows): compiled path 45 rows, 30/30 graded correct, 45/45 DROP rules
confirmed on the fabric, median 0.66 s incl. push; runtime path 25 rows, 23/25 correct (both misses
M3-unknown: held at confidence 0.66, and log_only), median 23.7 s, max 54.6 s; gate 27 rows.
S7 0/27 violations · S8 12/12 · S10 6/6 · persist errors 0 · HTTP 500 0 · rules left 0.
Provider outage 08:29–08:38 (Cerebras ConnectTimeout): 2 runtime cases recorded infra_error after
4 attempts (not scored); the compiled path kept deciding throughout.

### E5 final (results/e5_final, merged by compiled_policy/merge_e5.py)
Re-runs replace the three rows the main run lost to technical causes, in place, marked `rerun`:
S3 run 8 (IDS raised no alert) and S9 M1/M2-unknown repeat 2 (provider ConnectTimeout).
Live S1–S5: **50/50**, decision + push median 0.59 s, p90 1.98 s, max 3.93 s (n=40).
Injected (99 rows, 0 infra_error): compiled 45 rows, 30/30 correct, 45/45 DROP on fabric, median
0.66 s; runtime 27 rows, 25/27 (both M3-unknown), median 23.7 s; gate 27 rows, 15/15.
S6 27/27 · S7 0/27 violations · S8 12/12 · S9 25/27 · S10 6/6.
