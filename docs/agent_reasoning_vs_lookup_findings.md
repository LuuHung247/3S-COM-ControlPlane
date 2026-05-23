# Findings: Does the agent *reason*, or *look up a table*?

> Verification of the reviewer's concern, done by reading the **actual running
> code/prompts** (not the design docs / memory). For the thesis-writing agent: this
> determines how Section 4.4 (Test Scenarios) and any "how is this different from
> rule-based?" defense must be phrased. **Do not over-claim "pure reasoning" — the
> code does not support that.** All claims below are backed by file:line evidence.

---

## TL;DR (the honest verdict)

There **is** a hardcoded `signature-ID → attack-type → recommended-action` mapping,
and it **is injected into the decision prompt** for known SIDs. So the strong form
of the reviewer's worry is **confirmed**: for a known signature, the agent is shown
both the attack-type label *and* a recommended action before it decides.

It is **not**, however, a pure table lookup. The system is a **hybrid**:
signature-informed for known clear violations, reasoning-driven for ambiguous /
ALLOW-path / unknown-SID cases, plus safety invariants a rule engine lacks. The
defensible claim is the hybrid one, **not** "the agent reasons from baseline
deviation without being given the answer."

---

## Q1 — Is there a SID → type → action mapping in the decision prompt? **YES.**

- The mapping is `SID_KNOWLEDGE` in `src/core/knowledge.py` (docstring:
  *"SID → MITRE ATT&CK mapping. Hardcoded from DATAPLANE.md — no tool call needed."*).
  Each entry has `severity`, `desc` (attack-type label), `tactic`, `technique`,
  **`action`**, `ttl`, `flow`. Example:
  ```
  9000001: {severity:1, desc:"WEB direct access to DB (lateral movement)",
            tactic:"TA0008 Lateral Movement", action:"block", ttl:3600, flow:"WEB → DB"}
  ```
- The recommended `action` per known SID:
  `9000001/2 → "block"`; `9000030/31/32 → "block_targeted"`;
  `9000033 → "block_targeted_escalate"`; `9000035 → "block_targeted_flag_host"`;
  `9000010/11/20 → "log_only"`; **`9000034 → "agent_time_eval"`** (the only one that
  explicitly defers to the agent).
- It reaches the **decision** prompt: `build_policy_decision_prompt`
  (`src/agent/prompts.py:307-342`) sets `sid_context = str(sid_info)` — the *entire*
  dict, including `action` and `desc` — and the template
  (`_POLICY_DECISION_TEMPLATE`, `prompts.py:129-137`) renders it under
  **"Trusted alert metadata → SID context"**.
- The template also contains a HARD RULE (`prompts.py:157`):
  *"Action MUST be DROP for P1/P2 threats. log_only for P3/P4 or baseline matches."*
  Combined with the handed `severity`, this strongly determines the action for clear
  cases.

**So for a known DENY-path violation (e.g. SID 9000001), the agent is essentially
confirming a handed recommendation.** The "how is this different from rule-based?"
critique lands for these specific cases.

### Important mitigating facts (also true, also from the code)
1. The **full** lookup table (`render_sid_knowledge()`, all SIDs with `action=`) is
   **defined but never called** anywhere in `src/` — only the *single matching SID's*
   entry is injected per alert. It is not "here is the whole rulebook."
2. **Unknown SIDs** → `sid_context = "Unknown SID"` → the agent gets **no mapping**
   and must reason purely from context (signature text + topology + policy + baseline).
3. **ALLOW-path behavioral anomalies** (SID 9000030-35: bursts, volume anomalies,
   off-hours probes) carry a recommended action, but the *real* decision —
   `log_only` (within baseline) vs `DROP` (exceeds threshold) — is made by judging
   the observed flow against baselines, per the confidence-calibration block
   (`prompts.py:160-169`) and the per-alert baseline context. SID `9000034` is
   explicit: `action:"agent_time_eval"`, decided by business-hours context
   (`_time_context_for_alert`, `prompts.py:317-326`).
4. The agent **always** computes the enforcement *target / scope / CIDR / TTL /
   priority itself*, bound by the **off-target invariant** ("intent.src_ip MUST equal
   the alert source"). S14 proved this layer overrides even adversarial inputs.
5. **Kill-chain / playbook knowledge is deliberately kept OUT of the prompt** and is
   reachable only via the on-demand `query_kg` tool. The code comment
   (`src/core/threat_playbook.py:120`) states pre-loading it *"would hand the agent
   the test-scenario answer ... and turn reasoning into pattern-matching."* So the
   deeper campaign-stage reasoning is protected; only the flat SID→action hint is not.

## Q2 — Does similar-incident retrieval leak the attack-type label? **PARTIALLY.**

- `find_similar_past_incidents` (`src/agent/tools.py:426`) recalls past decisions by
  exact-SID + semantic vector + MITRE-technique match.
- The recalled/embedded text (`build_decision_text`, `src/storage/embedder.py:78`)
  contains `primary_hypothesis`, `mitre_technique`, and `reasoning_first_step`. So
  recalled incidents carry the *prior* attack hypothesis + MITRE label + prior
  reasoning ("last time this shape was lateral movement").
- This is **experience/memory**, not a static rule — arguably legitimate (a human
  analyst also recalls past cases). On a fresh/truncated `decisions` table it returns
  nothing (eval runs truncate it), so it does not affect cold-start decisions.

## Q3 — What is in the Suricata signature (`msg`) field, and is it in the prompt? **YES, as untrusted data.**

- `signature` and `category` ARE injected into the decision prompt, but wrapped in
  `<untrusted_alert_data>` tags and passed through `sanitize_alert_fields()`; the
  prompt instructs the model to treat them as DATA, not instructions
  (`prompts.py:139-143`, S14 confirmed this defense works).
- A Suricata `msg` typically already names the attack ("WEB to DB direct access"), so
  the agent does see Suricata's own label — but as *untrusted* input, separate from
  the *trusted* SID context. Real-world alerts carry `msg` too, so this is realistic,
  not a flaw — but it means "the agent infers the attack type from scratch" is **not**
  accurate; it is told what Suricata thinks (twice: once trusted via SID_KNOWLEDGE,
  once untrusted via msg).

---

## What this means for the thesis (and the decision the author must make)

The system is a **signature-informed reasoning agent**, not a pure reasoner and not
a pure rule engine. Pick one of:

**Option A — Reframe the claim honestly (recommended, no code change).**
State plainly that for *known* signatures the agent receives a type + recommended
action as a prior, and locate the agent's value where the code actually delivers it:
1. **Context-dependent action selection** for ambiguous / ALLOW-path anomalies
   (log_only vs DROP judged against baselines — the NetVigil S6-S13 hard classes,
   off-hours 9000034, burst/volume 9000030-32).
2. **Target / scope / TTL computation** and the **off-target + immutable-allowlist
   invariants** (S14: 0/8 vs 8/8 — value a rule engine cannot provide).
3. **Graceful degradation to pure reasoning** when the SID is unknown.
4. **On-demand kill-chain reasoning** (not pre-loaded).
Defense against "how is this different from rule-based?": *not* "it never looks up,"
but "it falls back to reasoning when signatures are unknown or behavior is ambiguous,
and it enforces safety invariants and target/scope decisions a static SID→action map
cannot."

**Option B — Make the strong claim true (more work, before deadline).**
Remove `action` (and optionally `desc`) from the injected `sid_context` in
`build_policy_decision_prompt` (keep only neutral facts like severity/MITRE, or
nothing), forcing the agent to derive the action from context. Then **re-run S1-S13**
to confirm pass-rate holds. Only after that can the thesis claim "reasons from
context, not a handed action." Risk: results may shift; costs time.

**Empirical follow-up (S15 — now done).** The unknown-SID ablation that this
section called for has since been run; see
[`docs/S15_experiment_report.md`](./S15_experiment_report.md). Headline (N=3):
on **unknown** signatures (no mapping, generic message) the agent still mitigates
**6/9 (67%)** of attacks vs **0/9** for a signature-keyed SOAR; it splits identical
WEB→DB (DROP) vs APP→DB (allow) metadata by policy; and in one run it *overrode* a
known SID's recommended `block` with `log_only` — three independent signs it is
**not** a pure lookup. But it is **non-deterministic** and **under-reacts to
cross-tier SSH→MGT** even with the hint present (M3-known unstable). So the honest
claim is the hybrid + an explicit limitation, exactly as Option A frames it — *not*
"pure reasoning."

> Bottom line for the writer: **do not claim the agent independently infers the attack
> type or action for known signatures — the prompt hands both.** Claim the hybrid +
> the safety/scoping value (S14) + graceful degradation. If a stronger claim is
> required, code change (Option B) + an unknown-SID scenario are prerequisites.

---

## Evidence index (file:line)

| Claim | Location |
|---|---|
| Hardcoded SID→{desc,action,...} table | `src/core/knowledge.py` (`SID_KNOWLEDGE`, lines 3-112) |
| Full dict injected into decision prompt | `src/agent/prompts.py:320, 338` (`sid_context=str(sid_info)`) |
| "Trusted alert metadata → SID context" line | `src/agent/prompts.py:133-137` |
| HARD RULE "P1/P2 MUST be DROP" | `src/agent/prompts.py:157` |
| Same injection at classify step | `src/agent/prompts.py:243-249` |
| Full table renderer defined but unused | `src/core/knowledge.py:118-126` (no caller in `src/`) |
| Unknown SID → no mapping | `src/agent/prompts.py:338` (`else "Unknown SID"`) |
| Kill-chain kept out of prompt (anti-leak) | `src/core/threat_playbook.py:120` |
| Similar-incident recall carries hypothesis/MITRE | `src/agent/tools.py:426`, `src/storage/embedder.py:78` |
| signature/category as untrusted, sanitized | `src/agent/prompts.py:139-143`, `sanitize_alert_fields` |
