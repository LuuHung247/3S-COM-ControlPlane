# Scenario 13 — Yatesbury #14: Unauthorized DB Access

## Context

| Field | Value |
|---|---|
| Wrapper | `scenarios/yates_08_unauth_db.py` |
| Trigger | `compromise-web.sh` (reuse — WEB host attempts direct DB) |
| Expected SID | 9000051 (DB connection from non-APP zone) |
| Paper | NetVigil Table 3 #14 |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| SIDs fired | 9000001 + 9000051 + 9000004 (WEB→DB + WEB→MGT lateral) |
| Conf | 0.95 |
| Action | DROP enforced TTL 3600s |

## 🧠 Agent reasoning (SID 9000051)

### Hypotheses
- **Lateral Movement (p=0.95)** — Attacker on web-01 attempting direct DB. Counter: None.
- **Configuration Drift (p=0.05)** — Counter: Source has history of violations + low trust score

### Reasoning chain (6 steps)
1. SID 9000051 P1: DB connection from non-APP zone (WEB)
2. Flow NOT in baselines; legit requires WEB→APP→DB path
3. Threat pattern match `cross_zone_violation_web_to_db` conf anchor 0.95
4. **Source reputation**: "trust score 0.4 and prior history of similar violations (SID 9000001, 9000051)" ← memory
5. **Alert sequence correlation**: "9000001 → 9000051 → 9000004 → 9000001 indicates multi-stage attack campaign" ← kill-chain awareness
6. Targeted block (src+dst+port) preserve WEB→APP:8080

---

## 📊 Evaluation

### ✅ Tốt

1. **Memory accumulation strong (step 4)**
   - Trust score giảm từ 0.5 (initial scenario 01) → **0.4** (scenario 13) — agent updating reputation across runs
   - "prior history of similar violations (SID 9000001, 9000051)" — explicit reference
   - **Memory layer working consistently**

2. **Kill-chain explicit (step 5)**
   - "Alert sequence (9000001 → 9000051 → 9000004 → 9000001) indicates multi-stage attack campaign"
   - Agent **chain alerts** không treat isolated
   - Recognize repeat patterns

3. **Same SID 9000001 fire 2 lần** trong sequence — agent note "campaign" rather than "isolated repeat"

### 🎯 Architectural insight

Scenario 13 reuses compromise-web.sh (same as scenario 01). Comparison:
- **Scenario 01 (first run)**: trust 0.5, "first observation"
- **Scenario 13 (after 12 prior runs)**: trust 0.4, "prior history of violations", kill-chain awareness

→ **Memory accumulation visible across run sequence.** Agent becomes more confident + detailed reasoning over time. Đây là bằng chứng mạnh cho **temporal learning** capability.

### 📐 Same scenario type, different reasoning depth

| Aspect | Scenario 01 (first) | Scenario 13 (after 12) |
|---|---|---|
| Trust score | 0.5 default | 0.4 (lowered by prior) |
| Memory references | Generic "first observation" | Explicit "prior SID 9000001, 9000051" |
| Kill-chain | Hypothetical (future) | Actual sequence cited |
| Confidence | 0.95 | 0.95 (same anchor) |

## Verdict

**CORRECT + IMPROVED reasoning vs scenario 01.** Memory accumulation evidence strong (trust score evolution, kill-chain sequence). Highlight cho luận văn: comparing scenario 01 vs 13 (same attack pattern) demonstrates **memory feature value-add through scenario sequence**.
