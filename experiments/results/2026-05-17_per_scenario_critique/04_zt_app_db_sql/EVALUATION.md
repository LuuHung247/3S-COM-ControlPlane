# Scenario 04 — ZT APP→DB SQL Destructive Content

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/zt_05_app_db_sql.py` |
| Trigger | `compromise-app-sql.sh` → APP touch `/tmp/compromised-sql` |
| Attack pattern | APP fires `DROP TABLE users` + `TRUNCATE orders` to DB:5432 |
| Expected SID | 9000050 (destructive SQL pcre) |
| Expected action | DROP src=APP |
| ZT context | APP→DB:5432 ALLOWED, nhưng **content match** detects destructive intent |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| SIDs fired | 9000050 (content) + 9000043 + 9000044 (rate from concurrent attacker SYN bursts) |
| Confidence | **0.92** (high for primary) |
| Action | DROP enforced, TTL 3600s |
| MITRE | TA0040 Impact / T1485 Data Destruction |

## Decisions (3 SIDs fired)

| SID | Action | Conf | Primary hypothesis |
|---|---|---|---|
| **9000050** | DROP 0.92 | "Destructive SQL Attack from compromised application tier" |
| 9000043 | DROP 0.88 | "Application Layer DoS / Resource Exhaustion" |
| 9000044 | DROP 0.88 | (Stage 2 empty) |

## 🧠 Agent reasoning (SID 9000050 — content-based detection)

### Primary hypothesis
**Destructive SQL Attack from compromised application tier** — conf 0.92

### Reasoning chain (7 steps)
1. SID 9000050 P1 severity: **content-based signature** (not rate-based) — actual SQL payload contained destructive DDL statements
2. Baseline check: APP→DB is legitimate path (SELECT/INSERT/UPDATE every 30s). **But threat playbook explicit: "destructive SQL has zero legitimate runtime use case in production"**
3. Source zone: APP (10.2.100.10) ≠ MGT zone. Per FP scenarios: "legitimate schema migrations should be from MGT or change-window source". **APP tier has no business executing DDL**
4. Threat pattern match: `destructive_sql_content` pattern (P1), confidence anchor 0.95. Severity scoring: destructive_keyword_match (+4) + critical DB port (+1) = 5 pts
5. Blast radius: full-source block would break APP→DB OLTP causing cascade outage. **Targeted block (src+dst+port) preserves other legitimate flows**
6. Confidence calibration: 0.92 reflects unambiguous content match + source zone mismatch. Slight reduction from 0.95 anchor due to first-time observation
7. Hard override check: src_zone ≠ MGT (NEVER_BLOCK miss), dst not in NEVER_BLOCK, conf 0.92 > 0.85 threshold → all safety gates passed

---

## 📊 Evaluation

### ✅ Đặc biệt tốt

1. **Content-based detection awareness (step 1)**
   - Agent phân biệt rõ "content match" vs "rate match"
   - Hiểu Suricata `pcre` rule khác `threshold` rule
   - Đây là **DPI understanding** — agent biết payload semantic

2. **Business rule citation (step 2)**
   - "destructive SQL has zero legitimate runtime use case in production"
   - Cite threat playbook explicit rule
   - Không phải general LLM hallucination — cite KG source

3. **Source-zone vs operation-type semantic (step 3)**
   - "APP tier has no business executing DDL statements"
   - Schema migration → MGT only
   - DML (SELECT/INSERT) → APP OK; DDL (DROP/TRUNCATE) → APP NEVER
   - **Đây là business logic chính xác** — không phải zone-level rule

4. **Severity scoring explicit (step 4)**
   - "destructive_keyword_match (+4) + dst_port_in_critical_db_set (+1) = 5 pts"
   - Agent reference rubric trong severity-scoring.md
   - Quantitative reasoning, không hand-waving

5. **Safety gate validation (step 7)**
   - Explicit check: NEVER_BLOCK list, confidence threshold
   - Agent **không bypass** safety even khi confidence cao
   - Architecture L1-L7 gate functioning đúng

### ⚠️ Điểm note

1. **Cùng scenario fire 3 SIDs (9000050 + 9000043 + 9000044)**
   - SQL destructive + accompanying SYN bursts từ attacker-app.sh burst mode (lingering từ test trước? hoặc cron tick)
   - Agent decide DROP cho cả 3 — acceptable (defense in depth)

### 🎯 Architectural validity

```
Per ZT theory:
  ALLOW-path content inspection cần DPI (deep packet inspection)
  Suricata rule pcre = layer DPI in pipeline (signature-based)
  Agent reason: "content matched = high confidence threat" + cite rationale
  
Per agent's reasoning:
  Step 1: explicit phân biệt content vs rate
  Step 3: business operation semantic (DML vs DDL)
  Step 4: severity scoring quantitative
  
→ Agent demonstrates DPI awareness + business policy reasoning.
  Cần thiết cho complete ZT stack (network rule + content rule + business policy).
```

### 📐 So sánh business semantic

| Expectation | Agent response | Match? |
|---|---|---|
| Detect destructive SQL keyword | ✓ pcre match → P1 alert → DROP | ✓ |
| Distinguish legit migration vs attack | ✓ Cite "must originate from MGT" rule | ✓ |
| High confidence cho clear content match | ✓ 0.92 (vs ~0.88 for rate-based) | ✓ |
| Targeted block preserve legit OLTP | ✓ src+dst+port, không cắt other queries | ✓ |
| Reference severity scoring rubric | ✓ "(+4) + (+1) = 5 pts" cite | ✓ |
| Safety gate validation | ✓ NEVER_BLOCK + threshold check | ✓ |

**→ Architecturally rigorous reasoning with explicit business policy citation.**

## Verdict

**Agent behavior EXCELLENT** — đặc biệt step 1-3 thể hiện hiểu biết về:
- DPI vs flow-based detection
- Business operation semantics (DML allowed from APP, DDL only from MGT)
- Confidence calibration based on detection type (content > rate)

Reasoning step 7 (safety gate explicit check) là minh chứng tốt cho **defense-in-depth at agent level** — agent biết về L1-L7 safety, không tự bypass.

Highlight cho luận văn: scenario này shows agent có thể reason về **multi-layer detection** (Suricata DPI + KG threat-pattern + business policy) một cách coherent.
