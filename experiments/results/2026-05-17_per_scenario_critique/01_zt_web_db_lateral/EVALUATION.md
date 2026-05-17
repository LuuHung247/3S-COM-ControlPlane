# Scenario 01 — ZT WEB→DB Lateral Movement

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/zt_01_web_db_lateral.py` |
| Trigger | `compromise-web.sh` (MGT SSH → WEB touch `/tmp/compromised`) |
| Attack pattern | WEB host (10.1.100.10) → DB:5432 direct PostgreSQL connect + WEB→MGT:22 SSH |
| Expected SID | 9000001 (WEB direct to DB) |
| Expected action | DROP src=WEB |
| ZT policy violation | YES — WEB zone không được phép direct access DB (chỉ APP qua zt-app-db-allow) |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| MTTD | 36.1s (attack → first alert) |
| M1 Alert→Decision | 6.91s |
| M2 Decision→LEAF | 6.77s |
| Confidence | 0.95 |
| Checks | 5/5 |

## Agent's decisions (3 SIDs fired từ 1 scenario)

Compromise-web.sh fires `attacker-web.sh` cron, which performs 2 network actions:
- `nc 10.1.200.10 5432` → matches SID 9000001 + SID 9000051
- `nc 10.2.50.10 22` → matches SID 9000004

Agent xử lý cả 3 SIDs độc lập:

| Time | SID | Action | Conf | Rule | TTL | Notes |
|---|---|---|---|---|---|---|
| 14:09:07 | 9000001 | DROP enforced | 0.95 | agent-5c5875aa62 | 3600s | Full V3 reasoning trace |
| 14:09:21 | 9000051 | DROP enforced | 0.95 | agent-5c5875aa62 (same) | 3600s | Stage 2 failed → reasoning empty |
| 14:09:35 | 9000004 | DROP enforced | 0.88 | agent-538ab9831a | 1800s | Full V3 trace, corroboration noted |

## 🧠 Agent reasoning trace (SID 9000001 — primary decision)

### Primary hypothesis
> **Lateral movement (p=0.95)** — WEB host attempting direct DB connection, bypassing application-tier mediation. Evidence: SID 9000001 trigger (WEB→DB microsegmentation bypass), cross-zone violation from untrusted WEB to crown-jewel DB, dst_port=5432 (PostgreSQL), not in any production baseline. Counter: None strong - this is a clear policy violation with no legitimate use case.

### Alternative hypotheses
- **Misconfigured monitoring tool (p=0.04)** — would explain pattern but counter: monitoring must originate from MGT zone per system model
- **DB migration script (p=0.01)** — counter: no change window record, migrations should originate from MGT bastion

### Reasoning chain (8 steps)
1. SID 9000001 triggered with P1 severity — explicitly designed to detect WEB→DB direct, violates defense-in-depth
2. Cross-zone violation: src 10.1.100.10 WEB zone (untrusted), dst 10.1.200.10 DB zone (crown-jewel)
3. Baseline check: flow NOT in production patterns. Legitimate DB access must come from APP (10.2.100.10) or MGT (10.2.50.10)
4. dst_port 5432 = PostgreSQL critical service. Direct access bypasses application-layer controls
5. Source host web-01 zero prior alerts in 30-day window, trust 0.5 — first observation, consistent with initial compromise
6. MITRE TA0008 Lateral Movement / T1021 Remote Services
7. **Targeted block (src+dst+port) thay vì full-source** để preserve WEB→APP:8080 user traffic. Blast radius minimized.
8. Confidence 0.95: unambiguous cross-zone violation, no legitimate baseline, matching P1 threat pattern. No corroboration needed.

### Alternative actions (escalation paths)
- IF additional WEB→DB to different DB hosts in 5min → escalate full-source block (multi-target campaign indicator)
- IF legitimate change ticket within TTL → revoke + escalate to human operator for ACCEPT rule (agent cannot push ACCEPT)
- IF SID 9000033 (SSH from WEB) within 10min → extend block to port 22 (multi-protocol lateral)

### Follow-up actions (proactive monitoring)
- Monitor SID 9000002 (DB outbound) within 15min — possible C2 channel established
- Monitor SID 9000030 (WEB→APP burst) within 10min — web-tier may be pivoting
- Query KG for kill-chain progression containing SID 9000001
- Watch SID 9000048/9/50 (SQL injection) on APP→DB — possible webshell exploitation
- Audit web-01 host: unexpected processes, modified binaries, external IPs

### Notification
> *"Blocked 10.1.100.10→10.1.200.10:5432 for 3600s. SID 9000001 fired - WEB direct DB access violates microsegmentation. No baseline match, FP likelihood low. Consistent with lateral movement bypassing application tier."*

---

## 📊 Evaluation — Tư duy agent có chuẩn không?

### ✅ Điểm tốt

1. **Hypothesis ranking đúng business priority**
   - p=0.95 cho lateral movement (high-confidence threat)
   - p=0.04 cho misconfigured tool (low-likelihood false positive)
   - p=0.01 cho legitimate migration (rare exception)
   - Probabilities sum to 1.0, well-calibrated

2. **Baseline awareness chính xác**
   - Agent biết "DB phải từ APP (10.2.100.10) hoặc MGT (10.2.50.10)" — đọc đúng zone matrix từ KG
   - Khi flow KHÔNG match baseline → reasoning step 3 explicit ghi nhận

3. **Targeted DROP thay vì full-source — đúng ZT principle**
   - Step 7: "Targeted block preserve WEB→APP:8080 user traffic" — agent **không over-react**
   - Đây là kiến trúc đúng (minimize blast radius), không như naive "block everything from compromised host"

4. **Cross-SID correlation**
   - Follow-up action #1-2: agent biết WEB→DB có thể là stage 1 của multi-stage attack
   - Suggest monitor SID 9000002 (DB outbound) — anticipate next stage of kill chain
   - Đây là **threat hunting mindset**, không chỉ react

5. **Confidence calibration đúng**
   - 0.95 cho clear policy violation (no legit use case) — phù hợp severity_scoring.md rubric
   - Không over-confident (1.0) cũng không under-confident (0.7)

6. **Escalation paths có logic**
   - "If multi-target campaign → escalate full-source" → đúng (multiple targets = more serious)
   - "If change ticket → revoke + escalate human" → đúng (human override path khi có context bên ngoài)

### ⚠️ Điểm cần cải thiện (minor)

1. **Stage 2 reasoning fail cho SID 9000051** (14:09:21)
   - Same scenario, same src/dst, nhưng Stage 2 timeout → reasoning="[]"
   - Agent vẫn enforce đúng (decision committed) nhưng audit trail thiếu cho 1 decision
   - **Đề xuất**: tăng timeout Stage 2 hoặc cache reasoning theo (src,dst,port) tuple



2. **Trust score 0.5 là "default"**
   - "web-01 trust score 0.5" — không phải đo lường thực sự, chỉ default value
   - Agent KG chưa có baseline trust score per host (memory feature chưa fully populated)
   - Acceptable cho cold start

### 🎯 Architectural validity

Agent's reasoning **đúng với ZT microsegmentation principle:**

```
Per ZT theory:
  WEB tier = exposed (public-facing) → untrusted zone
  DB tier = data (crown-jewel) → critical zone
  → Direct WEB→DB connection NEVER permitted (must go via APP)
  
Per agent's reasoning:
  Step 2: "cross-zone violation, WEB untrusted → DB crown-jewel"
  Step 3: "Legitimate DB access must come from APP (10.2.100.10) or MGT"
  Step 7: "Targeted block preserve WEB→APP:8080 user traffic"
  
→ Agent's mental model matches ZT spec exactly.
```

### 📐 So sánh với business semantic

| Business expectation | Agent's response | Match? |
|---|---|---|
| Detect cross-zone bypass | ✓ SID 9000001 detected, action=DROP | ✓ |
| Block immediately (P1 severity) | ✓ DROP enforced 3600s TTL | ✓ |
| Preserve legitimate traffic | ✓ Targeted (src+dst+port), không cắt full src | ✓ |
| Anticipate multi-stage attack | ✓ Follow-ups monitor 9000002/9000030/9000048-50 | ✓ |
| Provide escalation path | ✓ 3 alternative actions với trigger conditions | ✓ |
| Human override path | ✓ "If change ticket → escalate human" | ✓ |

**→ Agent's reasoning fully aligned với ZT business semantic + lateral movement detection best practice.**

## Verdict

**Agent behavior PERFECT cho scenario này.** Reasoning rich (8 steps + 3 hypotheses + 3 alts + 5 follow-ups), architectural understanding đúng, business semantic match. Có thể paste reasoning vào luận văn làm minh chứng trực tiếp.

**1 minor issue**: Stage 2 timeout cho 1 trong 3 decisions (SID 9000051) — agent vẫn enforce đúng nhưng audit trail thiếu. Acceptable nếu cron tick lại sẽ regen trace.
