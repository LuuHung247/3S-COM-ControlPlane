# Scenario 03 — ZT APP→DB Burst (compromised app-tier flooding DB)

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/zt_04_app_db_burst.py` |
| Trigger | `compromise-app-burst.sh` → APP touch `/tmp/compromised-burst` |
| Attack pattern | APP (10.2.100.10) → DB (10.1.200.10:5432) — 100 parallel SYN trong 30s |
| Expected SID | 9000043 (SYN flood) |
| Expected action | DROP src=APP |
| ZT context | APP→DB:5432 là **legitimate path** (zt-app-db-allow) — rate anomaly chỉ ra compromise |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| Actual SID fired | 9000043 + 9000044 (both fire) |
| MTTD | ~12s |
| Confidence | 0.88 (decision) / 0.85 (Stage 1 hypothesis) |
| Action | DROP enforced, TTL 1800s |
| Checks | 5/5 |

## Decisions agent generated

| SID | Action | Conf | Notification |
|---|---|---|---|
| 9000043 | DROP enforced | 0.88 | "Blocked APP→DB:5432 for 1800s. SID 9000043 fired at 200 SYN/10s (1200/min) vs baseline 2/min — 24x threshold indicates DoS." |
| 9000044 | DROP enforced | 0.88 | "SID 9000044 fired at 50 SYN/10s (300/min) — 6x above threshold, DoS contribution or connection-loop bug." |

## 🧠 Agent reasoning (SID 9000043 — primary)

### Hypotheses (3)
- **DoS Attack (p=0.85)** — App-01 flooding DB-01 with SYNs, likely compromise or runaway process. Counter: None, rate is definitive.
- **Connection Pool Storm (p=0.10)** — App logic bug causing rapid reconnection. Counter: rate too high for standard pool storms (usually bounded by config).
- **False Positive (p=0.05)** — Legitimate load spike. Counter: 600x baseline impossible for legitimate OLTP.

### Reasoning chain (6 steps)
1. SID 9000043 trigger: 200 SYN/10s from APP→DB
2. Baseline "application-to-database-oltp" expected ~2/min (120/hr); observed ~1200/min
3. **600x deviation, far exceeds >50/min anomaly threshold**
4. Impact: "Unchecked flood will exhaust DB connection pool (DoS). Blocking causes app outage, but preserves DB integrity."
5. Source reputation: trust score 0.2, prior SID 9000044 (DDoS component) — **memory tracking working**
6. Targeted block (src+dst+port) — surgical, minimize blast radius

### Alternative actions
- IF DB CPU/ConnPool remains high after block → investigate host compromise via MGT
- IF traffic resumes normal cadence after TTL → consider app-01 recovered/restarted

### Follow-ups
- Monitor MGT→APP SSH for forensic investigation
- Check lateral movement attempts (APP→MGT) trong 15 mins
- Verify DB-01 availability post-block

---

## 📊 Evaluation

### ✅ Đặc biệt tốt

1. **Reasoning về DB integrity tradeoff (step 4)**
   - "Blocking causes app outage, but preserves DB integrity"
   - Agent giải thích rõ đánh đổi — không default block
   - Đây là **production-grade thinking**: protect critical asset (DB) trên app instance

2. **Hypothesis "Connection Pool Storm" (p=0.10)**
   - Khôn ngoan: bug app cũng có thể tạo SYN flood-like pattern
   - Counter rất kỹ thuật: "rate too high for standard pool storms; usually bounded by config"
   - Hiểu được cả failure modes legit lẫn malicious

3. **Memory feature working consistently**
   - "Source has trust score 0.2, prior SID 9000044" — agent remember
   - Pattern này lặp lại từ scenario 02 → memory đang accumulate đúng

4. **Recovery path**
   - Alt actions có self-healing assumption: "If traffic resumes normal cadence after TTL → consider app-01 recovered"
   - Không "block forever" attitude

### ⚠️ Điểm cần để ý

1. **Confidence 0.85 cho primary hypothesis (vs 0.95 ở scenario 01)**
   - Lý do: APP→DB là ALLOWED path → ambiguity giữa "compromise" vs "high legit load"
   - Agent thận trọng hơn — **đúng calibration**
   - Vẫn enforce vì sự cố tệ hơn nếu không block (DB exhaust)

2. **2 decisions cho cùng pair (9000043 + 9000044)**
   - Cả 2 đều DROP enforced — hơi redundant
   - Nhưng đúng pipeline (mỗi SID → 1 decision độc lập)

### 🎯 Architectural validity

```
Per ZT theory:
  APP→DB là legitimate path (zt-app-db-allow) — packet level không vi phạm
  Compromised APP có thể abuse path này để extract data hoặc DoS DB
  → Cần BEHAVIORAL detection (rate, volume, pattern), không phải static rule
  
Per agent's reasoning:
  Step 2-3: rate comparison + 600x deviation → behavioral anomaly clear
  Step 4: business impact priority (DB integrity > app uptime)
  Step 6: targeted block preserve other APP services
  
→ Đúng paradigm "agent essential cho ALLOW-path detection" của NetVigil paper.
```

### 📐 So sánh business semantic

| Expectation | Agent response | Match? |
|---|---|---|
| Detect APP→DB rate anomaly | ✓ 600x baseline flagged | ✓ |
| Distinguish bug vs compromise | ✓ Connection pool hypothesis evaluated | ✓ |
| Protect DB tier ưu tiên | ✓ "Preserve DB integrity > app uptime" | ✓ |
| Use memory (prior alerts) | ✓ Reference prior SID 9000044 | ✓ |
| Self-healing path | ✓ TTL + auto-revoke trigger | ✓ |

**→ Architecturally correct + business-aware reasoning.**

## Verdict

**Agent behavior CORRECT.** Lý luận tradeoff DB integrity tốt, hypothesis "connection pool bug" thể hiện hiểu biết engineering. Memory accumulation working. Cùng với scenario 02 → 2 minh chứng mạnh cho "agent essential" claim trên ALLOW-path traffic.
