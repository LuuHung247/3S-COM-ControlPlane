# Scenario 02 — ZT WEB→APP Burst (compromised web-tier flooding app)

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/zt_03_web_app_burst.py` |
| Trigger | `compromise-web-burst.sh` → WEB touch `/tmp/compromised-burst` |
| Attack pattern | WEB (10.1.100.10) → APP (10.2.100.10:8080) — 250 parallel SYN trong 30s |
| Expected SID | 9000041 (TCP probe on key service ports) hoặc 9000043 (SYN flood) |
| Expected action | log_only hoặc DROP |
| ZT context | WEB→APP:8080 là **legitimate path** (zt-web-app-allow), nhưng RATE anomaly chỉ ra compromise |

## Eval result

| Metric | Value | Note |
|---|---|---|
| Outcome | **PASS** ✅ enforced | DROP rule pushed |
| Actual SID fired | **9000043** | (not 9000041 as preset expected — agent picked higher-severity SID first) |
| MTTD | 15.5s | |
| M1 Alert→Decision | 7.53s | |
| M2 Decision→LEAF | 7.20s | |
| Confidence | 0.88 (decision) / 0.92 (post Stage 2) | |
| Action | DROP enforced | TTL 1800s |
| Checks | 5/5 | |

## 🧠 Agent reasoning trace (SID 9000043)

### Primary hypothesis
> **DoS Attack (p=0.95)** — Source is flooding APP tier. Evidence: 200 SYNs/10s vs baseline 2/min (600x deviation). Counter: None, deviation magnitude precludes legitimate traffic.

### Alternative hypothesis
- **Legitimate Load Test (p=0.05)** — Path is valid baseline. **Counter: Runbook requires load tests originate from MGT zone, not WEB.**

### Reasoning chain (5 steps)
1. **Path identification**: WEB→APP:8080 = "critical web-to-application-proxy path"
2. **Rate comparison**: 200 SYNs/10s = 1200/min vs baseline 2/min = **600x deviation**
3. **Impact evaluation**: "Allowing flood risks crashing app-01, affecting all users. Blocking degrades service for users of web-01. **Preventing APP tier collapse is higher priority than preserving service for a single compromised/misbehaving web host.**"
4. **Source legitimacy check**: "Runbook states legitimate load tests originate from MGT. Source is WEB. Source has low trust score (0.2) and prior DDoS-related alert (SID 9000044)."
5. **Enforcement selection**: Targeted DROP (src+dst+port) — preserves other flows from web-01, TTL 1800s for automatic recovery

### Alternative actions
- IF SYN rate drops below 10/min within TTL → revoke rule (auto-restore service)
- IF source initiates scans to other zones (DB) → escalate full-source block

### Follow-ups
- Monitor web-01 for lateral movement (SSH to APP, direct DB)
- Investigate web-01 host logs for compromise indicators (C2, malware)
- Verify APP tier health metrics post-enforcement

### Notification
> *"Blocked 10.1.100.10→10.2.100.10:8080 for 1800s. SID 9000043 fired at 200 SYN/10s (1200/min) vs baseline expected 2/min and anomaly_threshold >10/min — 120x deviation confirms DoS attack on critical web-to-app path."*

---

## 📊 Evaluation — Tư duy agent có chuẩn không?

### ✅ Điểm tốt

1. **Path awareness chính xác**
   - Agent biết WEB→APP:8080 là "critical web-to-application-proxy path" — không phải arbitrary attack
   - Phân biệt "anomaly trên ALLOWED path" vs "violation cross-zone"
   - Đây là **insight quan trọng**: rate-based detection trên legitimate path

2. **Multi-tenant tradeoff reasoning (step 3)**
   - Agent giải thích trade-off rất tốt: "single compromised web host vs ENTIRE APP tier"
   - Quyết định block compromised src để **bảo vệ APP tier serving all users**
   - Đây là **business-aware reasoning**, không chỉ technical rule matching

3. **Cross-runbook check (step 4)**
   - Agent reference runbook explicitly: "load tests should originate from MGT"
   - Loại trừ false-positive (legitimate load test) bằng business policy, không chỉ stats
   - Cite **trust score 0.2 + prior SID 9000044** — agent remembering past behavior

4. **Memory feature working**
   - "Source has low trust score (0.2) and prior DDoS-related alert (SID 9000044)"
   - Agent's memory đã track web-01 có history nghi vấn → reduce hypothesis "legitimate load test" xuống 0.05
   - Memory accumulation đúng spec

5. **Quantitative anchoring**
   - "200 SYNs/10s vs baseline 2/min — 600x deviation" và "120x deviation" trong notification
   - Concrete numbers, không hand-waving
   - Reviewer luận văn dễ verify

6. **Self-healing path (TTL + revocation trigger)**
   - "If SYN rate drops below 10/min within TTL, revoke rule to restore service"
   - Agent có path tự khôi phục — không "set and forget"

### ⚠️ Điểm cần để ý

1. **SID fired = 9000043 (SYN flood) thay vì 9000041 (key port probe) như eval preset expect**
   - Đây không phải bug — chỉ là eval expectation vs actual rule firing order
   - 250 conn/30s vượt cả 2 thresholds (9000041 = 5/60s key ports, 9000043 = 200/10s SYN flood)
   - 9000043 có severity cao hơn → agent xử lý trước
   - **Acceptable** — Suricata fire SID nào tới trước, agent decide SID đó

2. **Hypotheses chỉ 2 (vs 3 ở scenario 01)**
   - Agent đánh giá situation "đủ rõ" với 2 hypotheses (DoS vs Legitimate Load)
   - Không có ngụy biện 3rd hypothesis chỉ để đầy đủ
   - **Đúng pragmatic reasoning**

### 🎯 Architectural validity

**Đây là case "agent essential" theo NetVigil paper Table 4:**

```
Per paper insight:
  ALLOW-path traffic (LEAF cho qua per zt-web-app-allow) — chỉ rate anomaly
  detect được. Single packet KHÔNG vi phạm policy. Agent là layer duy nhất
  có thể đánh giá rate context.
  
Per agent's reasoning:
  Step 1: "WEB→APP:8080 = critical web-to-application-proxy path" (legitimate)
  Step 2: "600x deviation from baseline"  
  Step 3: "Preventing APP tier collapse > preserving 1 web host service"
  Step 4: "Runbook says load tests should be from MGT, not WEB"
  
→ Agent demonstrates the EXACT value-add of ML/LLM-based detection over
  static rules. Static rule alone (LEAF) cho phép traffic này. Agent layer
  identify anomaly + apply business policy + decide DROP.
```

### 📐 So sánh với business semantic

| Business expectation | Agent's response | Match? |
|---|---|---|
| Detect rate anomaly trên ALLOWED path | ✓ 600x deviation flagged | ✓ |
| Avoid false-positive với legit traffic | ✓ Check runbook, source trust, history | ✓ |
| Protect downstream tier (APP) ưu tiên cao | ✓ "APP collapse > 1 web host service" | ✓ |
| Targeted block không cắt over | ✓ src+dst+port, không cắt other flows | ✓ |
| Auto-revoke khi traffic về normal | ✓ "If rate drops below 10/min → revoke" | ✓ |
| Anticipate compromise indicators | ✓ Follow-up monitor lateral movement + host logs | ✓ |

**→ Agent's reasoning fully aligned với "behavioral anomaly on legitimate path" detection semantics.**

## Verdict

**Agent behavior EXCELLENT.** Đặc biệt step 3 (tradeoff APP tier vs web-01) thể hiện reasoning có business context — không chỉ "match rule, block". Memory feature working (trust score + prior alert reference).

**Highlight cho luận văn**: scenario này là minh chứng tốt nhất cho **"agent essential"** claim — LEAF static rules cho phép WEB→APP traffic, chỉ có agent (xem context: rate, baseline, runbook, source history) mới detect được compromise.
