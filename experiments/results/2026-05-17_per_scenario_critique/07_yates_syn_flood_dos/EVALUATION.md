# Scenario 07 — Yatesbury #2: SYN Flood DoS (single source)

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/yates_02_syn_flood_dos.py` |
| Trigger | `compromise-yates-synflood.sh` → APP fires `hping3 --flood -p 5432 10.1.200.10` |
| Expected SID | 9000043 (SYN flood single source) |
| ZT context | hping3 --flood 20s = ~1200 SYN/min, vượt threshold 200/10s rất nhiều |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| SIDs fired | 9000043 + 9000044 (cả 2 fire vì rate cao) |
| Confidence | 0.92 |
| Action | DROP enforced, TTL 1800s |

## 🧠 Agent reasoning (SID 9000043)

### Hypotheses (3)
- **tcp_syn_flood_dos (p=0.92)** — App host flooding DB. Evidence: 600x deviation, prior SID 9000044 from same host
- **connection_pool_exhaustion_bug (p=0.05)** — Counter: rate 1200/min far exceeds any legit pool
- **legitimate_load_test (p=0.03)** — Counter: must originate from MGT per policy

### Reasoning chain (6 steps)
1. 200 SYN/10s threshold cross from src=APP→DB:5432
2. **600x baseline deviation** (1200/min vs expected 2/min, threshold 50/min)
3. **Pattern analysis: SYN-only packets (S,!A) = incomplete handshakes** = SYN flood signature, không phải normal OLTP
4. Host reputation: trust 0.2 + prior SID 9000044 (DDoS component) → recurring abusive behavior
5. Targeted block (src+dst+port), preserve other legit APP flows
6. Confidence 0.92: unambiguous + clear signature + corroborating past

### Alternative actions
- IF rate drops below 50/min trong 5 min → DELETE rule early (self-healed)
- IF WEB→APP errors spike → escalate human (business impact outweighs security)
- IF additional SIDs (SQL, lateral) → extend TTL + escalate (multi-stage)

---

## 📊 Evaluation

### ✅ Tốt

1. **TCP flag semantic awareness (step 3)**: agent biết "SYN-only (S,!A) = incomplete handshake = SYN flood signature". Hiểu protocol-level pattern, không chỉ count packets.
2. **Memory tracking consistent**: "trust 0.2 + prior SID 9000044" — same as previous scenarios → memory accumulation working stable
3. **Business-aware escalation path**: "IF WEB→APP errors spike → escalate human (business impact outweighs security)" — agent biết tradeoff, không security-first dogmatic
4. **Self-healing**: IF rate normalizes → revoke rule early

### 🎯 Architectural insight

Agent's "SYN flag analysis" (step 3) là **protocol-level reasoning** — không chỉ dùng count. Quan trọng cho thesis: agent reason ở **multiple abstraction levels** (packet flags, flow rate, host reputation, business impact).

### 📐 Business semantic match

| Expectation | Agent | Match? |
|---|---|---|
| Detect single-src SYN flood | ✓ SID 9000043 → DROP | ✓ |
| Protocol semantic (SYN-only) | ✓ Step 3 explicit | ✓ |
| Memory of past abusers | ✓ Reference prior SID 9000044 | ✓ |
| Business-vs-security tradeoff | ✓ Alt action #2 | ✓ |

## Verdict

**CORRECT** — đặc biệt step 3 (protocol semantic) và alt action #2 (business override path) là minh chứng tốt cho mature security reasoning, không phải naïve rule matching.
