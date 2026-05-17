# Scenario 12 — Yatesbury #11: C&C Beacon

## Context

| Field | Value |
|---|---|
| Wrapper | `scenarios/yates_07_c2_beacon.py` |
| Trigger | `compromise-yates-c2.sh` — APP fires 8 small SYN beacons to 8.8.8.8:443 over ~4 min |
| Expected SID | 9000046 (low-and-slow C2 — threshold 3/90s sau rev:2 fix) |
| Paper | NetVigil Table 4 — "difficult" category (AUC 0.93 NetVigil, 0.63 Kitsune+, 0.50 Whisper) |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| SID fires | 9000046 ×3 (14:56:09, 14:57:13, 14:58:45) — beacon pattern detected |
| Conf | 0.80 - 0.85 (consistent) |
| Action | DROP enforced TTL 3600s |

## 🧠 Agent reasoning (SID 9000046)

### Hypotheses (3 — well-balanced)
- **C2 beacon heartbeat (p=0.70)** — Periodic small outbound matches classic C2. Counter: Could be legitimate DoH client.
- **Legitimate DNS-over-HTTPS client (p=0.25)** — Application using Google DoH. Counter: APP tier should use internal DNS, not external DoH.
- **Data exfiltration channel (p=0.05)** — Counter: 200-byte too small for meaningful exfil.

### Reasoning chain (7 steps)
1. SID 9000046: 5 SYN small (<200B) to 8.8.8.8:443 in 300s
2. **Baseline analysis**: "10.2.100.10 → 8.8.8.8:443 is NOT in production patterns. Expected outbound is only to 10.1.200.10:5432 (DB OLTP)"
3. Threat pattern match `c2_beacon` (P2)
4. **Historical precedent**: "Past 90 days show 1 exact-SID match (enforced DROP), and 1 semantically similar incident (cosine sim=0.82). Pattern recurrence strengthens threat signal."
5. Blast radius mitigation: targeted block preserve OLTP
6. Confidence 0.85: clear SID + baseline violation + history. **Reduced from 0.92 due to FP possibility of legitimate DoH**
7. Hard override check: zone APP, dst not in NEVER_BLOCK, conf ≥ 0.85, action DROP — all satisfied

---

## 📊 Evaluation

### ✅ Đặc biệt notable

1. **DoH (DNS-over-HTTPS) hypothesis (p=0.25)**
   - Agent recognize 8.8.8.8:443 = Google DoH (modern legitimate use case)
   - Không reject hypothesis nhanh — give it 25% probability
   - Counter chính xác: "APP should use internal DNS, not external DoH"
   - **Modern threat knowledge** — DoH có thể là legit hoặc evasion

2. **Memory vector search visible (step 4)**
   - "cosine sim=0.82" với prior incident
   - Agent's embedding search **đang work** — retrieve semantically related past
   - Quan trọng cho luận văn về memory architecture

3. **Confidence calibration đúng (step 6)**
   - 0.85 (not 0.92 anchor) — explicitly note "reduced due to FP possibility of legitimate DoH"
   - Agent **thận trọng** với edge case modern apps

4. **Multiple fires confirmed pattern**
   - 9000046 fire 3 lần within 4 phút (14:56, 14:57, 14:58)
   - Mỗi lần DROP enforced — agent consistent
   - Pattern emergent từ cron behavior

### 🎯 Architectural insight

C2 beacon là **"difficult" category** per NetVigil paper — hard to distinguish from legitimate periodic traffic. Agent's reasoning shows:
- Multi-hypothesis weighing (C2 vs DoH vs exfil)
- Historical context via memory (cosine sim)
- Confidence calibration based on FP risk

→ **Đây là loại case mà ML agent rõ ràng beats static rules** — rules chỉ count packets, agent reason về intent + context.

### Verdict

**EXCELLENT** — đặc biệt DoH counter-hypothesis thể hiện modern security awareness. Memory retrieval (sim=0.82) visible. C2 beacon SID fires 3 lần consistent DROP — agent stable.

Highlight cho luận văn: **C2 detection scenario** này là minh chứng best cho **agent essentialness on "difficult" patterns** (paper categorization).
