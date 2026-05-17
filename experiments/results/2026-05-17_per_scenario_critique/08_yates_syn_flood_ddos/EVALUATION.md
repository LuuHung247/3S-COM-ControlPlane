# Scenario 08 — Yatesbury #3: SYN Flood DDoS (multi-source)

## Scenario context

| Field | Value |
|---|---|
| Wrapper | `scenarios/yates_03_syn_flood_ddos.py` |
| Trigger | `compromise-yates-synddos.sh` — sets flags on **APP + WEB**, BOTH fire hping3 |
| Attack pattern | Coordinated DDoS từ 2 sources tới DB:5432 |
| Expected SID | 9000044 ×2 (per-src threshold) |
| Paper attack | NetVigil Table 3 #3 — SYN Flood DDoS |

## Eval result — **AGENT NOW HANDLES BOTH SOURCES**

Khác với scenario 9 v4 (under-react APP src), lần này:

| src | SID | Action | Conf | Hypothesis |
|---|---|---|---|---|
| APP 10.2.100.10 | 9000044 | DROP enforced | 0.88 | tcp_syn_flood_anomaly |
| APP 10.2.100.10 | 9000043 | DROP enforced | 0.92 | tcp_syn_flood_dos |
| **WEB 10.1.100.10** | 9000001 | DROP enforced | 0.95 | Lateral movement via microseg bypass |
| **WEB 10.1.100.10** | 9000051 | DROP enforced | 0.95 | cross_zone_web_to_db_lateral_movement |
| **WEB 10.1.100.10** | 9000044 | DROP enforced | 0.95 | **cross_zone_ddos_lateral_movement** ← multi-src awareness |

→ **5 DROP rules pushed across 2 LEAFs cho cùng 1 coordinated DDoS scenario.** Multi-source detection improvement vs earlier run.

## 🧠 Agent reasoning — Comparison APP vs WEB

### APP src (path ALLOWED — zt-app-db-allow)
- Conf **0.88** (moderate — path is legit)
- Reasoning step 4: "**Path legitimacy: APP→DB:5432 is a baseline-ALLOW path. This is NOT a policy violation but a behavioral anomaly on a legitimate path.**"
- Reasoning step 7: "Strong rate signal (150x deviation) warrants action, but legitimate path and lack of prior history **reduce confidence from 0.95 to 0.88**"
- → **Agent calibrate đúng**: behavioral anomaly trên allowed path = lower conf than policy violation

### WEB src (path DENIED — cross-zone violation)
- Conf **0.95** (high — clear violation)
- Reasoning step 4: "**Multi-alert correlation shows kill-chain progression: recent SID sequence 9000001 → 9000051 → 9000044 indicates escalating attempts**"
- Reasoning step 7: "unambiguous zone violation (+4 points) + rate anomaly (+3 points) + corroborated by past incidents (+1 point) = 8+ points → P1 threshold"
- → **Agent identify multi-stage kill-chain** + correlate cross-SIDs

---

## 📊 Evaluation — **KEY IMPROVEMENTS observed**

### ✅ Multi-source correlation NOW visible (kill-chain mention)

**WEB src reasoning step 4 (NEW):**
> "Multi-alert correlation shows kill-chain progression: recent SID sequence 9000001 → 9000051 → 9000044 indicates escalating attempts to reach DB tier, now with DoS characteristics."

→ Agent **đang correlate** cross-SIDs trong sequence. Đây là **fix improvement** so với run earlier (scenario 9 v4 — agent under-react APP src). Có thể do memory accumulation từ scenarios 06+07 đã tăng signal strength.

### ✅ Differential confidence calibration

| Aspect | APP src (allowed path) | WEB src (cross-zone) |
|---|---|---|
| Confidence | 0.88 | 0.95 |
| Reasoning | "behavioral anomaly on legitimate path" | "unambiguous zone violation" |
| Severity scoring | 150x rate signal | 8+ points → P1 |

→ Agent **distinguish** giữa:
- Anomaly on legit path (need behavioral evidence, lower base conf)
- Hard policy violation (immediate high conf)

Đây là **production-grade discrimination** — exactly what we want.

### ✅ Hard override gate explicit (APP step 8)
> "src_zone=APP (not MGT), dst_ip not in NEVER_BLOCK list, confidence 0.88 > 0.85 threshold — DROP action permitted."

Agent **không bypass L7 safety check** even khi rate signal strong.

### 🎯 Architectural significance

```
Previous concern (scenario 09 v4):
  Multi-src DDoS → agent under-react contributor src (APP)
  Diagnosed as "architectural limitation — no cross-source aggregation"

This run shows:
  Agent NOW enforce DROP cho cả APP + WEB
  WEB reasoning EXPLICIT cite kill-chain progression
  → Cross-SID correlation đang work
  
Hypothesis: Memory layer accumulating from scenarios 06+07
  → prior SIDs reference đầy đủ hơn
  → agent confident enough to enforce on APP contributor
  → architectural concern partially mitigated
```

### 📐 Business semantic match

| Expectation | Agent response | Match? |
|---|---|---|
| Block ALL DDoS contributors | ✓ DROP for both APP + WEB | ✓ |
| Differentiate path legit vs violation | ✓ Conf 0.88 vs 0.95 | ✓ |
| Kill-chain correlation | ✓ Explicit cite "1 → 51 → 44 sequence" | ✓ |
| Memory across runs | ✓ "past enforcement for SID 9000001/9000051" | ✓ |

## Verdict

**MAJOR IMPROVEMENT vs trước.** Agent **now enforces both DDoS contributors** với appropriate differential confidence. Kill-chain correlation visible. Multi-source DDoS handling tốt hơn previous concern.

**Highlight cho luận văn**: agent's reasoning thay đổi theo memory accumulation (run sequential thay vì batch). Cross-SID correlation explicit. Đây là evidence cho **memory feature value-add** — agent improve over time với more context.
