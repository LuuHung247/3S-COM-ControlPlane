# Scenario 09 — Yatesbury #4: UDP DDoS

## Context

| Field | Value |
|---|---|
| Wrapper | `scenarios/yates_04_udp_ddos.py` |
| Trigger | `compromise-yates-udpddos.sh` — APP+WEB UDP flood DB:53 |
| Expected SID | 9000045 (UDP flood by_dst 500/10s) |
| Paper attack | NetVigil Table 3 #4 |

## Eval result

| Metric | Value |
|---|---|
| Outcome | **PASS** ✅ enforced |
| SID fired | 9000045 (UDP flood) for src=WEB |
| Conf | 0.92 |
| Action | DROP enforced |

## 🧠 Agent reasoning (SID 9000045)

### Hypotheses
- **Malicious UDP Flood (p=0.92)** — Compromised web-01 flooding db-01 on port 53. Counter: None.
- **Misconfigured DNS Client (p=0.08)** — Counter: "Packet rate 500/10s is orders of magnitude higher than normal DNS query bursts"

### Reasoning chain (6 steps)
1. SID 9000045 trigger: WEB→DB:53 with >500 UDP/10s
2. **Microsegmentation violation**: "WEB zone (untrusted) must not initiate to DB zone (crown-jewel)"
3. **Port semantic**: "Port 53 (DNS) is anomalous for db-01 (PostgreSQL backend), which does NOT provide DNS services"
4. High packet rate confirms malicious intent (DoS/flood)
5. Targeted block (src+dst+port), preserve WEB→APP:8080
6. Confidence 0.92: policy violation + high-rate anomaly

---

## 📊 Evaluation

### ✅ Tốt

1. **Service-port semantic awareness (step 3)**
   - "DB is PostgreSQL backend, does NOT provide DNS"
   - Agent có **service inventory knowledge** — không chỉ port number, mà service mapping per host
   - Đây là contextual reasoning, không generic UDP flood detection

2. **Counter-hypothesis với rate scaling**
   - "DNS query bursts orders of magnitude lower than 500/10s"
   - Quantitative reject FP — không chỉ "could be misconfig"

3. **Cross-zone + DoS combined reasoning**
   - WEB→DB cross-zone violation + UDP flood rate
   - Double signal → high confidence
   - **Multi-dimensional threat scoring**

### ⚠️ Note

1. **Hypothesis probability field mismatch (same bug từ scenario 05)**
   - Text says "0.92" và "0.08" nhưng JSON field probability = 0.5 both
   - Decision vẫn enforce đúng (confidence field separate)

2. **Only WEB src decision** — APP UDP flood may have fired SID 9000045 first (by_dst threshold) → only 1 decision per SID needed → agent reasoning shows WEB context. APP contribution still counted nhưng không có separate decision.

### 🎯 Architectural insight

UDP DDoS detection requires **service-port reasoning** — không chỉ "high UDP rate" mà "high UDP rate TO PORT-not-running-this-service". Agent demonstrates this awareness via step 3.

## Verdict

**CORRECT** — service-port semantic awareness là điểm mạnh. Cross-zone + DoS double signal lead to confident DROP. Similar pattern multi-src DDoS như scenario 08 — agent enforce on first-fire src.
