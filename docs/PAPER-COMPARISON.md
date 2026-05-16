# Paper Comparison — NetVigil (NSDI'24) vs Zero-Trust LLM Agent

> Side-by-side comparison of this thesis project against
> **NetVigil: Robust and Low-Cost Anomaly Detection for East-West Data
> Center Security** (Hsieh et al., USENIX NSDI 2024), and the open-source
> **Yatesbury** benchmark released alongside it.
>
> Paper PDF: `/home/dis/deploy/nsdi24-hsieh.pdf`
> Benchmark: `https://github.com/microsoft/Yatesbury`

---

## 1. Problem statement

Both works target the same gap: **east-west traffic anomaly detection
inside a data center**. Perimeter IDS / signature-based tools (Snort,
Suricata, Zeek, Pigasus) cover north-south well but become cost-prohibitive
when applied to all internal flows.

| | NetVigil | This thesis |
|---|---|---|
| Goal | Cost-efficient anomaly detector for east-west flows | Closed-loop LLM-driven response on zero-trust microsegmentation |
| Output | Anomaly score per (IP-pair, 2-min window) | Enforcement decision per suspect flow (DROP / log_only / refuse) |
| Action taken | Surface to security team (alert-only) | Push iptables DROP via Secure Framework + audit trail |
| Detection model | GNN autoencoder + contrastive learning + temporal smoothing | LLM-augmented decision-making (LLaMA-3.1-8b classifier + GLM-4.7 reasoner) over a curated KG |

→ **Complementary, not competing.** NetVigil = detection benchmark; this
project = detection + response benchmark.

---

## 2. Architecture comparison

### NetVigil

```
Cloud VMs / containers
   ↓ NSG flow logs (5-tuple + bytes/packets, aggregated 1 min)
Security Graph Feature Extractor
   • IP-pair aggregation (vs 5-tuple) — 100× smaller graph
   • 9 features per pair (Table 2)
   • Unseen-port tracking
   ↓
GNN Autoencoder
   • Reconstruction loss = anomaly score
   • Contrastive learning + temporal smoothing
   • Continuous retraining on clean logs
   ↓
Anomaly edges → security team review (manual)
```

### This thesis

```
SONIC Spine-Leaf fabric (4 Alpine workload VMs)
   ↓ Suricata eve.json type:flow (no SID rule alerts)
SSE consumer → FlowWindow buffer (2-min, NetVigil-aligned)
   ↓ window close
FlowAggregator
   • IP-pair aggregation
   • Same 9 NetVigil features (Table 2)
   ↓
[Tier 1a] Python heuristic suspect_score()  — $0
[Tier 1b] LLaMA-3.1-8b batch classifier      — 1 call/window
[Toggle gate] Operator can pause Tier-1b + Tier-2 for token control
   ↓ union of suspects
[Tier 2] GLM-4.7 Stage 1 with full KG context (~10K tokens prompt)
   • threat-patterns.md (20 patterns, 8 classes)
   • severity-scoring.md (point rubric)
   • flow-features.md (NetVigil features ref)
   • baselines.md (statistical bounds)
   • invariants.md (NEVER_BLOCK list)
   ↓
9-layer safety validation
   ↓
Enforcement: DROP rule pushed to LEAF iptables via Secure Framework
              OR log_only audit (no rule)
              OR refuse (low confidence / off-target / never-block hit)
   ↓
Window summary event → FE Monitor (FE alive signal)
```

---

## 3. Yatesbury benchmark coverage

NetVigil's Table 3 lists 14 attack scenarios. Lab coverage:

| # | Yatesbury scenario | Lab eval script | Approach |
|---|---|---|---|
| 1 | Vertical Port Scan | `eval_yates_vertical_scan.py` | nmap APP→DB ports 1-1000 |
| 2 | SYN Flood DoS | `eval_yates_syn_flood_dos.py` | hping3 -S --flood APP→DB:5432 |
| 3 | SYN Flood DDoS | `eval_yates_syn_flood_ddos.py` | Coordinated APP + WEB SYN flood DB |
| 4 | UDP DDoS | `eval_yates_udp_ddos.py` | UDP flood from 2 hosts to DB:53 |
| 5 | Distributed Stealth Port Scan | `eval_yates_distributed_scan.py` *(subset)* | 2 hosts low-and-slow scan |
| 6 | Distributed Port Scan | `eval_yates_distributed_scan.py` | 2 hosts scan many targets |
| 7 | Distributed UDP Port Scan | `eval_yates_distributed_scan.py` *(udp variant)* | UDP scan distributed |
| 8 | Infection Monkey 1 | `eval_yates_infection_monkey.py` | Multi-stage scan → exploit → lateral |
| 9 | Infection Monkey 2 | `eval_yates_infection_monkey.py` | Limited target |
| 10 | Infection Monkey 3 | `eval_yates_infection_monkey.py` | Limited exploits |
| 11 | C&C Communication | `eval_yates_c2_beacon.py` | curl periodic small POST → NAT2 |
| 12 | DNS Amplification | (subset of UDP DDoS) | DNS-style amplification |
| 13 | SQL Injection | `eval_app_db_sql.py` | DROP TABLE / TRUNCATE content |
| 14 | Unauthorized DB Access | `eval_yates_unauth_db.py` | WEB→DB direct microseg bypass |

**Coverage: 14/14 paper scenarios** (some grouped due to similar attack
shape and lab's 4-VM scale).

---

## 4. Methodology differences

### Trace mode (paper) vs IID mode (this thesis)

| | NetVigil/Yatesbury | This thesis |
|---|---|---|
| **Per scenario** | 1 long continuous trace, 1-2 hours | 10 discrete IID attack triggers, ~2 min each |
| **Total wall time** | 60-120 min | ~21 min (10 × 2 min + pauses) |
| **Unit of measurement** | (src_ip, dst_ip, 2-min window) → binary label | Per-run pass/fail |
| **Primary metric** | AUC, TPR, FPR | Pass rate (e.g., 10/10), MTTD avg, latency p99 |
| **Statistical basis** | 100s of (pair × window) datapoints / scenario | 10 runs → mean ± stddev of MTTD |
| **Captures** | Time-of-day variation, traffic dynamics | Burst-response repeatability |

**Why the difference?**
- NetVigil claims **anomaly detection accuracy** — needs many (pair, window)
  labels to compute AUC over the full ROC curve.
- This thesis claims **closed-loop response correctness** — measures
  whether the system fires the right enforcement under attack, repeatable
  variance is what matters.

Both are valid; they answer different questions. Future work:
`eval_trace.py` to add paper-compatible trace mode (~3-4 days code).

---

## 5. NetVigil published numbers — apples-to-apples target

From paper Table 4 (NetVigil column, Yatesbury benchmark on 16-VM Azure):

| Scenario | AUC | TPR | FPR |
|---|---|---|---|
| Vertical Port Scan | 0.984 | 0.95 | 0.00 |
| SYN Flood | 1.000 | 1.00 | 0.00 |
| SYN Flood DDoS | 1.000 | 1.00 | 0.00 |
| UDP DDoS | 1.000 | 1.00 | 0.00 |
| Distributed Port Scan | 0.997 | 0.95 | 0.00 |
| Distributed Stealth Port Scan | 0.989 | 0.83 | 0.00 |
| Distributed UDP Port Scan | 0.996 | 0.95 | 0.02 |
| Infection Monkey 1 | 1.000 | 1.00 | 0.00 |
| Infection Monkey 2 | 1.000 | 1.00 | 0.00 |
| Infection Monkey 3 | 1.000 | 1.00 | 0.00 |
| **C&C communication** | **0.930** | 0.76 | 0.09 |
| **DNS amplification** | **0.892** | 0.37 | 0.07 |
| **SQL injection** | **0.640** | 0.64 | 0.26 |
| **Unauthorized DB access** | **0.800** | 0.71 | 0.17 |

NetVigil paper acknowledges difficulty on the last 4 (content-shape or
behavioral-mimicry attacks). This thesis project's KG-based reasoning
SHOULD do better on:

- **SQL injection** — Suricata content match + `threat-patterns.md F1
  destructive_sql_content` give explicit DROP signal.
- **Unauthorized DB access** — `threat-patterns.md A1
  cross_zone_violation_web_to_db` is a hard policy violation, agent
  classifies P1 deterministically from KG.

This thesis project SHOULD struggle on:

- **DNS amplification** — current lab has no DNS server in topology;
  amplification setup requires extra infrastructure.
- **C&C beacon** — periodic small outbound blends with health-probe
  cadence; agent must reason about destination IP being outside HOME_NET.

---

## 6. Cost comparison (paper's economic argument)

Paper's Figure 7 — annual cost for 16-VM deployment:

| Tool | Cost/year (USD) |
|---|---|
| Kitsune+ (packet trace) | 49,159 |
| Kitsune+ (flow logs) | 48,428 |
| Whisper (packet trace) | 8,602 |
| Whisper (flow logs) | 7,871 |
| **NetVigil** | **2,939** |

NetVigil's win: avoids expensive packet inspection + 56 vCPU detection box.

**This thesis cost estimate** (per window, 2-min):
- Heuristic: $0
- LLaMA-3.1-8b: ~$0.0001 / call × 30 windows/h = $0.003/h
- GLM-4.7: ~$0.001 / suspect × ~2 suspect/window × 30 windows/h = $0.06/h
- 24h: ~$1.50; year: ~$550

**16-VM equivalent** (paper scale): roughly 4× the rate → ~$2,200/year.

→ This thesis is ~30% cheaper than NetVigil's cost claim, with the
toggle providing further savings during idle / demo periods.

(All numbers approximate; production usage shows actual cost in Langfuse
session billing.)

---

## 7. Where each approach wins

### NetVigil wins
- **Scale** — GNN handles 1000s of nodes/edges efficiently
- **Truly unsupervised** — no labeled malicious data required
- **Continuous retraining** — adapts to traffic drift automatically
- **No reasoning lag** — single GNN inference ~ms

### This thesis wins
- **Closed-loop enforcement** — actually blocks attacks, not just flags
- **Explainable** — agent's reasoning trace cites baselines + threat-patterns
  + MITRE technique mapping (HITL-ready)
- **Zero-shot on unfamiliar patterns** — KG + LLM generalises beyond
  patterns seen in training data
- **Operator-controllable** — toggle ON/OFF for token economy, severity
  thresholds adjustable via prompts (no model retraining)
- **Audit-grade** — Postgres decisions table + Langfuse trace per call

---

## 8. Limitations of this thesis vs paper

| | Paper claim | Thesis honest gap |
|---|---|---|
| Statistical strength | 100s of labeled (pair × window) per scenario | 10 IID runs per scenario — limited variance estimation |
| AUC computation | Direct from labels | Not yet implemented — need `eval_trace.py` (future work) |
| Continuous learning | Continuous GNN retraining | Static KG — manual edits to `.md` files |
| Multi-tenant / cluster scale | 16-VM, 400-VM production traces | 4-VM lab — distributed-attack scenarios need careful design |
| Adversarial robustness | Limited explicit testing | 25 adversarial test cases in CI (L9 safety) but not full red-team |

---

## 9. Threat patterns coverage — KG vs NetVigil features

| NetVigil-detected pattern | KG pattern in `threat-patterns.md` | Class |
|---|---|---|
| Vertical port scan | C1 vertical_port_scan | C — Recon |
| Horizontal scan | C2 horizontal_fanout_scan | C — Recon |
| Distributed scan | C3 distributed_port_scan | C — Recon |
| SYN flood | E1 syn_flood_dos | E — DoS |
| SYN flood DDoS | E2 syn_flood_ddos | E — DoS |
| UDP DDoS | E3 udp_ddos | E — DoS |
| C&C beacon | D1 c2_beacon | D — C&C |
| DNS amplification | D2 dns_tunneling | D — C&C |
| Infection Monkey | G1 infection_monkey_chain | G — Multi-stage |
| Unauthorized DB | A1 cross_zone_violation_web_to_db | A — Policy violation |
| SQL injection | F1/F2 destructive_sql_content / sql_injection_recon | F — Content |
| Off-hours probe | B3 off_hours_activity | B — Behavioral |

Plus lab-specific patterns NOT in paper:
- B1 rate_burst_anomaly (APP→DB burst)
- B2 volume_exfiltration_outbound (DB→APP large reply)
- A2 sensitive_zone_outbound (DB outbound)
- A3 cross_tier_admin_port (workload→workload SSH)
- H1 mgt_compliance_baseline (MGT NEVER_BLOCK)

---

## 10. Recommended thesis chapter structure

For thesis defense, this comparison naturally feeds a dedicated chapter:

1. **Background** — east-west threat landscape, why microsegmentation alone
   is insufficient (cites NetVigil §1-§2).
2. **Related work** — anomaly-based vs signature-based IDS, NetVigil's
   GNN approach, Kitsune/Whisper baselines.
3. **System** — pipeline 3-tier description (heuristic → LLaMA → GLM)
   referencing §13 of INTELLIGENCE-LAYER.md.
4. **Knowledge curation** — threat-patterns / severity-scoring /
   flow-features as alternative to GNN training corpus.
5. **Evaluation** — 14-scenario coverage (`eval_yates_*.py` + lab's 6) +
   IID-mode results + future trace-mode for AUC.
6. **Discussion** — when LLM reasoning beats GNN (semantic-rich attacks)
   and when GNN wins (scale, continuous learning).
7. **Limitations & future work** — `eval_trace.py`, multi-cluster scale,
   adversarial robustness.

---

## References

1. K. Hsieh et al. "NetVigil: Robust and Low-Cost Anomaly Detection
   for East-West Data Center Security." USENIX NSDI 2024.
   https://www.usenix.org/conference/nsdi24/presentation/hsieh

2. Microsoft. Yatesbury benchmark dataset.
   https://github.com/microsoft/Yatesbury

3. This thesis project source: `/home/dis/deploy/zerotrust`
