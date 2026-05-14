# East-West Threat Patterns — Flow-Keyed Taxonomy

This file enumerates the threat patterns the agent must recognize from raw flow
events (no pre-classified SID). Each pattern is keyed by a **flow signature**
that the LLM can match against an incoming `eve.json` flow record + recent
`past_incidents` window.

The taxonomy is structured by **threat class** (policy violation, behavioral
anomaly, reconnaissance, C&C, DoS, content-based, multi-stage) so the agent
can quickly narrow the candidate set before deep reasoning.

Pattern coverage spans the lab's current six scenarios and the Yatesbury
benchmark from the NetVigil paper (NSDI'24), giving the agent a vocabulary
broad enough to handle production east-west traffic.

---

## Class A — Policy Violations (Microsegmentation Bypass)

Hard zero-trust violations. Flow originates from or arrives at a zone pair
that the policy matrix explicitly disallows. LEAF iptables already drops
these, but the agent must still produce a structured decision (audit trail,
MITRE mapping, escalation).

### A1 · cross_zone_violation_web_to_db
```yaml
id: cross_zone_violation_web_to_db
threat_class: policy_violation
flow_signature:
  src_zone: WEB
  dst_zone: DB
  dst_port: any
description: |
  WEB tier initiates a connection directly to DB. Policy requires all data
  access to be mediated by the APP tier. Direct WEB→DB connection indicates
  compromised web-tier preparing to exfiltrate or destroy data.
severity: P1
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.95
false_positive_scenarios:
  - Pre-announced DB migration script run from WEB host (extremely rare)
  - Misconfigured monitoring tool
ref_yatesbury: partially_unauthorized_db_access
ref_lab_scenario: SID 9000001 (eval_iid)
```

### A2 · sensitive_zone_outbound
```yaml
id: sensitive_zone_outbound
threat_class: policy_violation
flow_signature:
  src_zone: DB
  dst_zone: NOT in [DB, internal_storage]
description: |
  DB tier initiates outbound connection. By design, DB never originates any
  flow — it only accepts queries from APP. Any DB-initiated outbound is
  exfiltration, C&C beacon, or data tier compromise.
severity: P1
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1041 Exfiltration Over C2 Channel
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.92
false_positive_scenarios:
  - DB host pulling security update via package manager (should use proxy)
ref_yatesbury: c2_communication
ref_lab_scenario: SID 9000002 (eval_db_exfil)
```

### A3 · cross_tier_admin_port
```yaml
id: cross_tier_admin_port
threat_class: policy_violation
flow_signature:
  src_zone: in [WEB, APP, DB]
  dst_zone: in [WEB, APP, DB]
  dst_port: in [22, 3389, 5985, 5986]   # ssh, rdp, winrm
description: |
  Workload-tier host attempts SSH/RDP/WinRM to another workload-tier host.
  Only MGT may SSH into workloads. Workload→workload admin-port traffic
  is lateral movement preparation (attacker pivoting after foothold).
severity: P1
mitre_tactic: TA0008 Lateral Movement
mitre_technique: "T1021.004 Remote Services: SSH"
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.92
false_positive_scenarios:
  - Devops running ad-hoc tooling from APP host (should use MGT bastion)
ref_yatesbury: infection_monkey (lateral SSH stage)
ref_lab_scenario: SID 9000035 (eval_app_mgt_ssh)
```

---

## Class B — Behavioral Anomalies on ALLOW paths

LEAF permits the flow direction by policy, but observed behavior deviates
from baseline. Only the agent (with baseline + temporal context) can detect.

### B1 · rate_burst_anomaly
```yaml
id: rate_burst_anomaly
threat_class: behavioral_anomaly
flow_signature:
  src_ip: same
  dst_port: same
  observed_rate_per_minute: ">3x baseline mean"
  window_seconds: 60
description: |
  Connection rate from a single source to a single dst_port exceeds 3x the
  baseline mean within 60-second window. Indicates compromised host
  weaponizing an allowed permission (e.g., proxy abuse, mass DB extraction).
severity_inference:
  - dst is critical service (DB, payment) → P1
  - dst is regular service → P2
mitre_tactic: TA0040 Impact | TA0010 Exfiltration
mitre_technique: T1499 Endpoint Denial of Service | T1530 Data from Cloud Storage
recommended_action: DROP
recommended_scope: src_ip/32 + dst_ip/32 + dst_port
recommended_ttl_seconds: 1800
confidence_baseline: 0.85
requires_corroboration:
  - past_incidents window 5min same src
  - off-hours timing strengthens severity
false_positive_scenarios:
  - Legitimate batch job spike (should be pre-announced via change ticket)
  - Cache invalidation storm
ref_yatesbury: syn_flood_dos, unauthorized_db_access (volume variant)
ref_lab_scenario: SID 9000030, 9000031
```

### B2 · volume_exfiltration_outbound
```yaml
id: volume_exfiltration_outbound
threat_class: behavioral_anomaly
flow_signature:
  reply_direction: server_to_client
  bytes_per_flow: ">4096 sustained"
  count_flows: ">10 in 30s"
description: |
  Server (typically DB) replies with payloads >4KB across many flows in a
  short window. Normal OLTP returns small banners/result sets; large
  sustained reply payloads indicate bulk SELECT JOIN / table dump.
severity: P2
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1530 Data from Cloud Storage
recommended_action: DROP
recommended_scope: src_ip/32 (the receiving APP host)
recommended_ttl_seconds: 1800
confidence_baseline: 0.85
note: |
  In lab topology (asymmetric routing), reply direction may bypass IDS.
  Pattern still valid for symmetric deployments and future routing fix.
ref_yatesbury: unauthorized_db_access
ref_lab_scenario: SID 9000032 (deferred — routing limitation)
```

### B3 · off_hours_activity
```yaml
id: off_hours_activity
threat_class: behavioral_anomaly
flow_signature:
  src_zone: workload
  observed_at_utc: outside 08:00-18:00
  dst_zone: sensitive (DB or MGT-internal)
description: |
  Workload tier accesses sensitive zone outside the canonical business window.
  Legitimate user-driven traffic clusters during business hours; off-hours
  activity warrants extra scrutiny especially when paired with rate or
  volume signal.
severity: P3 (alone) | P2 (corroborated by rate anomaly) | P1 (corroborated by destructive content)
mitre_tactic: TA0007 Discovery | TA0010 Exfiltration
mitre_technique: T1078 Valid Accounts (off-hours abuse)
recommended_action: log_only (P3) | DROP (P2+)
recommended_ttl_seconds: 0 (log_only) | 1800 (DROP)
confidence_baseline: 0.60
requires_corroboration: rate_burst_anomaly OR destructive_content_payload
ref_lab_scenario: SID 9000034 (time-window context probe)
```

---

## Class C — Reconnaissance

Discovery/scanning patterns. Single source touches many destinations or many
ports — fan-out shape that legitimate workload traffic never exhibits.

### C1 · vertical_port_scan
```yaml
id: vertical_port_scan
threat_class: reconnaissance
flow_signature:
  src_ip: same
  dst_ip: same
  unique_dst_ports: ">20 in 60s"
description: |
  Single source scans many ports on a single target. Classic vertical
  port-scan looking for open services.
severity: P3
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
recommended_action: log_only + raise_trust_score
recommended_ttl_seconds: 0
confidence_baseline: 0.75
ref_yatesbury: vertical_port_scan
```

### C2 · horizontal_fanout_scan
```yaml
id: horizontal_fanout_scan
threat_class: reconnaissance
flow_signature:
  src_ip: same
  dst_port: same
  unique_dst_ips: ">10 in 60s"
description: |
  Single source touches the same port on many destinations. Horizontal
  scan looking for which hosts run a specific service.
severity: P3
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
recommended_action: log_only + raise_trust_score
recommended_ttl_seconds: 0
confidence_baseline: 0.80
ref_yatesbury: distributed_port_scan (single source variant)
ref_lab_scenario: SID 9000011 (port scan)
```

### C3 · distributed_port_scan
```yaml
id: distributed_port_scan
threat_class: reconnaissance
flow_signature:
  unique_src_ips: ">2"
  dst_ip: same
  unique_dst_ports: ">10 aggregate in 60s"
description: |
  Multiple sources collectively scan a single target. Distributed/stealth
  recon — each individual src looks low-volume but aggregate is anomalous.
  Detection requires group-level (graph) reasoning.
severity: P2
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 + T1595 Active Scanning
recommended_action: DROP each src_ip + escalate group as suspicious
recommended_ttl_seconds: 1800
confidence_baseline: 0.85
note: |
  Requires looking across multiple src_ip simultaneously. Stronger
  indicator of coordinated attacker than single-source scan.
ref_yatesbury: distributed_port_scan, distributed_stealth_port_scan, distributed_udp_port_scan
```

### C4 · icmp_sweep
```yaml
id: icmp_sweep
threat_class: reconnaissance
flow_signature:
  proto: icmp
  type: echo_request
  unique_dst_ips: ">3 in 10s"
description: |
  ICMP ping sweep — enumerating live hosts on a subnet.
severity: P3
mitre_tactic: TA0007 Discovery
mitre_technique: T1018 Remote System Discovery
recommended_action: log_only
recommended_ttl_seconds: 0
confidence_baseline: 0.85
ref_lab_scenario: SID 9000010
```

---

## Class D — Command & Control (C&C) Patterns

Periodic, low-volume outbound to attacker-controlled infrastructure.
Hallmarks: regular interval, small payload, persistent destination.

### D1 · c2_beacon
```yaml
id: c2_beacon
threat_class: command_and_control
flow_signature:
  src_zone: workload
  dst_zone: external (NAT-out)
  bytes_per_flow: "<500"
  interval_seconds: "30-300, regular cadence (low jitter)"
  duration_minutes: ">10"
description: |
  Compromised workload periodically beacons to external C&C server.
  Small payload (heartbeat or check-in), regular cadence with low jitter
  (often 60s ± 5s). Distinguishable from legitimate health checks by
  destination outside HOME_NET.
severity: P2
mitre_tactic: TA0011 Command and Control
mitre_technique: T1071 Application Layer Protocol | T1571 Non-Standard Port
recommended_action: DROP
recommended_scope: src_ip/32 + dst_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.80
requires_corroboration: dst_ip not in HOME_NET allow-list
false_positive_scenarios:
  - Legitimate telemetry agent (should be in allow-list)
  - Software update check
ref_yatesbury: c2_communication
```

### D2 · dns_tunneling
```yaml
id: dns_tunneling
threat_class: command_and_control
flow_signature:
  proto: udp_or_tcp
  dst_port: 53
  query_size: ">200 bytes"
  query_rate: "high"
description: |
  Abnormally large DNS queries (typically TXT records) from workload host.
  Data exfiltration encoded in DNS queries to attacker-controlled domain.
severity: P2
mitre_tactic: TA0011 Command and Control | TA0010 Exfiltration
mitre_technique: T1071.004 DNS | T1048.003 Exfiltration Over Unencrypted DNS
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 1800
confidence_baseline: 0.75
ref_yatesbury: dns_amplification (related — DNS abuse family)
```

---

## Class E — DoS / DDoS Patterns

High-volume traffic intended to deny service. Distinguishable from B1
(behavioral burst) by the SHAPE: DoS is uncoordinated flood, B1 is sustained
abuse of permitted protocol.

### E1 · syn_flood_dos
```yaml
id: syn_flood_dos
threat_class: dos
flow_signature:
  src_ip: same
  dst_ip: same
  proto: tcp
  flags: SYN_only_no_ACK
  rate_per_second: ">1000"
description: |
  Single source floods victim with TCP SYN at very high rate. SYN packets
  never followed by ACK (half-open connections exhausting victim's
  connection table).
severity: P1
mitre_tactic: TA0040 Impact
mitre_technique: T1499.002 Service Exhaustion Flood
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.95
ref_yatesbury: syn_flood_dos
```

### E2 · syn_flood_ddos
```yaml
id: syn_flood_ddos
threat_class: dos
flow_signature:
  unique_src_ips: ">2"
  dst_ip: same
  proto: tcp
  flags: SYN
  aggregate_rate_per_second: ">500"
description: |
  Multiple sources collectively flood single victim with SYN. Aggregate
  rate high but per-src may look legitimate. Requires group-level reasoning
  (count flows by dst_ip, sum rates).
severity: P1
mitre_tactic: TA0040 Impact
mitre_technique: T1499.002 Service Exhaustion Flood
recommended_action: DROP all participating src_ips + escalate victim defense
recommended_ttl_seconds: 3600
confidence_baseline: 0.90
ref_yatesbury: syn_flood_ddos
```

### E3 · udp_ddos
```yaml
id: udp_ddos
threat_class: dos
flow_signature:
  proto: udp
  unique_src_ips: ">2"
  dst_ip: same
  aggregate_rate_per_second: ">500"
description: |
  UDP flood from multiple sources to single victim. No handshake, harder
  to filter than SYN. Often reflective (DNS, NTP, memcached amplification).
severity: P1
mitre_tactic: TA0040 Impact
mitre_technique: T1498 Network Denial of Service
recommended_action: DROP all participating src_ips
recommended_ttl_seconds: 3600
confidence_baseline: 0.85
ref_yatesbury: udp_ddos, dns_amplification
```

---

## Class F — Content-based Attack Patterns

Payload-level attack signatures. Requires content inspection (NOT detectable
from flow logs alone — needs IDS DPI mode).

### F1 · destructive_sql_content
```yaml
id: destructive_sql_content
threat_class: content_attack
flow_signature:
  dst_port: in [5432, 3306, 1433, 27017]
  payload_contains_any: [DROP TABLE, TRUNCATE, DELETE FROM, DROP DATABASE]
description: |
  Database connection carries destructive SQL keyword in payload.
  Application code should never execute schema destruction; presence
  indicates direct attacker injection or compromised admin path.
severity: P1
mitre_tactic: TA0040 Impact
mitre_technique: T1485 Data Destruction
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 3600
confidence_baseline: 0.95
false_positive_scenarios:
  - Pre-announced schema migration (should be from MGT or change-window source)
  - DBA running maintenance from MGT bastion
ref_yatesbury: sql_injection (destructive subset)
ref_lab_scenario: SID 9000033
```

### F2 · sql_injection_recon
```yaml
id: sql_injection_recon
threat_class: content_attack
flow_signature:
  dst_port: in [5432, 3306, 1433]
  payload_matches_regex: |
    UNION\s+SELECT | OR\s+1\s*=\s*1 | WAITFOR\s+DELAY | ;--
description: |
  SQL injection payload pattern: UNION-based, boolean-blind, time-based
  blind, or comment-terminated. Attacker probing for data extraction.
severity: P2
mitre_tactic: TA0001 Initial Access | TA0010 Exfiltration
mitre_technique: T1190 Exploit Public-Facing Application
recommended_action: DROP
recommended_scope: src_ip/32
recommended_ttl_seconds: 1800
confidence_baseline: 0.85
ref_yatesbury: sql_injection
```

---

## Class G — Multi-stage Lateral Movement

Multi-step attack chains. Detection requires correlating multiple flow
events across time + zones (graph reasoning).

### G1 · infection_monkey_chain
```yaml
id: infection_monkey_chain
threat_class: lateral_movement_chain
flow_signature:
  observed_sequence:
    - stage_1: horizontal_fanout_scan from src_X
    - stage_2: cross_tier_admin_port (SSH/RDP) from src_X
    - stage_3: same pattern from new src_Y on previously-scanned host
  time_window_minutes: 10
description: |
  Classic Infection Monkey / human attacker chain — scan to identify reachable
  hosts, probe SSH credentials, hop to new host, repeat. Each stage alone
  may look low-confidence; chain together = high-confidence compromise.
severity_progression:
  - stage_1 alone: P3
  - stage_1 + stage_2: P2
  - stage_1 + stage_2 + stage_3: P1
mitre_tactic: TA0008 Lateral Movement | TA0007 Discovery
mitre_technique: T1021.004 + T1046
recommended_action:
  - stage_1: log_only + raise_trust_score
  - stage_2: DROP src_X + alert SOC
  - stage_3: DROP both src_X and src_Y + quarantine + escalate
recommended_ttl_seconds: 3600
confidence_baseline: 0.70 (chain detection requires multi-event correlation)
ref_yatesbury: infection_monkey_1, _2, _3
```

---

## Class H — Audit Baseline (Non-incident)

Flows the agent MUST recognize as legitimate to avoid false positives.

### H1 · mgt_compliance_baseline
```yaml
id: mgt_compliance_baseline
threat_class: audit
flow_signature:
  src_zone: MGT
  dst_zone: any
description: |
  Management plane traffic for compliance (health probes, audit SSH,
  log retrieval). Required by governance. Always permitted, logged
  for visibility, NEVER blocked.
severity: P4
mitre_tactic: N/A
recommended_action: log_only (audit trail)
recommended_ttl_seconds: 0
confidence_baseline: 0.99
note: |
  Hard rule — agent must never DROP MGT-originated flows even if rate looks
  high. MGT is in NEVER_BLOCK list at L4 safety gate.
ref_lab_scenario: SID 9000020
```

---

## How the agent uses this file

1. Receive raw flow event from `eve.json type:flow` (no SID).
2. Extract 5-tuple + bytes + flags + timestamp.
3. Match flow against `flow_signature` of each pattern (top-down by class).
4. Pick first matching pattern → adopt `severity`, `recommended_action`,
   `recommended_ttl_seconds`, `recommended_scope`, `mitre_tactic`,
   `mitre_technique` as starting point.
5. If `requires_corroboration` listed, fetch `past_incidents` and apply
   severity adjustment per `severity_progression` (Class G) or
   `severity_inference` (Class B).
6. Cross-check against `severity-scoring.md` for final P-level.
7. Output structured `POLICY_DECISION_SCHEMA`.

For patterns flagged "requires_corroboration" or "severity_progression",
the agent SHOULD use ReAct tool calls to verify before issuing P1/P2 DROP.

---

## Detection difficulty reference (from NetVigil paper, NSDI'24)

Empirical AUC scores from NetVigil's Yatesbury evaluation. Use this as
**confidence calibration anchor**: easy patterns → high confidence; hard
patterns → lower confidence, more reliance on corroboration.

```yaml
detection_difficulty_tiers:
  moderate:
    description: Single-host signature, high volume — easy to detect from flow logs alone.
    patterns: [C1 vertical_port_scan, E1 syn_flood_dos]
    netvigil_auc: 0.98-1.00
    agent_confidence_anchor: 0.90-0.95
    reasoning_aid: "Volume/rate features alone suffice"

  medium:
    description: Distributed or aggregated — needs cross-source graph reasoning.
    patterns: [E2 syn_flood_ddos, E3 udp_ddos, C2 horizontal_fanout_scan,
               C3 distributed_port_scan]
    netvigil_auc: 0.99-1.00
    agent_confidence_anchor: 0.85-0.92
    reasoning_aid: "Aggregate features across multiple src_ip, look for coordinated shape"

  difficult:
    description: Multi-stage, behavioral, or low-volume — needs deep reasoning + history.
    patterns: [G1 infection_monkey_chain, D1 c2_beacon, D2 dns_tunneling,
               F2 sql_injection_recon, B1 rate_burst_anomaly (subtle variant)]
    netvigil_auc: 0.64-0.93
    agent_confidence_anchor: 0.60-0.85
    reasoning_aid: |
      Single connection looks normal; pattern emerges only when correlating
      across time + multiple flows. Use past_incidents window. Require
      corroboration before P1 DROP.

  very_difficult:
    description: Content-based or amplification — flow logs alone insufficient.
    patterns: [F1 destructive_sql_content (needs DPI), 
               D2 dns_tunneling (requires query content)]
    netvigil_auc: 0.64-0.89
    agent_confidence_anchor: 0.50-0.80
    reasoning_aid: |
      Pure flow log misses content signal. Lab eve.json includes http+dns
      event types — supplement flow reasoning with content events when
      available. NetVigil paper notes SQL injection AUC only 0.64.
```

---

## Paper-derived insights (NetVigil NSDI'24)

Key reasoning principles the paper extracted, applicable to LLM agent too:

```yaml
insights:
  - id: previously_unseen_ports_is_strong_signal
    description: |
      Number of "previously unseen ports" per IP pair is one of the most
      predictive features for scan/lateral-movement detection. Legitimate
      east-west flows reuse a small port set. Agent should track unseen
      ports per (src_ip, dst_ip) from prior windows.
    source: NetVigil §6.2

  - id: distributed_attacks_need_aggregate_reasoning
    description: |
      Each individual flow in a distributed attack looks low-anomaly.
      Detection emerges only at the aggregate level (count of unique src
      hitting same dst, sum of rates). Agent must consider GROUP behavior
      not individual flow.
    source: NetVigil §6.2

  - id: c2_and_dns_amplification_blend_with_normal_traffic
    description: |
      C&C beacons and DNS amplification mimic normal traffic shape (file
      transfer, DNS query). Hard for flow-log-only detection. NetVigil
      AUC for these = 0.89-0.93 (vs 1.00 for DDoS). Agent should require
      corroboration before P1 action on these patterns.
    source: NetVigil §6.2, Table 4

  - id: content_attacks_require_payload_inspection
    description: |
      SQL injection and other content-based attacks cannot be reliably
      detected from flow logs (NetVigil AUC 0.64 for SQL injection).
      Agent uses http/dns event types in eve.json for content classification
      when flow features inconclusive.
    source: NetVigil §6.2, Table 4

  - id: ip_pair_aggregation_over_5_tuple
    description: |
      Aggregating at IP-pair level (vs 5-tuple) reduces graph size 100×
      (139k nodes → 300) while preserving anomaly-detection signal. Agent
      should reason at IP-pair granularity by default.
    source: NetVigil §4.1

  - id: temporal_smoothing_reduces_false_alarms
    description: |
      Embeddings of temporally-adjacent windows should be similar in normal
      operation. Sudden divergence = anomaly. Agent's past_incidents window
      provides functionally similar context.
    source: NetVigil §4.4

  - id: 2_minute_detection_window_is_industry_norm
    description: |
      NetVigil and Yatesbury use 2-minute aggregation windows. Lab agent
      should target similar window for apples-to-apples comparison.
    source: NetVigil §6.1
```
