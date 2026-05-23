# Suricata SID Inventory

Active Suricata signatures the IDS emits. Each SID maps to MITRE ATT&CK
tactic/technique and a recommended response (DROP src_ip / log_only / escalate).
P-level: 1=critical, 2=high, 3=info-recon, 4=audit (visibility, not incident).

## SID 9000001 — WEB direct to DB - microsegmentation bypass

**Severity P1**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: direct connection initiated from presentation tier toward data tier database service ports. This violates defense-in-depth principle requiring application-mediated data access. Likely lateral movement preparing SQL exfiltration.

**Detection logic**: `TCP SYN from 10.1.100.0/24 to 10.1.200.0/24 dst_port in {5432,3306,1433,27017}`

**False-positive scenarios**:

- Legitimate DB migration script run from WEB tier (rare, pre-announced)
- Misconfigured monitoring tool scraping DB from wrong zone

```yaml
sid: 9000001
severity_p_level: 1
signature_msg: WEB direct to DB - microsegmentation bypass
production_description: 'Detection trigger: direct connection initiated from presentation tier toward
  data tier database service ports. This violates defense-in-depth principle requiring application-mediated
  data access. Likely lateral movement preparing SQL exfiltration.'
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.1.100.0/24 to 10.1.200.0/24 dst_port in {5432,3306,1433,27017}
uses_flags_s_workaround: true
recommended_response: DROP src_ip
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
- Legitimate DB migration script run from WEB tier (rare, pre-announced)
- Misconfigured monitoring tool scraping DB from wrong zone
```

## SID 9000002 — DB initiating outbound connection - exfiltration

**Severity P1**  ·  **MITRE**: TA0010 Exfiltration / T1041 Exfiltration Over C2 Channel  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: data tier initiating outbound connection beyond all internal trust zones. Violates crown-jewel invariant (DB never initiates outbound). Strong indicator of data exfiltration over C2 channel or covert tunnel.

**Detection logic**: `TCP SYN from 10.1.200.0/24 to !{WEB,DB,APP,MGT}`

**False-positive scenarios**:

- OS package update from DB host (should be staged via MGT proxy, but possible)
- DNS resolver call (legitimate but should not happen in this datacenter)

```yaml
sid: 9000002
severity_p_level: 1
signature_msg: DB initiating outbound connection - exfiltration
production_description: 'Detection trigger: data tier initiating outbound connection beyond all internal
  trust zones. Violates crown-jewel invariant (DB never initiates outbound). Strong indicator of data
  exfiltration over C2 channel or covert tunnel.'
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1041 Exfiltration Over C2 Channel
detection_logic: TCP SYN from 10.1.200.0/24 to !{WEB,DB,APP,MGT}
uses_flags_s_workaround: true
recommended_response: DROP src_ip
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
- OS package update from DB host (should be staged via MGT proxy, but possible)
- DNS resolver call (legitimate but should not happen in this datacenter)
```

<!-- SIDs 9000003, 9000004, 9000005 removed in 2026-05-09 refactor:
     all three fire on DENY paths that LEAF iptables zt-default-drop already blocks.
     Agent rule would be redundant with no audit-trail upside beyond what SID 9000001 demonstrates.
     Replaced by ALLOW-path anomaly SIDs 9000030-9000035 below where agent IS essential. -->

## SID 9000030 — WEB→APP rate burst (ALLOW-path volumetric)

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1499 Endpoint DoS  ·  **Response**: DROP targeted (src+dst+port)  ·  **FP likelihood**: medium

Detection trigger: WEB tier opens an abnormal number of TCP connections to APP:8080 within 60 seconds, exceeding 200/min/src (baseline ~60/min). LEAF iptables accepts these (matches `zt-web-app-allow`) — agent is the only layer that can detect rate-anomaly within a legitimate path. Indicator of compromised web-tier weaponizing the legit WEB→APP channel for floods or scraping.

**Detection logic**: `tcp 10.1.100.0/24 any -> 10.2.100.0/24 8080 flags:S threshold count 200 in 60s by_src`

```yaml
sid: 9000030
severity_p_level: 2
signature_msg: WEB->APP abnormal connection rate (compromised web-tier?)
production_description: 'Detection trigger: web tier exceeds 200 SYN/min toward APP:8080 — baseline ~60/min.
  Flow path itself is ALLOWED (zt-web-app-allow) so LEAF accepts. Agent must detect rate anomaly and push
  targeted DROP for the abusive src — this is the canonical ALLOW-path defense scenario.'
mitre_tactic: TA0040 Impact
mitre_technique: T1499 Endpoint Denial of Service
detection_logic: TCP SYN from 10.1.100.0/24 to 10.2.100.0/24 dst_port 8080 threshold 200/60s by_src
uses_flags_s_workaround: true
recommended_response: DROP targeted (src+dst+port)
default_ttl_seconds: 1800
false_positive_likelihood: medium
false_positive_scenarios:
  - "Legitimate burst from new product launch / promotional traffic spike"
  - "Health-check probe misconfiguration retrying aggressively"
```

## SID 9000031 — APP→DB volume anomaly (ALLOW-path exfiltration signal)

**Severity P2**  ·  **MITRE**: TA0010 Exfiltration / T1041 Exfil over C2  ·  **Response**: DROP targeted  ·  **FP likelihood**: medium

Detection trigger: application tier opens >100 SYN/min toward DB:5432 against baseline ~60/min. Flow is ALLOWED (zt-app-db-allow) so LEAF accepts. Agent detects rate anomaly inside a legitimate path — primary signal for "compromised application server abusing its DB grant".

**Detection logic**: `tcp 10.2.100.0/24 any -> 10.1.200.0/24 5432 flags:S threshold count 100 in 60s by_src`

```yaml
sid: 9000031
severity_p_level: 2
signature_msg: APP->DB volume anomaly (possible data exfiltration)
production_description: 'Detection trigger: application tier exceeds 100 SYN/min toward DB:5432 — baseline
  ~60/min. ALLOW path so LEAF accepts. Compromised app-01 abusing its DB grant for bulk extraction is the
  textbook scenario where agent is essential.'
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1041 Exfiltration Over C2 Channel
detection_logic: TCP SYN from 10.2.100.0/24 to 10.1.200.0/24 dst_port 5432 threshold 100/60s by_src
uses_flags_s_workaround: true
recommended_response: DROP targeted (src+dst+port)
default_ttl_seconds: 1800
false_positive_likelihood: medium
false_positive_scenarios:
  - "Legitimate batch job / migration window (should be pre-announced)"
  - "Application bug retry-loop after DB transient error"
```

## SID 9000032 — DB→APP large reply payload (bulk extraction)

**Severity P2**  ·  **MITRE**: TA0009 Collection / T1567 Exfil  ·  **Response**: DROP targeted  ·  **FP likelihood**: medium

Detection trigger: DB-mock reply payload exceeds 4KB, repeated ≥10 times in 30s. Indicates bulk SELECT extracting many rows in a single session — exfiltration via the legitimate reply channel that LEAF cannot inspect.

**Detection logic**: `tcp 10.1.200.0/24 5432 -> 10.2.100.0/24 any flow:established,from_server dsize:>4096 threshold count 10 in 30s`

```yaml
sid: 9000032
severity_p_level: 2
signature_msg: DB large reply payload (possible bulk SELECT)
production_description: 'Detection trigger: DB returns reply >4KB repeatedly. Normal vanilla query reply
  is ~100 bytes (PG_OK banner). Sustained large replies imply bulk SELECT or JOIN extraction — agent must
  evaluate against business intent.'
mitre_tactic: TA0009 Collection
mitre_technique: T1567 Exfiltration to Cloud Storage (adapted to internal DB extraction)
detection_logic: TCP from DB:5432 to APP flow:from_server dsize>4096 threshold 10/30s
uses_flags_s_workaround: false
recommended_response: DROP targeted (src+dst+port)
default_ttl_seconds: 1800
false_positive_likelihood: medium
false_positive_scenarios:
  - "Pre-announced reporting / analytics export window"
  - "Legitimate full-table refresh from APP cache warmup"
```

## SID 9000033 — Destructive SQL pattern (DROP TABLE / TRUNCATE)

**Severity P1**  ·  **MITRE**: TA0040 Impact / T1485 Data Destruction  ·  **Response**: DROP targeted + escalate  ·  **FP likelihood**: low

Detection trigger: APP→DB traffic contains DROP TABLE or TRUNCATE SQL fragments. APP tier should never execute schema-destructive operations — only DBA via MGT plane has that authority. Strong indicator of compromise or insider sabotage.

**Detection logic**: `tcp 10.2.100.0/24 any -> 10.1.200.0/24 5432 flow:to_server content:"DROP TABLE" OR content:"TRUNCATE"`

```yaml
sid: 9000033
severity_p_level: 1
signature_msg: Destructive SQL pattern (DROP TABLE / TRUNCATE)
production_description: 'Detection trigger: APP tier sends destructive SQL toward DB. APP role is supposed
  to execute CRUD via prepared statements, never schema-destructive commands. Any DROP/TRUNCATE from APP
  is incident-grade — block immediately and escalate to SOC.'
mitre_tactic: TA0040 Impact
mitre_technique: T1485 Data Destruction
detection_logic: TCP from APP:any to DB:5432 flow:to_server content match "DROP TABLE" or "TRUNCATE"
uses_flags_s_workaround: false
recommended_response: DROP targeted (src+dst+port) + escalate
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
  - "Pre-announced schema migration script ran from APP (should run from MGT instead)"
  - "Application contains literal SQL string DROP TABLE inside non-query context (rare)"
```

## SID 9000034 — APP→DB time-window context (agent evaluates off-hours)

**Severity P3**  ·  **MITRE**: TA0001 Initial Access / T1078 Valid Accounts  ·  **Response**: agent-evaluated  ·  **FP likelihood**: high (in business hours)

Detection trigger: throttled to 1 fire/5min per source — always-fire SID by design. Suricata cannot evaluate time-of-day natively, so this SID acts as a periodic context probe. Agent reasoning evaluates current hour against business window (08:00–18:00 UTC). Off-hours APP→DB activity is suspicious especially when paired with other anomalies (rate / volume).

**Detection logic**: `tcp 10.2.100.0/24 any -> 10.1.200.0/24 5432 flags:S threshold 1/300s by_src`

```yaml
sid: 9000034
severity_p_level: 3
signature_msg: APP->DB access for time-window analysis
production_description: 'Detection trigger: throttled fire 1/5min as an always-on probe. Time-of-day check
  happens in the agent prompt context, not in Suricata. Fires in business hours = log_only; fires off-hours
  with corroborating signal (rate burst, large reply) = strong suspicion of exfiltration.'
mitre_tactic: TA0001 Initial Access
mitre_technique: T1078 Valid Accounts (off-hours abuse)
detection_logic: TCP SYN APP→DB:5432 throttle 1/300s by_src; agent does time-of-day evaluation
uses_flags_s_workaround: true
recommended_response: agent-evaluated (log_only in business hours, DROP off-hours with corroboration)
default_ttl_seconds: 900
false_positive_likelihood: high
false_positive_scenarios:
  - "Routine business-hours operation — agent expected to ignore in 08-18 UTC window"
  - "Pre-announced overnight batch — should be paired with operator approval"
```

## SID 9000035 — Cross-tier SSH attempt (lateral movement vector)

**Severity P1**  ·  **MITRE**: TA0008 Lateral Movement / T1021.004 SSH  ·  **Response**: DROP targeted + flag host  ·  **FP likelihood**: low

Detection trigger: workload-to-workload TCP/22 connection attempt (WEB↔APP↔DB on port 22). Only MGT plane is authorized to SSH into workload hosts. Any SSH initiated by web-01 / app-01 / db-01 toward a peer workload indicates compromise pivot.

**Detection logic**: `tcp [10.1.100.0/24,10.2.100.0/24] any -> [10.1.100.0/24,10.2.100.0/24,10.1.200.0/24] 22 flags:S`

```yaml
sid: 9000035
severity_p_level: 1
signature_msg: SSH attempt between workload tiers (lateral movement)
production_description: 'Detection trigger: workload host (WEB/APP/DB) initiates SSH toward another workload.
  Only MGT plane SSHes into workload hosts per policy. Cross-tier workload SSH is a textbook lateral movement
  indicator — block immediately and consider full host isolation.'
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021.004 Remote Services - SSH
detection_logic: TCP SYN from {WEB,APP} to {WEB,APP,DB}:22 flags:S
uses_flags_s_workaround: true
recommended_response: DROP targeted (src+dst+port) + flag src host as suspicious
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
  - "Mistaken admin operation using wrong jump host (should always use MGT)"
  - "Misconfigured backup tool attempting SSH from data tier (should be removed)"
```

## SID 9000010 — ICMP ping sweep - reconnaissance

**Severity P3**  ·  **MITRE**: TA0043 Reconnaissance / T1018 Remote System Discovery  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: ICMP echo activity from a single source exceeding 3 within 10 seconds. Indicative of network reconnaissance scanning live hosts.

**Detection logic**: `ICMP echo, threshold 3 within 10s per src`

**False-positive scenarios**:

- Legitimate operations team running connectivity verification
- Health check tools doing host enumeration

```yaml
sid: 9000010
severity_p_level: 3
signature_msg: ICMP ping sweep - reconnaissance
production_description: 'Detection trigger: ICMP echo activity from a single source exceeding 3 within
  10 seconds. Indicative of network reconnaissance scanning live hosts.'
mitre_tactic: TA0043 Reconnaissance
mitre_technique: T1018 Remote System Discovery
detection_logic: ICMP echo, threshold 3 within 10s per src
uses_flags_s_workaround: false
recommended_response: log_only
default_ttl_seconds: 0
false_positive_likelihood: medium
false_positive_scenarios:
- Legitimate operations team running connectivity verification
- Health check tools doing host enumeration
```

## SID 9000011 — TCP port scan - reconnaissance

**Severity P3**  ·  **MITRE**: TA0043 Reconnaissance / T1046 Network Service Discovery  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: TCP SYN burst from single source — 10 SYN within 5 seconds. Indicative of port-scanning behavior mapping service surface area.

**Detection logic**: `TCP SYN, threshold 10 within 5s per src`

**False-positive scenarios**:

- Vulnerability scanner from MGT zone
- Application connection-pool warmup

```yaml
sid: 9000011
severity_p_level: 3
signature_msg: TCP port scan - reconnaissance
production_description: 'Detection trigger: TCP SYN burst from single source — 10 SYN within 5 seconds.
  Indicative of port-scanning behavior mapping service surface area.'
mitre_tactic: TA0043 Reconnaissance
mitre_technique: T1046 Network Service Discovery
detection_logic: TCP SYN, threshold 10 within 5s per src
uses_flags_s_workaround: false
recommended_response: log_only
default_ttl_seconds: 0
false_positive_likelihood: medium
false_positive_scenarios:
- Vulnerability scanner from MGT zone
- Application connection-pool warmup
```

## SID 9000020 — MGT zone access - audit baseline

**Severity P4**  ·  **MITRE**: TA0007 Discovery / T1082 System Information Discovery  ·  **Response**: log_only  ·  **FP likelihood**: high

Detection trigger: management plane initiating any flow, rate-limited to 1/min/src. BY DESIGN — required visibility for compliance. NOT an incident. Confirms management plane is operating normally.

**Detection logic**: `MGT (10.2.50.0/24) → any, rate-limit 1/min/src`

**False-positive scenarios**:

- Every legitimate MGT scrape, audit, logpull triggers this — by design.

```yaml
sid: 9000020
severity_p_level: 4
signature_msg: MGT zone access - audit baseline
production_description: 'Detection trigger: management plane initiating any flow, rate-limited to 1/min/src.
  BY DESIGN — required visibility for compliance. NOT an incident. Confirms management plane is operating
  normally.'
mitre_tactic: TA0007 Discovery
mitre_technique: T1082 System Information Discovery
detection_logic: MGT (10.2.50.0/24) → any, rate-limit 1/min/src
uses_flags_s_workaround: false
recommended_response: log_only
default_ttl_seconds: 0
false_positive_likelihood: high
false_positive_scenarios:
- Every legitimate MGT scrape, audit, logpull triggers this — by design.
```

---

# Yatesbury Benchmark SIDs (NetVigil NSDI'24, Table 3)

Suricata signals each per-source contribution. For aggregated patterns (DDoS multi-source, distributed scan, infection chain), agent correlates SIDs across pairs/time windows during reasoning. `recommended_response` is a KG default — agent reasons + may override based on context.

## SID 9000040 — Vertical port scan

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1046 Network Service Discovery  ·  **Response**: log_only + raise_trust_score  ·  **FP likelihood**: low

Detection trigger: single source initiates SYN to many ports on one destination within a short window. Indicates port enumeration / reconnaissance preceding exploit. Maps to KG pattern `vertical_port_scan`.

**Detection logic**: `TCP SYN any→lab any, threshold both,track by_src,count 20,seconds 30`

```yaml
sid: 9000040
severity_p_level: 3
signature_msg: Vertical port scan
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
kg_pattern_id: vertical_port_scan
detection_logic: TCP SYN any→lab any, threshold by_src,count 20,seconds 30
recommended_response: log_only + raise_trust_score
default_ttl_seconds: 0
false_positive_likelihood: low
false_positive_scenarios:
- Monitoring agent service discovery from non-MGT source
```

## SID 9000041 — TCP probe on key service ports

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1046 Network Service Discovery  ·  **Response**: log_only + raise_trust_score; agent correlates per-source to detect distributed pattern  ·  **FP likelihood**: medium

Detection trigger: per-source signal of probing on the union of common service ports (22/23/80/443/3389/5432/3306/1433/8080/8443). Multiple sources within a window → distributed scan pattern. Maps to KG `distributed_port_scan`.

**Detection logic**: `TCP SYN any→lab key_ports, threshold by_src,count 5,seconds 60`

```yaml
sid: 9000041
severity_p_level: 3
signature_msg: TCP probe on key service ports
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
kg_pattern_id: distributed_port_scan
detection_logic: TCP SYN any→lab key_ports, threshold by_src,count 5,seconds 60
recommended_response: log_only + raise_trust_score
default_ttl_seconds: 0
false_positive_likelihood: medium
false_positive_scenarios:
- MGT configuration sweep
- Health-check tooling
```

## SID 9000042 — UDP probe on many ports

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1046 Network Service Discovery  ·  **Response**: log_only + raise_trust_score  ·  **FP likelihood**: low

Detection trigger: UDP-based scan from one source touching many destination ports. UDP version of vertical/distributed scan. Maps to KG `distributed_port_scan` (UDP variant).

**Detection logic**: `UDP any→lab any, threshold by_src,count 15,seconds 60`

```yaml
sid: 9000042
severity_p_level: 3
signature_msg: UDP probe on many ports
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
kg_pattern_id: distributed_port_scan
detection_logic: UDP any→lab any, threshold by_src,count 15,seconds 60
recommended_response: log_only + raise_trust_score
default_ttl_seconds: 0
false_positive_likelihood: low
false_positive_scenarios:
- DNS/NTP cluster discovery from MGT
```

## SID 9000043 — TCP SYN flood — single source

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1499 Endpoint Denial of Service  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: one source sustains SYN-without-ACK at >200/10s. Classic SYN flood DoS. Maps to KG `syn_flood_dos`.

**Detection logic**: `TCP S,!A any→lab any, threshold by_src,count 200,seconds 10`

```yaml
sid: 9000043
severity_p_level: 2
signature_msg: TCP SYN flood — single source
mitre_tactic: TA0040 Impact
mitre_technique: T1499 Endpoint Denial of Service
kg_pattern_id: syn_flood_dos
detection_logic: TCP S,!A any→lab any, threshold by_src,count 200,seconds 10
recommended_response: DROP src_ip
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios:
- Legitimate load test (should originate from MGT only)
```

## SID 9000044 — TCP SYN contribution from source (DDoS component)

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1499 Endpoint Denial of Service  ·  **Response**: DROP src_ip; agent aggregates concurrent 9000044 SIDs same dst → DDoS posture  ·  **FP likelihood**: low

Detection trigger: per-source SYN-without-ACK contribution to one dst. Lower per-source threshold than 9000043 because each attacker in a DDoS contributes less. A sustained 50+ SYN/10s from a workload-tier host to a service port (e.g. DB OLTP 5432) is well above any legitimate retry/burst rate and should be treated as an attack on its own — do not wait to correlate a second source before acting. Agent still correlates concurrent 9000044 SIDs targeting same dst to escalate the DDoS posture. Maps to KG `syn_flood_ddos`.

**Detection logic**: `TCP S,!A any→lab any, threshold by_src_dst,count 50,seconds 10`

```yaml
sid: 9000044
severity_p_level: 2
signature_msg: TCP SYN contribution from source (DDoS component)
mitre_tactic: TA0040 Impact
mitre_technique: T1499 Endpoint Denial of Service
kg_pattern_id: syn_flood_ddos
detection_logic: TCP S,!A any→lab any, threshold by_src_dst,count 50,seconds 10
recommended_response: DROP src_ip
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios:
- Health-check probers that legitimately reconnect at high frequency (rare; verify the dst is not a critical service port)
```

## SID 9000045 — UDP packet flood — high rate to destination

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1499.002 UDP Flood  ·  **Response**: DROP src_ip(s)  ·  **FP likelihood**: low

Detection trigger: UDP flood rate exceeds 500 packets / 10s to one dst, tracked across srcs. Maps to KG `udp_ddos`.

**Detection logic**: `UDP any→lab any, threshold by_dst,count 500,seconds 10`

```yaml
sid: 9000045
severity_p_level: 2
signature_msg: UDP packet flood — high rate to destination
mitre_tactic: TA0040 Impact
mitre_technique: T1499.002 UDP Flood
kg_pattern_id: udp_ddos
detection_logic: UDP any→lab any, threshold by_dst,count 500,seconds 10
recommended_response: DROP src_ip(s)
default_ttl_seconds: 1800
false_positive_likelihood: low
```

## SID 9000046 — Periodic small outbound — possible C2 heartbeat

**Severity P2**  ·  **MITRE**: TA0011 Command and Control / T1071.001 Application Layer Protocol  ·  **Response**: DROP src_ip + quarantine investigation  ·  **FP likelihood**: medium

Detection trigger: src in lab sends ≥3 small (<200 byte) outbound SYNs over 90 seconds to an external destination. Low-and-slow C2 beacon pattern. Maps to KG `c2_beacon`. (rev:2 tuned threshold from 5/300s → 3/90s to fit eval window 120s while preserving low-rate beacon semantics.)

**Detection logic**: `TCP SYN dsize:<200 lab→!lab any, threshold by_src,count 3,seconds 90`

```yaml
sid: 9000046
severity_p_level: 2
signature_msg: Periodic small outbound — possible C2 heartbeat
mitre_tactic: TA0011 Command and Control
mitre_technique: T1071.001 Application Layer Protocol
kg_pattern_id: c2_beacon
detection_logic: TCP SYN dsize:<200 lab→!lab any, threshold by_src,count 3,seconds 90
recommended_response: DROP src_ip + quarantine investigation
default_ttl_seconds: 3600
false_positive_likelihood: medium
false_positive_scenarios:
- Notification/mail client outbound
- NTP / package update poller
```

## SID 9000047 — DNS response with abnormally large payload

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1498.002 Reflection Amplification  ·  **Response**: DROP source DNS endpoint + rate-limit dst  ·  **FP likelihood**: low

Detection trigger: UDP responses from port 53 with payload >1000 bytes arriving at one lab dst, threshold 5/30s. Indicates DNS amplification attack where lab host is the victim. Maps to KG `dns_tunneling` (amplification variant).

**Detection logic**: `UDP src_port 53 →lab any, dsize:>1000, threshold by_dst,count 5,seconds 30`

```yaml
sid: 9000047
severity_p_level: 2
signature_msg: DNS response with abnormally large payload
mitre_tactic: TA0040 Impact
mitre_technique: T1498.002 Reflection Amplification
kg_pattern_id: dns_tunneling
detection_logic: UDP src_port 53→lab any dsize:>1000, threshold by_dst,count 5,seconds 30
recommended_response: DROP source DNS endpoint + rate-limit dst
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios:
- DNSSEC/TXT records with large legitimate payloads (rare for internal DNS)
```

## SID 9000048 — SQL syntax — UNION SELECT in DB stream

**Severity P1**  ·  **MITRE**: TA0001 Initial Access / T1190 Exploit Public-Facing Application  ·  **Response**: DROP src_ip + escalate  ·  **FP likelihood**: low

Detection trigger: content match `UNION SELECT` in TCP stream targeting DB ports. Classic SQL injection signature. Maps to KG `sql_injection_recon`.

**Detection logic**: `TCP any→DB:5432/3306/1433, content:"UNION SELECT" nocase`

```yaml
sid: 9000048
severity_p_level: 1
signature_msg: SQL syntax — UNION SELECT in DB stream
mitre_tactic: TA0001 Initial Access
mitre_technique: T1190 Exploit Public-Facing Application
kg_pattern_id: sql_injection_recon
detection_logic: TCP any→DB content:"UNION SELECT" nocase
recommended_response: DROP src_ip + escalate
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
- Legitimate analytics query containing "UNION SELECT" from APP zone
```

## SID 9000049 — SQL syntax — tautology condition in DB stream

**Severity P1**  ·  **MITRE**: TA0001 Initial Access / T1190 Exploit Public-Facing Application  ·  **Response**: DROP src_ip + escalate  ·  **FP likelihood**: low

Detection trigger: content match `OR 1=1` in TCP stream targeting DB ports. Tautology-based SQL injection bypass. Maps to KG `sql_injection_recon`.

**Detection logic**: `TCP any→DB:5432/3306/1433, content:"OR 1=1" nocase`

```yaml
sid: 9000049
severity_p_level: 1
signature_msg: SQL syntax — tautology condition in DB stream
mitre_tactic: TA0001 Initial Access
mitre_technique: T1190 Exploit Public-Facing Application
kg_pattern_id: sql_injection_recon
detection_logic: TCP any→DB content:"OR 1=1" nocase
recommended_response: DROP src_ip + escalate
default_ttl_seconds: 3600
false_positive_likelihood: low
```

## SID 9000050 — Destructive SQL statement in DB stream

**Severity P1**  ·  **MITRE**: TA0040 Impact / T1485 Data Destruction  ·  **Response**: DROP src_ip + escalate; immediate quarantine  ·  **FP likelihood**: low

Detection trigger: pcre match on `DROP TABLE`, `TRUNCATE`, or `DELETE FROM` in TCP stream to DB ports. Destructive intent — never legitimate from the APP tier under normal operation. Maps to KG `destructive_sql_content`.

**Detection logic**: `TCP any→DB, pcre /\b(DROP\s+TABLE|TRUNCATE|DELETE\s+FROM)\b/i`

```yaml
sid: 9000050
severity_p_level: 1
signature_msg: Destructive SQL statement in DB stream
mitre_tactic: TA0040 Impact
mitre_technique: T1485 Data Destruction
kg_pattern_id: destructive_sql_content
detection_logic: TCP any→DB pcre /\b(DROP\s+TABLE|TRUNCATE|DELETE\s+FROM)\b/i
recommended_response: DROP src_ip + escalate
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
- Scheduled migration run from MGT (pre-announced, rare)
```

## SID 9000051 — DB connection from non-APP zone

**Severity P1**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: TCP SYN to DB service ports from any source NOT in APP zone (10.2.100.0/24) and NOT from DB itself. Generalizes SID 9000001 (WEB→DB) to catch any unauthorized data-tier access. Maps to KG `cross_zone_violation_web_to_db`.

**Detection logic**: `TCP SYN ![APP,DB] → DB:5432/3306/1433/27017`

```yaml
sid: 9000051
severity_p_level: 1
signature_msg: DB connection from non-APP zone
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
kg_pattern_id: cross_zone_violation_web_to_db
detection_logic: TCP SYN ![10.2.100.0/24,10.1.200.0/24] → 10.1.200.0/24 [5432,3306,1433,27017]
recommended_response: DROP src_ip
default_ttl_seconds: 3600
false_positive_likelihood: low
false_positive_scenarios:
- MGT operator running DB administration (rate-limited; verify source)
```

## SID 9000052 — Probe on commonly-exploited service port

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1046 Network Service Discovery  ·  **Response**: log_only + raise_trust_score; agent correlates with 9000040–9000041 to detect Infection Monkey chain  ·  **FP likelihood**: medium

Detection trigger: probe pattern on common exploit-target ports (22, 23, 135, 139, 445, 3389, 8080, 8443) from one source. Stage signal for multi-stage attacks like Infection Monkey. Maps to KG `infection_monkey_chain` (one stage).

**Detection logic**: `TCP SYN any→lab [22,23,135,139,445,3389,8080,8443], threshold by_src,count 10,seconds 60`

```yaml
sid: 9000052
severity_p_level: 3
signature_msg: Probe on commonly-exploited service port
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Discovery
kg_pattern_id: infection_monkey_chain
detection_logic: TCP SYN any→lab [22,23,135,139,445,3389,8080,8443], threshold by_src,count 10,seconds 60
recommended_response: log_only + raise_trust_score
default_ttl_seconds: 0
false_positive_likelihood: medium
false_positive_scenarios:
- MGT SSH scrape (rate-limited per spec)
- Legacy app health-check
```
