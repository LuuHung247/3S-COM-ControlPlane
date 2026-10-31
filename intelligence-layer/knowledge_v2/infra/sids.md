# Suricata SID Inventory (V2 — 29 SIDs)

Active Suricata signatures the IDS emits in V2 deployment. Each SID maps to MITRE
ATT&CK tactic/technique and a recommended response (DROP src_ip / log_only / escalate).
P-level: 1=critical, 2=high, 3=info-recon, 4=audit (visibility, not incident).

Categories (29 total):
- **Cat 1: V2 policy violations** (9000001–9000013) — one rule per critical DENY cell of 8×8 matrix
- **Cat 2: Recon — Yatesbury** (9000040–9000044)
- **Cat 3: Flooding — Yatesbury** (9000050–9000052)
- **Cat 4: C2 / tunneling / exfil** (9000060–9000062)
- **Cat 5: DB content — Yatesbury L7** (9000070–9000072)
- **Cat 6: Audit (low-rate)** (9000080–9000081)

The 8×8 matrix SIDs are intentionally orthogonal: most violations fire 2 SIDs (a
specific zone-pair SID + a generic SID like 9000011 MGT-inbound or 9000012 DB-conn).
The agent can correlate: same flow + 2 SIDs = high confidence; 1 SID alone = lower.

## SID 9000001 — WEB to DB direct - microsegmentation bypass

**Severity P1**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: very low

Detection trigger: TCP SYN from WEB zone toward any DB tier on DB ports. WEB has no legitimate DB path — must traverse APP-GW → APP-CORE → DB. Hard policy violation; likely staged exfil.

**Detection logic**: `TCP SYN from 10.1.100.0/24 to [10.1.200.0/24, 10.3.200.0/24] dst_port in {5432,3306,1433,27017}`

```yaml
sid: 9000001
severity_p_level: 1
signature_msg: WEB to DB direct - microsegmentation bypass
production_description: WEB direct to any DB - hard violation. Most attack-relevant cell (bypass full chain).
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.1.100.0/24 to [10.1.200.0/24,10.3.200.0/24] dst_port in {5432,3306,1433,27017}
uses_flags_s_workaround: true
```

## SID 9000002 — WEB to APP/WORKER direct - skips APP-GW

**Severity P1**  ·  **MITRE**: TA0008 / T1210 Exploitation of Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: WEB tier directly contacting APP-CORE or WORKER, bypassing APP-GW. Policy violation — APP-GW is the only legitimate ingress point.

```yaml
sid: 9000002
severity_p_level: 1
signature_msg: WEB to APP/WORKER direct - skips APP-GW
production_description: WEB skipping APP-GW into app/worker tier. Bypass of designed ingress.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1210 Exploitation of Remote Services
detection_logic: TCP SYN from 10.1.100.0/24 to [10.2.100.0/24,10.4.100.0/24]
uses_flags_s_workaround: true
```

## SID 9000003 — WEB to MGT/MON - unauthorized

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: very low

Detection trigger: WEB toward MGT or MONITORING. Untrusted zone has zero legitimate path to control/observability tier.

```yaml
sid: 9000003
severity_p_level: 1
signature_msg: WEB to MGT/MON - unauthorized
production_description: WEB targeting control tier — high-confidence compromise indicator.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.1.100.0/24 to [10.2.50.0/24,10.4.200.0/24]
uses_flags_s_workaround: true
```

## SID 9000004 — APP-GW to DB direct - skips APP-CORE

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: APP-GW directly contacting DB tier. APP-GW should only forward to APP-CORE; DB access must go through APP-CORE for business-logic mediation.

```yaml
sid: 9000004
severity_p_level: 1
signature_msg: APP-GW to DB direct - skips APP-CORE
production_description: APP-GW skipping APP-CORE into DB. Bypass of business-logic mediation.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.3.100.0/24 to [10.1.200.0/24,10.3.200.0/24] dst_port in {5432,3306,1433,27017}
uses_flags_s_workaround: true
```

## SID 9000005 — APP-GW to non-APP zone - lateral move

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: APP-GW toward WEB (reverse), WORKER, MGT, or MON. APP-GW's only legitimate outbound is APP-CORE.

```yaml
sid: 9000005
severity_p_level: 1
signature_msg: APP-GW to non-APP zone - lateral move
production_description: APP-GW initiating to non-APP-CORE destination. Reverse or sideways lateral.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.3.100.0/24 to [10.1.100.0/24,10.4.100.0/24,10.2.50.0/24,10.4.200.0/24]
uses_flags_s_workaround: true
```

## SID 9000006 — APP-CORE reverse call to WEB/GW - lateral movement

**Severity P2**  ·  **MITRE**: TA0008 / T1071 Application Layer Protocol  ·  **Response**: DROP src_ip after correlation  ·  **FP likelihood**: medium

Detection trigger: APP-CORE initiating toward WEB or APP-GW. Legitimate chain is unidirectional (WEB→GW→CORE). Reverse calls signal compromise or misconfigured service trying to call back upstream.

```yaml
sid: 9000006
severity_p_level: 2
signature_msg: APP-CORE reverse call to WEB/GW - lateral movement
production_description: APP-CORE initiating toward upstream zones. P2 because some legitimate reverse-proxy patterns exist.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1071 Application Layer Protocol
detection_logic: TCP SYN from 10.2.100.0/24 to [10.1.100.0/24,10.3.100.0/24]
uses_flags_s_workaround: true
```

## SID 9000007 — APP-CORE to MGT/MON - unauthorized

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: APP-CORE toward MGT or MON. No legitimate path — control tier is read-only from MGT/MON's side.

```yaml
sid: 9000007
severity_p_level: 1
signature_msg: APP-CORE to MGT/MON - unauthorized
production_description: APP-CORE reaching control tier — control-plane segregation broken.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.2.100.0/24 to [10.2.50.0/24,10.4.200.0/24]
uses_flags_s_workaround: true
```

## SID 9000008 — WORKER lateral move - only DB-OLTP allowed

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: WORKER initiating toward any zone except DB-OLTP. WORKER's only legitimate outbound is `DB-OLTP:5432` (job result persistence).

```yaml
sid: 9000008
severity_p_level: 1
signature_msg: WORKER lateral move - only DB-OLTP allowed
production_description: WORKER reaching any zone except DB-OLTP. Worker-tier compromise indicator.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.4.100.0/24 to [10.1.100.0/24,10.3.100.0/24,10.2.100.0/24,10.3.200.0/24,10.2.50.0/24,10.4.200.0/24]
uses_flags_s_workaround: true
```

## SID 9000009 — DB-OLTP initiating outbound - data exfil suspect

**Severity P1**  ·  **MITRE**: TA0010 Exfiltration / T1048 Exfiltration Over Alternative Protocol  ·  **Response**: DROP src_ip + escalate to SOC  ·  **FP likelihood**: very low

Detection trigger: DB-OLTP initiating toward any zone except DB-ANALYTICS. DB-OLTP is a near-sink — only replication to DB-ANALYTICS is allowed.

```yaml
sid: 9000009
severity_p_level: 1
signature_msg: DB-OLTP initiating outbound - data exfil suspect
production_description: DB-OLTP outbound to any zone except DB-ANALYTICS. Near-sink role violated — high-confidence exfil.
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1048 Exfiltration Over Alternative Protocol
detection_logic: TCP SYN from 10.1.200.0/24 to [10.1.100.0/24,10.3.100.0/24,10.2.100.0/24,10.4.100.0/24,10.2.50.0/24,10.4.200.0/24]
uses_flags_s_workaround: true
```

## SID 9000010 — DB-ANALYTICS initiating outbound - sink role violated

**Severity P1**  ·  **MITRE**: TA0010 / T1048  ·  **Response**: DROP src_ip + escalate  ·  **FP likelihood**: very low

Detection trigger: DB-ANALYTICS initiating outbound to any zone. DB-ANALYTICS is a pure sink — ANY init is a sink-role invariant breach.

```yaml
sid: 9000010
severity_p_level: 1
signature_msg: DB-ANALYTICS initiating outbound - sink role violated
production_description: DB-ANALYTICS initiating any outbound. Pure-sink invariant breach — high-confidence compromise.
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1048 Exfiltration Over Alternative Protocol
detection_logic: TCP SYN from 10.3.200.0/24 to any zone CIDR
uses_flags_s_workaround: true
```

## SID 9000011 — Inbound to MGT zone from non-control - unauthorized access

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: Anything except MGT and MON initiating toward MGT. MGT receives only from itself and MON observability — generic guard against MGT escalation.

```yaml
sid: 9000011
severity_p_level: 1
signature_msg: Inbound to MGT zone from non-control - unauthorized access
production_description: Inbound to MGT from non-control zone. Generic MGT-escalation guard — fires alongside zone-specific SIDs.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from ![10.2.50.0/24,10.4.200.0/24] to 10.2.50.0/24
uses_flags_s_workaround: true
```

## SID 9000012 — DB connection from unauthorized zone

**Severity P1**  ·  **MITRE**: TA0008 / T1021  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: DB connection (5432/3306/1433/27017) from any zone except APP-CORE/WORKER/MON/MGT/DB-OLTP/DB-ANALYTICS. Generic guard against DB tier touch from unauthorized origin (defense-in-depth with zone-specific SIDs).

```yaml
sid: 9000012
severity_p_level: 1
signature_msg: DB connection from unauthorized zone
production_description: Generic DB-tier guard. Fires alongside 9000001/9000004/9000008 on violations.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from ![APP-CORE,WORKER,MON,MGT,DB-OLTP,DB-ANALYTICS] to [DB-OLTP,DB-ANALYTICS] dst_port in {5432,3306,1433,27017}
uses_flags_s_workaround: true
```

## SID 9000013 — WORKER to DB-ANALYTICS - only APP-CORE allowed

**Severity P2**  ·  **MITRE**: TA0008 / T1071  ·  **Response**: DROP src_ip  ·  **FP likelihood**: medium

Detection trigger: WORKER reaching DB-ANALYTICS. Analytics tier is written only by APP-CORE; WORKER must stay on DB-OLTP.

```yaml
sid: 9000013
severity_p_level: 2
signature_msg: WORKER to DB-ANALYTICS - only APP-CORE allowed
production_description: WORKER crossing to analytics tier. P2 because some legitimate ETL-job patterns may share namespace.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1071 Application Layer Protocol
detection_logic: TCP SYN from 10.4.100.0/24 to 10.3.200.0/24
uses_flags_s_workaround: true
```

## SID 9000040 — ICMP ping sweep

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1018 Remote System Discovery  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: ICMP echo-request burst. Threshold: 3 / 10s per source.

```yaml
sid: 9000040
severity_p_level: 3
signature_msg: ICMP ping sweep
production_description: Network discovery via ping bursts.
mitre_tactic: TA0007 Discovery
mitre_technique: T1018 Remote System Discovery
detection_logic: ICMP echo-request threshold:both,by_src,3/10s
```

## SID 9000041 — Vertical port scan - many ports same destination

**Severity P3**  ·  **MITRE**: TA0007 Discovery / T1046 Network Service Scanning  ·  **Response**: log_only + escalate if from sensitive zone  ·  **FP likelihood**: medium

Detection trigger: Single source probing many ports on a single destination within window. Threshold: 20 ports / 30s. Excludes baseline service ports (22, 80, 443, 5432, 8080, 8082, 8090, 9090).

```yaml
sid: 9000041
severity_p_level: 3
signature_msg: Vertical port scan
production_description: Single-src vertical scan against single-dst. Recon indicator.
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Scanning
detection_logic: TCP SYN from $HOME_NET any to $HOME_NET ![22,80,443,5432,8080,8082,8090,9090] threshold:both,by_src,20/30s
uses_flags_s_workaround: true
```

## SID 9000042 — TCP probe on commonly-exploited service ports

**Severity P3**  ·  **MITRE**: TA0007 / T1046  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: TCP SYN to commonly-exploited ports (23, 135, 139, 445, 3389, 3306, 1433, 8443). Threshold: 5 / 60s per source.

```yaml
sid: 9000042
severity_p_level: 3
signature_msg: TCP probe on commonly-exploited service ports
production_description: Probes on telnet/SMB/RDP/MS-SQL/HTTPS-alt. Yatesbury distributed-scan signal.
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Scanning
detection_logic: TCP SYN to [23,135,139,445,3389,3306,1433,8443] threshold:both,by_src,5/60s
uses_flags_s_workaround: true
```

## SID 9000043 — UDP probe on many ports

**Severity P3**  ·  **MITRE**: TA0007 / T1046  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: UDP packets to many ports from single source. Threshold: 15 / 60s.

```yaml
sid: 9000043
severity_p_level: 3
signature_msg: UDP probe on many ports
production_description: UDP scan variant of port discovery.
mitre_tactic: TA0007 Discovery
mitre_technique: T1046 Network Service Scanning
detection_logic: UDP from $HOME_NET to $HOME_NET threshold:both,by_src,15/60s
```

## SID 9000044 — Multi-stage probe - Infection Monkey-style chain

**Severity P3**  ·  **MITRE**: TA0008 / T1210  ·  **Response**: log_only + correlate  ·  **FP likelihood**: medium

Detection trigger: Repeated probes on exploit-prone ports (telnet/SMB/RDP/HTTPS-alt). Yatesbury Infection-Monkey signal — chain detection.

```yaml
sid: 9000044
severity_p_level: 3
signature_msg: Multi-stage probe - Infection Monkey-style chain
production_description: Infection-Monkey-style multi-port probe chain.
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1210 Exploitation of Remote Services
detection_logic: TCP SYN to [23,135,139,445,3389,8443] threshold:both,by_src,10/60s
uses_flags_s_workaround: true
```

## SID 9000050 — TCP SYN flood - sustained high rate from single source

**Severity P2**  ·  **MITRE**: TA0040 Impact / T1499 Endpoint Denial of Service  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: 200 SYN / 10s from single source. Sustained DoS.

```yaml
sid: 9000050
severity_p_level: 2
signature_msg: TCP SYN flood - sustained high rate from single source
production_description: Single-source SYN flood DoS.
mitre_tactic: TA0040 Impact
mitre_technique: T1499 Endpoint Denial of Service
detection_logic: TCP SYN to $HOME_NET threshold:both,by_src,200/10s
uses_flags_s_workaround: true
```

## SID 9000051 — TCP SYN contribution from source - DDoS aggregation signal

**Severity P2**  ·  **MITRE**: TA0040 / T1498 Network Denial of Service  ·  **Response**: log_only — agent aggregates per-dst  ·  **FP likelihood**: high (individual contributions look normal)

Detection trigger: Per-source SYN rate ≥ 50 / 10s per (src,dst). Designed as a per-source contribution; agent must aggregate by destination across many sources to detect DDoS.

```yaml
sid: 9000051
severity_p_level: 2
signature_msg: TCP SYN contribution from source
production_description: Per-source DDoS contribution signal. Agent correlates by dst.
mitre_tactic: TA0040 Impact
mitre_technique: T1498 Network Denial of Service
detection_logic: TCP SYN threshold:both,by_both,50/10s
uses_flags_s_workaround: true
```

## SID 9000052 — UDP packet flood - high rate to destination

**Severity P2**  ·  **MITRE**: TA0040 / T1499  ·  **Response**: log_only + escalate  ·  **FP likelihood**: low

Detection trigger: 500 UDP / 10s tracking by destination — DDoS aggregation across sources.

```yaml
sid: 9000052
severity_p_level: 2
signature_msg: UDP packet flood - high rate to destination
production_description: UDP DDoS aggregation by dst.
mitre_tactic: TA0040 Impact
mitre_technique: T1499 Endpoint Denial of Service
detection_logic: UDP threshold:both,by_dst,500/10s
```

## SID 9000060 — Periodic small outbound - possible C2 heartbeat

**Severity P2**  ·  **MITRE**: TA0011 Command and Control / T1071 Application Layer Protocol  ·  **Response**: DROP src_ip after correlate  ·  **FP likelihood**: medium

Detection trigger: Internal source initiating to EXTERNAL_NET with small payload (<200B), sustained over 90s. Beacon pattern.

```yaml
sid: 9000060
severity_p_level: 2
signature_msg: Periodic small outbound - possible C2 heartbeat
production_description: Low-and-slow C2 beacon to external. Agent correlates with workload identity.
mitre_tactic: TA0011 Command and Control
mitre_technique: T1071 Application Layer Protocol
detection_logic: TCP SYN from $HOME_NET to $EXTERNAL_NET dsize:<200 threshold:both,by_src,3/90s
uses_flags_s_workaround: true
```

## SID 9000061 — DNS response with abnormally large payload

**Severity P2**  ·  **MITRE**: TA0011 / T1071.004 DNS  ·  **Response**: log_only  ·  **FP likelihood**: medium

Detection trigger: UDP from src port 53 with payload >1000B toward internal host. DNS amplification or DNS-tunnel exfil signal.

```yaml
sid: 9000061
severity_p_level: 2
signature_msg: DNS response with abnormally large payload
production_description: DNS amp or DNS-tunnel exfil.
mitre_tactic: TA0011 Command and Control
mitre_technique: T1071.004 DNS
detection_logic: UDP src_port:53 to $HOME_NET dsize:>1000 threshold:both,by_dst,5/30s
```

## SID 9000062 — DB tier outbound to external - data exfil suspect

**Severity P1**  ·  **MITRE**: TA0010 / T1048  ·  **Response**: DROP src_ip + escalate  ·  **FP likelihood**: very low

Detection trigger: DB-OLTP or DB-ANALYTICS initiating to EXTERNAL_NET. Crown-jewel exfil indicator — DB tier has NO legitimate external destination.

```yaml
sid: 9000062
severity_p_level: 1
signature_msg: DB tier outbound to external - data exfil suspect
production_description: Crown-jewel exfil signal. DB tier never legitimately reaches external.
mitre_tactic: TA0010 Exfiltration
mitre_technique: T1048 Exfiltration Over Alternative Protocol
detection_logic: TCP SYN from [10.1.200.0/24,10.3.200.0/24] to $EXTERNAL_NET
uses_flags_s_workaround: true
```

## SID 9000070 — SQL syntax - UNION SELECT in DB stream

**Severity P1**  ·  **MITRE**: TA0001 Initial Access / T1190 Exploit Public-Facing Application  ·  **Response**: DROP src_ip  ·  **FP likelihood**: very low

Detection trigger: Substring `UNION SELECT` in TCP payload to DB ports (5432/3306/1433). SQL injection content match.

```yaml
sid: 9000070
severity_p_level: 1
signature_msg: SQL syntax - UNION SELECT in DB stream
production_description: SQL injection content — UNION-based payload to DB tier.
mitre_tactic: TA0001 Initial Access
mitre_technique: T1190 Exploit Public-Facing Application
detection_logic: TCP to [10.1.200.0/24,10.3.200.0/24] [5432,3306,1433] content:"UNION SELECT" nocase
```

## SID 9000071 — SQL syntax - tautology condition in DB stream

**Severity P1**  ·  **MITRE**: TA0001 / T1190  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: Substring `OR 1=1` in TCP payload to DB ports. Classic tautology SQL injection.

```yaml
sid: 9000071
severity_p_level: 1
signature_msg: SQL syntax - tautology condition in DB stream
production_description: SQL injection tautology pattern.
mitre_tactic: TA0001 Initial Access
mitre_technique: T1190 Exploit Public-Facing Application
detection_logic: TCP to [10.1.200.0/24,10.3.200.0/24] [5432,3306,1433] content:"OR 1=1" nocase
```

## SID 9000072 — Destructive SQL statement in DB stream

**Severity P1**  ·  **MITRE**: TA0040 Impact / T1485 Data Destruction  ·  **Response**: DROP src_ip + escalate to SOC  ·  **FP likelihood**: low

Detection trigger: PCRE for `DROP TABLE | TRUNCATE | DELETE FROM` in TCP stream to DB ports.

```yaml
sid: 9000072
severity_p_level: 1
signature_msg: Destructive SQL statement in DB stream
production_description: Destructive DDL/DML targeting DB.
mitre_tactic: TA0040 Impact
mitre_technique: T1485 Data Destruction
detection_logic: TCP to [10.1.200.0/24,10.3.200.0/24] [5432,3306,1433] pcre:"/\\b(DROP\\s+TABLE|TRUNCATE|DELETE\\s+FROM)\\b/i"
```

## SID 9000080 — Management zone access (audit baseline)

**Severity P4**  ·  **MITRE**: N/A (compliance audit)  ·  **Response**: log_only  ·  **FP likelihood**: n/a (baseline expected)

Detection trigger: ANY IP traffic initiating from MGT zone. Rate-limited to 1/60s per source via `threshold:limit`. NOT an incident — required compliance audit signal.

```yaml
sid: 9000080
severity_p_level: 4
signature_msg: Management zone access
production_description: MGT-initiated session — compliance audit baseline (rate-limited).
mitre_tactic: N/A
mitre_technique: N/A
detection_logic: IP from 10.2.50.0/24 to $HOME_NET threshold:limit,by_src,1/60s
classtype: policy-violation
note: Reclassified P4 in V2 — not incident, required visibility.
```

## SID 9000081 — Monitoring zone aggregation (audit baseline)

**Severity P4**  ·  **MITRE**: N/A  ·  **Response**: log_only  ·  **FP likelihood**: n/a

Detection trigger: ANY IP from MON zone. Rate-limited to 1/300s. Baseline scrape visibility log.

```yaml
sid: 9000081
severity_p_level: 4
signature_msg: Monitoring zone aggregation
production_description: MON-initiated scrape session — baseline audit.
mitre_tactic: N/A
mitre_technique: N/A
detection_logic: IP from 10.4.200.0/24 to $HOME_NET threshold:limit,by_src,1/300s
classtype: not-suspicious
note: Reclassified P4 — observability is allowed and expected.
```
