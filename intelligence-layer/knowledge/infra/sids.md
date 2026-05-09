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

## SID 9000003 — APP reverse call to WEB - lateral movement

**Severity P2**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: application tier initiating connection toward presentation tier — direction reversal from intended dataflow. APP should never call WEB. Indicator of APP tier compromise pivoting toward web frontend.

**Detection logic**: `TCP SYN from 10.2.100.0/24 to 10.1.100.0/24 dst_port in {80,443,22}`

```yaml
sid: 9000003
severity_p_level: 2
signature_msg: APP reverse call to WEB - lateral movement
production_description: 'Detection trigger: application tier initiating connection toward presentation
  tier — direction reversal from intended dataflow. APP should never call WEB. Indicator of APP tier compromise
  pivoting toward web frontend.'
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.2.100.0/24 to 10.1.100.0/24 dst_port in {80,443,22}
uses_flags_s_workaround: true
recommended_response: DROP src_ip
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios: []
```

## SID 9000004 — WEB to MGT - unauthorized escalation attempt

**Severity P2**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: presentation tier initiating connection toward management plane on operational ports (SSH/RDP). Lateral movement from untrusted zone into privileged management zone. Strong indicator of WEB compromise attempting credential pivot or remote shell.

**Detection logic**: `TCP SYN from 10.1.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}`

```yaml
sid: 9000004
severity_p_level: 2
signature_msg: WEB to MGT - unauthorized escalation attempt
production_description: 'Detection trigger: presentation tier initiating connection toward management
  plane on operational ports (SSH/RDP). Lateral movement from untrusted zone into privileged management
  zone. Strong indicator of WEB compromise attempting credential pivot or remote shell.'
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.1.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}
uses_flags_s_workaround: true
recommended_response: DROP src_ip
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios: []
```

## SID 9000005 — APP to MGT - unauthorized escalation attempt

**Severity P2**  ·  **MITRE**: TA0008 Lateral Movement / T1021 Remote Services  ·  **Response**: DROP src_ip  ·  **FP likelihood**: low

Detection trigger: application tier initiating connection toward management plane on operational ports. Same threat model as 9000004 but from APP tier — indicates deeper compromise reaching application layer.

**Detection logic**: `TCP SYN from 10.2.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}`

```yaml
sid: 9000005
severity_p_level: 2
signature_msg: APP to MGT - unauthorized escalation attempt
production_description: 'Detection trigger: application tier initiating connection toward management plane
  on operational ports. Same threat model as 9000004 but from APP tier — indicates deeper compromise reaching
  application layer.'
mitre_tactic: TA0008 Lateral Movement
mitre_technique: T1021 Remote Services
detection_logic: TCP SYN from 10.2.100.0/24 to 10.2.50.0/24 dst_port in {22,3389}
uses_flags_s_workaround: true
recommended_response: DROP src_ip
default_ttl_seconds: 1800
false_positive_likelihood: low
false_positive_scenarios: []
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
