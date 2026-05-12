# Production Traffic Baselines

Steady-state east-west volume: ~120 flows/minute. MGT audit emissions ~1/minute (SID 9000020) are
REQUIRED VISIBILITY by compliance design — they are NOT incidents. Anything matching
a baseline is normal operation. Anything outside this set is either new application
behaviour or intrusion.

## Constants

```yaml
steady_state_flows_per_minute: 120
mgt_audit_alert_rate_per_minute: 1
```

## Anomalous patterns (NOT in baseline — red flags)

Two classes of anomalies the agent must reason about:

**Class A — DENY-path violations** (LEAF already drops, but Suricata still alerts for audit):
- Any flow originating from DB to anywhere — DB never initiates outbound by design.
- WEB initiating to DB on any port — bypasses application tier (lateral movement).
- Workload-to-workload SSH (WEB/APP/DB → port 22) — only MGT may SSH into workloads.

**Class B — ALLOW-path abuse** (LEAF accepts; only agent can detect — this is the agent's primary value-add):
- WEB→APP connection rate above 200/min/src — baseline ~60/min; sustained burst suggests compromised web-tier weaponizing proxy.
- APP→DB connection rate above 100/min/src — baseline ~60/min; suggests compromised application abusing DB grant for bulk extraction.
- DB→APP reply payload exceeding 4KB repeated in short window — normal queries return ~100-byte banner; large payloads imply bulk SELECT / JOIN extraction.
- Destructive SQL fragments ("DROP TABLE", "TRUNCATE") in APP→DB traffic — APP must never execute schema destruction; this is an incident-grade signal.
- APP→DB activity in off-hours window (outside 08:00–18:00 UTC) — legitimate business traffic clusters during the day; off-hours activity warrants extra scrutiny especially when paired with rate or volume anomaly.

```yaml
anomalous_patterns:
- Any flow originating from DB to anywhere — DB never initiates outbound by design.
- WEB initiating to DB on any port — bypasses application tier (lateral movement).
- Workload-to-workload SSH (WEB/APP/DB → port 22) — only MGT may SSH into workloads.
- WEB->APP connection rate above 200/min/src — baseline ~60/min; sustained burst suggests compromised web-tier.
- APP->DB connection rate above 100/min/src — baseline ~60/min; suggests compromised app abusing DB grant.
- DB->APP reply payload exceeding 4KB repeated in short window — implies bulk SELECT extraction.
- Destructive SQL fragments (DROP TABLE / TRUNCATE) in APP->DB traffic — incident-grade.
- APP->DB activity in off-hours window (outside 08:00-18:00 UTC) — extra scrutiny especially with corroborating signal.
```

## Application traffic flows

### web-to-application-proxy

`10.1.100.10` → `10.2.100.10:8080/tcp`, cadence: every 30s, criticality: **critical**

Presentation tier proxies user HTTP requests to the application tier for business logic processing. This is the canonical user-request east-west flow.

- **Anomaly trigger**: >10/min sustained suggests proxy abuse or DoS
- **If disrupted**: End-user-facing path broken. Users cannot complete actions requiring application logic.

```yaml
name: web-to-application-proxy
src_zone: WEB
src_ip: 10.1.100.10
dst_zone: APP
dst_ip: 10.2.100.10
dst_port: 8080
proto: tcp
cadence: every 30s
expected_volume_per_hour: 120
burst_anomaly_threshold: '>10/min sustained suggests proxy abuse or DoS'
production_description: Presentation tier proxies user HTTP requests to the application tier for business
  logic processing. This is the canonical user-request east-west flow.
criticality_to_business: critical
if_disrupted: End-user-facing path broken. Users cannot complete actions requiring application logic.
```

### application-to-database-oltp

`10.2.100.10` → `10.1.200.10:5432/tcp`, cadence: every 30s, criticality: **critical**

Application tier issues OLTP transactions against the relational database. Typical workload: SELECT users, SELECT orders, INSERT log, UPDATE session. Sustained transactional load is normal operation.

- **Anomaly trigger**: >50/min sustained suggests query-loop bug or exfiltration probe
- **If disrupted**: Application cannot read/write business state. Cascade outage to user-facing operations.

```yaml
name: application-to-database-oltp
src_zone: APP
src_ip: 10.2.100.10
dst_zone: DB
dst_ip: 10.1.200.10
dst_port: 5432
proto: tcp
cadence: every 30s
expected_volume_per_hour: 120
burst_anomaly_threshold: '>50/min sustained suggests query-loop bug or exfiltration probe'
production_description: 'Application tier issues OLTP transactions against the relational database. Typical
  workload: SELECT users, SELECT orders, INSERT log, UPDATE session. Sustained transactional load is normal
  operation.'
criticality_to_business: critical
if_disrupted: Application cannot read/write business state. Cascade outage to user-facing operations.
```

### application-database-readiness

`10.2.100.10` → `10.1.200.10:5432/tcp`, cadence: every 60s, criticality: **medium**

Application tier performs DB connectivity readiness probe. Validates that the data tier service is accepting connections.

- **Anomaly trigger**: N/A — health check, low volume
- **If disrupted**: Application loses early signal of DB health degradation. Outages detected later.

```yaml
name: application-database-readiness
src_zone: APP
src_ip: 10.2.100.10
dst_zone: DB
dst_ip: 10.1.200.10
dst_port: 5432
proto: tcp
cadence: every 60s
expected_volume_per_hour: 60
burst_anomaly_threshold: N/A — health check, low volume
production_description: Application tier performs DB connectivity readiness probe. Validates that the
  data tier service is accepting connections.
criticality_to_business: medium
if_disrupted: Application loses early signal of DB health degradation. Outages detected later.
```

## Management plane flows

### management-service-health-scrape-web

`10.2.50.10` → `10.1.100.10:80/tcp`, cadence: every 60s, criticality: **medium**

Management plane probes WEB tier HTTP service health from MGT vantage. Provides operational visibility into presentation tier liveness.

- **Anomaly trigger**: N/A — health check
- **If disrupted**: Loss of WEB tier health monitoring. Outages detected later.

```yaml
name: management-service-health-scrape-web
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: WEB
dst_ip: 10.1.100.10
dst_port: 80
proto: tcp
cadence: every 60s
expected_volume_per_hour: 60
burst_anomaly_threshold: N/A — health check
production_description: Management plane probes WEB tier HTTP service health from MGT vantage. Provides
  operational visibility into presentation tier liveness.
criticality_to_business: medium
if_disrupted: Loss of WEB tier health monitoring. Outages detected later.
```

### management-service-health-scrape-app

`10.2.50.10` → `10.2.100.10:8080/tcp`, cadence: every 60s, criticality: **medium**

Management plane probes APP tier HTTP API health for operational monitoring.

- **Anomaly trigger**: N/A — health check
- **If disrupted**: Loss of APP tier health monitoring.

```yaml
name: management-service-health-scrape-app
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: APP
dst_ip: 10.2.100.10
dst_port: 8080
proto: tcp
cadence: every 60s
expected_volume_per_hour: 60
burst_anomaly_threshold: N/A — health check
production_description: Management plane probes APP tier HTTP API health for operational monitoring.
criticality_to_business: medium
if_disrupted: Loss of APP tier health monitoring.
```

### management-service-health-scrape-db

`10.2.50.10` → `10.1.200.10:5432/tcp`, cadence: every 60s, criticality: **medium**

Management plane probes DB tier connectivity from MGT vantage. Critical for early detection of data tier service degradation.

- **Anomaly trigger**: N/A — health check
- **If disrupted**: Loss of DB tier health monitoring.

```yaml
name: management-service-health-scrape-db
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: DB
dst_ip: 10.1.200.10
dst_port: 5432
proto: tcp
cadence: every 60s
expected_volume_per_hour: 60
burst_anomaly_threshold: N/A — health check
production_description: Management plane probes DB tier connectivity from MGT vantage. Critical for early
  detection of data tier service degradation.
criticality_to_business: medium
if_disrupted: Loss of DB tier health monitoring.
```

### management-compliance-ssh-audit

`10.2.50.10` → `rotating:22/tcp`, cadence: every 2 minutes (rotating destinations), criticality: **high**

Management plane performs periodic compliance SSH login across managed zones, capturing host telemetry (uptime, posture). Required by governance for audit trail.

- **Anomaly trigger**: >5/min on same dst suggests credential brute-force
- **If disrupted**: Loss of compliance audit posture. Governance violation.

```yaml
name: management-compliance-ssh-audit
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: WEB+APP+DB
dst_ip: rotating
dst_port: 22
proto: tcp
cadence: every 2 minutes (rotating destinations)
expected_volume_per_hour: 30
burst_anomaly_threshold: '>5/min on same dst suggests credential brute-force'
production_description: Management plane performs periodic compliance SSH login across managed zones,
  capturing host telemetry (uptime, posture). Required by governance for audit trail.
criticality_to_business: high
if_disrupted: Loss of compliance audit posture. Governance violation.
```

### management-application-log-retrieval

`10.2.50.10` → `10.2.100.10:22/tcp`, cadence: every 5 minutes, criticality: **medium**

Management plane retrieves application logs via SSH from APP tier for centralized log aggregation and incident analysis.

- **Anomaly trigger**: N/A — scheduled retrieval
- **If disrupted**: Operational logs not centralized. Incident analysis degraded.

```yaml
name: management-application-log-retrieval
src_zone: MGT
src_ip: 10.2.50.10
dst_zone: APP
dst_ip: 10.2.100.10
dst_port: 22
proto: tcp
cadence: every 5 minutes
expected_volume_per_hour: 12
burst_anomaly_threshold: N/A — scheduled retrieval
production_description: Management plane retrieves application logs via SSH from APP tier for centralized
  log aggregation and incident analysis.
criticality_to_business: medium
if_disrupted: Operational logs not centralized. Incident analysis degraded.
```
